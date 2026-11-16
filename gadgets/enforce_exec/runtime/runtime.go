// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package runtime owns immutable execution rules and mutable container membership.
package runtime

import (
	"errors"
	"fmt"
	"maps"
	"path"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	configKey   = "enforce-exec/config"
	bindingsKey = "enforce-exec/bindings"
)

const MaxImageOrigins = 65536

// ImageOriginKey identifies a regular lower file by stable backing identity.
// Major/minor use the kernel's 12:20 device encoding, not userspace dev_t bits.
type ImageOriginKey struct {
	Inode        uint64
	Major, Minor uint32
}

// ImageOriginSnapshot is an attestation from the trusted runtime owner, NEVER
// policy-authored input. Complete certifies ALL regular lower files plus a
// validated root/mount matrix and immutable lower roots. IG cannot establish
// those guarantees: the owner must reject mutable, nested, redirected or
// otherwise unsupported roots before supplying this snapshot.
type ImageOriginSnapshot struct {
	Complete bool
	Keys     []ImageOriginKey
}

// Config contains compiled immutable rules and initial container discovery selectors.
// Empty Targets protects no discovered containers. Bind can explicitly add targets.
type Config struct {
	// Full selects the advanced immutable program ABI, never a legacy fallback.
	Full            *fullpolicy.KernelProgram
	ImageOrigins    *ImageOriginSnapshot
	Entries         [execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry
	Targets         []execpolicy.Container
	InitialBindings []ContainerIdentity
}

func WithConfig(config Config) gadgetcontext.Option {
	if config.ImageOrigins != nil {
		snapshot := *config.ImageOrigins
		snapshot.Keys = append([]ImageOriginKey(nil), snapshot.Keys...)
		config.ImageOrigins = &snapshot
	}
	if config.Full != nil {
		snapshot := *config.Full
		snapshot.Entries = append([]fullpolicy.Blob(nil), config.Full.Entries...)
		snapshot.Rules = append([]fullpolicy.RuleMetadata(nil), config.Full.Rules...)
		snapshot.Identities = maps.Clone(config.Full.Identities)
		config.Full = &snapshot
	}
	config.Targets = append([]execpolicy.Container(nil), config.Targets...)
	config.InitialBindings = append([]ContainerIdentity(nil), config.InitialBindings...)
	return func(gc *gadgetcontext.GadgetContext) { gc.SetVar(configKey, config) }
}

type ContainerIdentity struct {
	Runtime, ID string
	CgroupID    uint64
	CgroupPath  string
}

func (c ContainerIdentity) validate() error {
	if strings.TrimSpace(c.Runtime) == "" || strings.TrimSpace(c.ID) == "" || c.CgroupID == 0 || c.CgroupPath == "/" || !path.IsAbs(c.CgroupPath) || path.Clean(c.CgroupPath) != c.CgroupPath {
		return fmt.Errorf("binding requires runtime, full container ID and non-root cgroup v2 identity")
	}
	return nil
}

func (c ContainerIdentity) selector() execpolicy.Container {
	return execpolicy.Container{Runtime: c.Runtime, ID: c.ID}
}

type Status struct {
	Revision           uint64
	Bound              int
	RestrictedBindings int
	Ready              bool
	Error              error
}

// immutableMap allows failure-ordering tests without creating privileged BPF
// maps. Production Start still accepts only map handles from the eBPF operator.
type immutableMap interface {
	bindingMap
	Type() ebpf.MapType
	KeySize() uint32
	ValueSize() uint32
	MaxEntries() uint32
	Flags() uint32
	Freeze() error
}
type faultMap interface {
	immutableMap
	Lookup(interface{}, interface{}) error
}
type bindingMap interface {
	Put(interface{}, interface{}) error
	Delete(interface{}) error
}

// Bindings serializes all writes. Map handles are borrowed from the eBPF operator.
type Bindings struct {
	mu                     sync.Mutex
	config                 Config
	desired                map[execpolicy.Container]ContainerIdentity
	active                 map[uint64]ContainerIdentity
	members                bindingMap
	restricted             map[uint64]*namespaceRefs
	hostNamespaceSupported bool
	fullImage              bool
	fullFeatures           string
	faults                 faultMap
	fsTrackerVerified      bool
	fsProbe, fsHealth      func() error
	kernelError            error
	ready, stopped         bool
	startupComplete        bool
	startupError           error
	lastError              error
}

// GetBindings is called from an operator lifecycle hook or after instance
// startup completes. Retain the returned controller for concurrent live writes.
func GetBindings(gc operators.GadgetContext) (*Bindings, error) {
	value, _ := gc.GetVar(bindingsKey)
	b, ok := value.(*Bindings)
	if !ok {
		return nil, fmt.Errorf("execution binding controller is unavailable")
	}
	return b, nil
}

func (b *Bindings) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.checkFaults()
	err := b.lastError
	if !b.startupComplete && b.startupError != nil {
		err = b.startupError
	}
	if b.kernelError != nil {
		err = b.kernelError
	}
	return Status{Revision: b.config.Entries[0].Generation, Bound: len(b.active), RestrictedBindings: len(b.restricted), Ready: b.ready && b.startupComplete && !b.stopped && b.kernelError == nil, Error: err}
}

// Bind synchronously authorizes one exact container after this operator starts.
// A later operator may populate bindings before the final readiness check.
func (b *Bindings) Bind(c ContainerIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return b.recordError(fmt.Errorf("binding controller is not running"))
	}
	err := b.bind(c)
	b.recordError(err)
	return err
}

// recordError is called with mu held. Startup errors remain sticky even if a
// later unrelated binding succeeds; the entire candidate must then be replaced.
func (b *Bindings) recordError(err error) error {
	b.lastError = err
	if err != nil && !b.startupComplete && b.startupError == nil {
		b.startupError = err
	}
	return err
}

// Ready is the final startup boundary. Errors after this check are active-runtime
// failures returned to the owner and exposed through Status.
func (b *Bindings) Ready(operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return fmt.Errorf("binding controller is not running")
	}
	if !b.startupComplete && filesystemRequired(b.config) {
		if b.fsProbe == nil {
			return b.recordError(fmt.Errorf("filesystem tracker readiness probe is unavailable"))
		}
		if err := b.fsProbe(); err != nil {
			return b.recordError(err)
		}
	}
	if err := b.checkFaults(); err != nil {
		return err
	}
	if b.startupError != nil {
		return b.startupError
	}
	if !b.startupComplete && filesystemRequired(b.config) {
		b.fsTrackerVerified = true
		for _, c := range b.desired {
			if err := b.bind(c); err != nil {
				var rollback []error
				for _, active := range b.active {
					rollback = append(rollback, b.unbind(active))
				}
				b.fsTrackerVerified = false
				return b.recordError(errors.Join(append([]error{err}, rollback...)...))
			}
		}
		b.desired = nil
	}
	b.startupComplete = true
	return nil
}

func (b *Bindings) bind(c ContainerIdentity) error {
	return b.bindWithScope(c, nil)
}

// bindWithScope takes ownership of refs on every path, including rejection.
func (b *Bindings) bindWithScope(c ContainerIdentity, refs *namespaceRefs) error {
	stored := false
	defer func() {
		if refs != nil && !stored {
			refs.close()
		}
	}()
	if err := c.validate(); err != nil {
		return err
	}
	if filesystemRequired(b.config) && !b.fsTrackerVerified {
		if refs != nil {
			return fmt.Errorf("filesystem candidate supports strict bindings only")
		}
		if b.desired == nil {
			b.desired = map[execpolicy.Container]ContainerIdentity{}
		}
		for _, previous := range b.desired {
			if (previous.CgroupID == c.CgroupID || previous.selector() == c.selector()) && previous != c {
				return fmt.Errorf("pending container binding identity conflicts")
			}
		}
		if _, exists := b.desired[c.selector()]; !exists && len(b.desired) >= execpolicy.KernelMaxBindings {
			return fmt.Errorf("container binding capacity exceeded")
		}
		b.desired[c.selector()] = c
		return nil
	}
	if filesystemRequired(b.config) && b.fsTrackerVerified {
		if err := b.checkFaults(); err != nil {
			return err
		}
	}
	if previous, ok := b.active[c.CgroupID]; ok {
		if previous != c {
			return fmt.Errorf("cgroup identity conflicts with active binding")
		}
		previousRefs := b.restricted[c.CgroupID]
		if (previousRefs == nil) != (refs == nil) || (refs != nil && !previousRefs.same(refs)) {
			return fmt.Errorf("binding scope differs; explicitly unbind before changing scope")
		}
		return nil
	}
	for _, previous := range b.active {
		if previous.selector() == c.selector() {
			return fmt.Errorf("container identity already bound to a different cgroup")
		}
	}
	if len(b.active) >= execpolicy.KernelMaxBindings {
		return fmt.Errorf("container binding capacity exceeded")
	}
	value := uint64(0) // zero selects strict cgroup-only enforcement
	if refs != nil {
		value = refs.hostID.Inode
	}
	if err := b.members.Put(c.CgroupID, value); err != nil {
		return fmt.Errorf("writing container binding: %w", err)
	}
	b.active[c.CgroupID] = c
	if refs != nil {
		if b.restricted == nil {
			b.restricted = map[uint64]*namespaceRefs{}
		}
		b.restricted[c.CgroupID] = refs
		stored = true
	}
	return nil
}

// Unbind ignores stale removal notifications, which cannot remove a newer identity.
func (b *Bindings) Unbind(c ContainerIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready || b.stopped {
		return b.recordError(fmt.Errorf("binding controller is not running"))
	}
	err := b.unbind(c)
	b.recordError(err)
	return err
}

func (b *Bindings) unbind(c ContainerIdentity) error {
	if b.desired[c.selector()] == c {
		delete(b.desired, c.selector())
	}
	if previous, ok := b.active[c.CgroupID]; !ok || previous != c {
		return nil
	}
	if err := b.members.Delete(c.CgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("removing container binding: %w", err)
	}
	delete(b.active, c.CgroupID)
	if refs := b.restricted[c.CgroupID]; refs != nil {
		delete(b.restricted, c.CgroupID)
		return refs.close()
	}
	return nil
}

func (b *Bindings) container(kind string, c ContainerIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return nil
	}
	selected := false
	for _, target := range b.config.Targets {
		if target == c.selector() {
			selected = true
			break
		}
	}
	if !selected {
		return nil
	}
	if kind != "CREATED" && kind != "DELETED" {
		return nil
	}
	if err := c.validate(); err != nil {
		b.recordError(err)
		return err
	}
	if !b.ready || (filesystemRequired(b.config) && !b.fsTrackerVerified) {
		if kind == "CREATED" {
			b.desired[c.selector()] = c
		} else if b.desired[c.selector()] == c {
			delete(b.desired, c.selector())
		}
		return nil
	}
	var err error
	if kind == "CREATED" {
		err = b.bind(c)
	} else {
		err = b.unbind(c)
	}
	b.recordError(err)
	return err
}

type operator struct{}

func New() operators.DataOperator            { return &operator{} }
func init()                                  { operators.RegisterDataOperator(New()) }
func (*operator) Name() string               { return "enforce-exec" }
func (*operator) Priority() int              { return 1 }
func (*operator) Init(*params.Params) error  { return nil }
func (*operator) GlobalParams() api.Params   { return nil }
func (*operator) InstanceParams() api.Params { return nil }
func (*operator) InstantiateDataOperator(gc operators.GadgetContext, _ api.ParamValues) (operators.DataOperatorInstance, error) {
	value, _ := gc.GetVar(configKey)
	config, supplied := value.(Config)
	value, _ = gc.GetVar("config")
	metadata, ok := value.(*viper.Viper)
	fullImage := ok && metadata.GetBool("annotations.enforce-exec-full")
	if !ok || !metadata.GetBool("annotations.enforce-exec") {
		if fullImage || (supplied && config.Full != nil) {
			return nil, fmt.Errorf("full enforcement requires both enforce-exec and enforce-exec-full image annotations")
		}
		return nil, nil
	}
	if !supplied {
		return nil, fmt.Errorf("enforce_exec requires native policy configuration; use ig enforce-exec or runtime.WithConfig")
	}
	if err := validatePolicyConfig(config, fullImage); err != nil {
		return nil, err
	}
	if err := validateFullFeatures(config, metadata.GetString("annotations.enforce-exec-full-features")); err != nil {
		return nil, err
	}
	if len(config.Targets) > execpolicy.KernelMaxBindings {
		return nil, fmt.Errorf("too many container selectors")
	}
	seen := map[execpolicy.Container]bool{}
	for _, target := range config.Targets {
		if strings.TrimSpace(target.Runtime) == "" || strings.TrimSpace(target.ID) == "" || seen[target] {
			return nil, fmt.Errorf("invalid or duplicate container selector")
		}
		seen[target] = true
	}
	b := &Bindings{config: config, desired: map[execpolicy.Container]ContainerIdentity{}, active: map[uint64]ContainerIdentity{}, hostNamespaceSupported: !fullImage && metadata.GetBool("annotations.enforce-exec-host-namespace"), fullImage: fullImage, fullFeatures: metadata.GetString("annotations.enforce-exec-full-features")}
	if len(config.InitialBindings) > execpolicy.KernelMaxBindings {
		return nil, fmt.Errorf("too many initial bindings")
	}
	for _, c := range config.InitialBindings {
		if err := c.validate(); err != nil {
			return nil, err
		}
		if _, exists := b.desired[c.selector()]; exists {
			return nil, fmt.Errorf("duplicate initial container identity")
		}
		b.desired[c.selector()] = c
	}
	ds := gc.GetDataSources()["containers"]
	if ds == nil {
		if len(config.Targets) > 0 {
			return nil, fmt.Errorf("enforce_exec discovery targets require the containers datasource")
		}
		gc.SetVar(bindingsKey, b)
		return b, nil
	}
	for _, field := range []string{"event_type", "runtime", "container_id", "cgroup_id", "cgroup_v2_path"} {
		if ds.GetField(field) == nil {
			return nil, fmt.Errorf("missing container field %s", field)
		}
	}
	if err := ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
		kind, e1 := ds.GetField("event_type").String(data)
		runtime, e2 := ds.GetField("runtime").String(data)
		id, e3 := ds.GetField("container_id").String(data)
		cg, e4 := ds.GetField("cgroup_id").Uint64(data)
		cgpath, e5 := ds.GetField("cgroup_v2_path").String(data)
		if err := errors.Join(e1, e2, e3, e4, e5); err != nil {
			b.mu.Lock()
			defer b.mu.Unlock()
			return b.recordError(err)
		}
		return b.container(kind, ContainerIdentity{Runtime: runtime, ID: id, CgroupID: cg, CgroupPath: cgpath})
	}, 0); err != nil {
		return nil, err
	}
	gc.SetVar(bindingsKey, b)
	return b, nil
}
func (*Bindings) Name() string { return "enforce-exec" }
func (b *Bindings) Start(gc operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return fmt.Errorf("binding controller already stopped")
	}
	if b.startupError != nil {
		return b.startupError
	}
	getMap := func(name string) (*ebpf.Map, error) {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, ok := value.(*ebpf.Map)
		if !ok || m == nil {
			return nil, fmt.Errorf("missing BPF map %s", name)
		}
		return m, nil
	}
	policy, err := getMap("policy")
	if err != nil {
		return err
	}
	members, err := getMap("bindings")
	if err != nil {
		return err
	}
	var full immutableMap
	var faults faultMap
	var images imageMaps
	if b.config.Full != nil {
		images.origins, err = getMap("image_origins")
		if err != nil {
			return err
		}
		images.ready, err = getMap("image_ready")
		if err != nil {
			return err
		}
		faults, err = getMap("full_faults")
		if err != nil {
			return err
		}
		full, err = getMap("full_program")
		if err != nil {
			return err
		}
	}
	if filesystemRequired(b.config) {
		origins, e := getMap("fs_inode_origins")
		if e != nil {
			return e
		}
		diagnostics, e := getMap("fs_diagnostics")
		if e != nil {
			return e
		}
		if e = b.configureFilesystem(origins, diagnostics); e != nil {
			return e
		}
	}
	return b.startMaps(policy, members, full, faults, images)
}

// validatePolicyConfig runs both at admission and immediately before map writes.
// The role-less subset is deliberately an interim capability
// boundary, not a declaration that full exec semantics are implemented.
func validatePolicyConfig(config Config, fullImage bool) error {
	if fullImage != (config.Full != nil) {
		return fmt.Errorf("full image and full policy configuration must be supplied together")
	}
	if err := execpolicy.ValidateKernel(config.Entries); err != nil {
		return err
	}
	if config.Full == nil {
		if config.ImageOrigins != nil {
			return fmt.Errorf("image origins require a full program")
		}
		return nil
	}
	if err := validateImageOrigins(config.ImageOrigins); err != nil {
		return err
	}
	if err := fullpolicy.ValidateKernelProgram(config.Full); err != nil {
		return fmt.Errorf("invalid full program: %w", err)
	}
	header, err := fullpolicy.Decode[fullpolicy.KernelHeader](config.Full.Entries[0])
	if err != nil {
		return err
	}
	legacy := config.Entries[0]
	if header.Generation != legacy.Generation || legacy.Mode != 2 || legacy.Count != 0 || legacy.DefaultDeny != 0 {
		return fmt.Errorf("full program requires matching generation and an empty enforce/default-allow legacy header")
	}
	for i := uint32(0); i < header.RuleCount; i++ {
		rule, err := fullpolicy.Decode[fullpolicy.KernelRule](config.Full.Entries[header.RuleBase+i])
		if err != nil {
			return err
		}
		if rule.ActorRole.Count > 0 || rule.SetRole != 0 {
			return fmt.Errorf("full rule %d requires unsupported role state", i)
		}
		if rule.ActorImage != -1 || rule.TargetImage != -1 {
			if config.ImageOrigins == nil || !config.ImageOrigins.Complete {
				return fmt.Errorf("full rule %d requires complete trusted image-origin snapshot", i)
			}
		}
	}
	return nil
}

// Image capabilities are explicit. Omission never causes a predicate to be
// silently ignored. Role observations remain unsupported even if advertised.
// Filesystem unknowns become sticky operational faults, never false matches.
// Stdin support is restricted to x86 sole-owned descriptor tables; observation
// uncertainty becomes a sticky kernel fault/NotReady, never a false predicate.
func validateFullFeatures(config Config, annotation string) error {
	if config.Full == nil {
		return nil
	}
	features := map[string]bool{}
	for _, feature := range strings.Split(annotation, ",") {
		features[strings.TrimSpace(feature)] = true
	}
	require := func(name string) error {
		if !features[name] {
			return fmt.Errorf("full image lacks required capability %q", name)
		}
		return nil
	}
	if err := require("path"); err != nil {
		return err
	}
	header, err := fullpolicy.Decode[fullpolicy.KernelHeader](config.Full.Entries[0])
	if err != nil {
		return err
	}
	for i := uint32(0); i < header.RuleCount; i++ {
		rule, err := fullpolicy.Decode[fullpolicy.KernelRule](config.Full.Entries[header.RuleBase+i])
		if err != nil {
			return err
		}
		required := []struct {
			name string
			used bool
		}{
			{"image", rule.ActorImage != -1 || rule.TargetImage != -1},
			{"stdin", rule.Stdin != -1},
			{"fs", rule.FSType.Count > 0},
			{"uid", rule.UID.Count > 0},
			{"argv", rule.ArgContains.Count > 0 || rule.ArgPrefix.Count > 0},
			{"actor-path", rule.ActorPath.Count > 0},
			{"ancestor", rule.AncestorPath.Count > 0},
		}
		for _, feature := range required {
			if feature.used {
				if err := require(feature.name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// checkFaults preserves a sticky operational failure without withdrawing
// last-good enforcement. Never access borrowed map handles after Stop.
func (b *Bindings) checkFaults() error {
	if b.stopped || b.faults == nil || b.kernelError != nil {
		return b.kernelError
	}
	var value uint64
	if err := b.faults.Lookup(uint32(0), &value); err != nil {
		b.kernelError = fmt.Errorf("reading full enforcement faults: %w", err)
	} else if value != 0 {
		b.kernelError = fmt.Errorf("full enforcement cannot observe required authoritative facts (fault mask %d)", value)
	}
	if b.kernelError == nil && b.fsHealth != nil {
		b.kernelError = b.fsHealth()
	}
	return b.kernelError
}

func validateImageOrigins(snapshot *ImageOriginSnapshot) error {
	if snapshot == nil {
		return nil
	}
	if !snapshot.Complete {
		return fmt.Errorf("image-origin snapshot is incomplete")
	}
	if len(snapshot.Keys) > MaxImageOrigins {
		return fmt.Errorf("image-origin snapshot exceeds %d keys", MaxImageOrigins)
	}
	seen := make(map[ImageOriginKey]struct{}, len(snapshot.Keys))
	for _, key := range snapshot.Keys {
		if key.Inode == 0 || key.Major >= 1<<12 || key.Minor >= 1<<20 {
			return fmt.Errorf("invalid image-origin key")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate image-origin key")
		}
		seen[key] = struct{}{}
	}
	return nil
}

type imageMaps struct{ origins, ready immutableMap }

func (m imageMaps) validate() error {
	if m.origins == nil || m.origins.Type() != ebpf.Hash || m.origins.KeySize() != 16 || m.origins.ValueSize() != 1 || m.origins.MaxEntries() != MaxImageOrigins || m.origins.Flags() != unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG {
		return fmt.Errorf("invalid immutable image-origin map layout")
	}
	if m.ready == nil || m.ready.Type() != ebpf.Array || m.ready.KeySize() != 4 || m.ready.ValueSize() != 4 || m.ready.MaxEntries() != 1 || m.ready.Flags() != unix.BPF_F_RDONLY_PROG {
		return fmt.Errorf("invalid immutable image-ready map layout")
	}
	return nil
}

func (m imageMaps) populate(snapshot *ImageOriginSnapshot) error {
	var ready uint32
	if snapshot != nil {
		for _, key := range snapshot.Keys {
			if err := m.origins.Put(key, uint8(1)); err != nil {
				return fmt.Errorf("writing image origins: %w", err)
			}
		}
		if snapshot.Complete {
			ready = 1
		}
	}
	if err := m.origins.Freeze(); err != nil {
		return fmt.Errorf("freezing image origins: %w", err)
	}
	if err := m.ready.Put(uint32(0), ready); err != nil {
		return fmt.Errorf("writing image readiness: %w", err)
	}
	if err := m.ready.Freeze(); err != nil {
		return fmt.Errorf("freezing image readiness: %w", err)
	}
	return nil
}

// startMaps is called with b.mu held. No binding becomes visible until every
// immutable map has been validated, populated and frozen successfully.
func (b *Bindings) startMaps(policy, members, full immutableMap, faults faultMap, images imageMaps) error {
	if b.ready {
		return fmt.Errorf("binding controller already started")
	}
	if err := validatePolicyConfig(b.config, b.fullImage); err != nil {
		return err
	}
	if err := validateFullFeatures(b.config, b.fullFeatures); err != nil {
		return err
	}
	if policy == nil || policy.Type() != ebpf.Array || policy.KeySize() != 4 || policy.ValueSize() != 288 || policy.MaxEntries() != execpolicy.KernelMaxRules+1 || policy.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
		return fmt.Errorf("invalid immutable policy map layout")
	}
	if members == nil || members.Type() != ebpf.Hash || members.KeySize() != 8 || members.ValueSize() != 8 || members.MaxEntries() != execpolicy.KernelMaxBindings {
		return fmt.Errorf("invalid binding map layout")
	}
	if b.config.Full != nil {
		if err := images.validate(); err != nil {
			return err
		}
		if faults == nil || faults.Type() != ebpf.Array || faults.KeySize() != 4 || faults.ValueSize() != 8 || faults.MaxEntries() != 1 || faults.Flags() != unix.BPF_F_RDONLY {
			return fmt.Errorf("invalid full fault map layout")
		}
		if full == nil || full.Type() != ebpf.Hash || full.KeySize() != 4 || full.ValueSize() != fullpolicy.KernelBlobSize || full.MaxEntries() != fullpolicy.MaxKernelEntries || full.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
			return fmt.Errorf("invalid immutable full program map layout")
		}
	} else if full != nil {
		return fmt.Errorf("unexpected full program map for legacy configuration")
	}
	for i, entry := range b.config.Entries {
		if err := policy.Put(uint32(i), entry); err != nil {
			return fmt.Errorf("writing policy: %w", err)
		}
	}
	if err := policy.Freeze(); err != nil {
		return fmt.Errorf("freezing policy: %w", err)
	}
	if b.config.Full != nil {
		for i, entry := range b.config.Full.Entries {
			if err := full.Put(uint32(i), entry); err != nil {
				return fmt.Errorf("writing full program: %w", err)
			}
		}
		if err := full.Freeze(); err != nil {
			return fmt.Errorf("freezing full program: %w", err)
		}
		if err := images.populate(b.config.ImageOrigins); err != nil {
			return err
		}
	}
	b.faults = faults
	if err := b.checkFaults(); err != nil {
		return err
	}
	b.members = members
	if filesystemRequired(b.config) {
		// Global marker hook is attached by the eBPF operator. Its concrete
		// probe must pass at final Ready before ANY binding write.
		b.ready = true
		return nil
	}
	for _, c := range b.desired {
		if err := b.bind(c); err != nil {
			b.recordError(err)
			return err
		}
	}
	b.desired = nil
	b.ready = true
	return nil
}

func (b *Bindings) Stop(operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	b.ready = false
	// Remove exception values before releasing their namespace references. Strict
	// bindings have no owned resources and are released by the eBPF operator.
	var errs []error
	for cgroup := range b.restricted {
		if err := b.unbind(b.active[cgroup]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PostStop runs after all operators' Stop methods, including eBPF link detach.
// Only this boundary may release references retained after failed map deletion.
func (b *Bindings) PostStop(operators.GadgetContext) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.stopped {
		return fmt.Errorf("namespace cleanup requires stopped operators")
	}
	var errs []error
	for cgroup, refs := range b.restricted {
		errs = append(errs, refs.close())
		delete(b.restricted, cgroup)
		delete(b.active, cgroup)
	}
	return errors.Join(errs...)
}

func (b *Bindings) Close(gc operators.GadgetContext) error { return b.Stop(gc) }

// InitializeImageOrigins is for a trusted native persistent owner, before scope
// activation. It shares the immutable reader's validation and freeze contract.
func InitializeImageOrigins(origins, ready *ebpf.Map, snapshot *ImageOriginSnapshot) error {
	if origins == nil || ready == nil {
		return fmt.Errorf("image-origin maps required")
	}
	if err := validateImageOrigins(snapshot); err != nil {
		return err
	}
	maps := imageMaps{origins: origins, ready: ready}
	if err := maps.validate(); err != nil {
		return err
	}
	return maps.populate(snapshot)
}

// ValidateImageOriginSnapshot validates trusted native input without touching
// maps. Complete is an owner attestation, never a policy-provided assertion.
func ValidateImageOriginSnapshot(snapshot *ImageOriginSnapshot) error {
	return validateImageOrigins(snapshot)
}
