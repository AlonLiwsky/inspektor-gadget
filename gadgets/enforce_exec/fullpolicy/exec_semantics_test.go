package fullpolicy

import (
	"encoding/json"
	"reflect"
	"testing"
	"unsafe"
)

func TestExecNewFieldsNotNativeReady(t *testing.T) {
	for _, change := range []func(*Policy){
		func(p *Policy) { p.DefaultMode = Audit },
		func(p *Policy) { p.DefaultOrigin = "catalog/A1" },
		func(p *Policy) {
			p.Rules = []Rule{{Name: "d", Action: Deny, Except: []Exception{{Target: Target{Path: []string{"/bin/sh"}}}}}}
		},
		func(p *Policy) { p.Rules = []Rule{{Name: "d", Action: Deny, Except: []Exception{}}} },
	} {
		p := base()
		change(&p)
		if _, err := Compile([]Policy{p}); err == nil {
			t.Fatal("Compile silently accepted native-unsupported semantics")
		}
		if _, err := CompileKernel([]Policy{p}, 1, "app"); err == nil {
			t.Fatal("native compiler silently accepted new semantics")
		}
	}
}

func TestExecExceptionsReference(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "d", Action: Deny, Target: Target{Path: []string{"/bin/*"}}, Except: []Exception{{Actor: Actor{Container: []string{"trusted"}}, Target: Target{Path: []string{"/bin/sh"}}}, {Target: Target{Path: []string{"/bin/true"}}}}}}
	q := base()
	q.ID = "other"
	q.Rules = []Rule{{Name: "other-deny", Action: Deny, Target: Target{Path: []string{"/bin/sh"}}}}
	prog, err := CompileReference([]Policy{p})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		container, path string
		deny            bool
	}{{"trusted", "/bin/sh", false}, {"other", "/bin/sh", true}, {"other", "/bin/true", false}, {"trusted", "/bin/false", true}} {
		d, err := prog.Evaluate(Facts{Container: tc.container, TargetPath: tc.path})
		if err != nil || d.Block != tc.deny {
			t.Fatalf("%+v: %+v %v", tc, d, err)
		}
	}
	prog, err = CompileReference([]Policy{p, q})
	if err != nil {
		t.Fatal(err)
	}
	d, err := prog.Evaluate(Facts{Container: "trusted", TargetPath: "/bin/sh"})
	if err != nil || !d.Block || len(d.Matches) != 1 || d.Matches[0].PolicyID != "other" {
		t.Fatalf("own deny only: %+v %v", d, err)
	}
	d, meta, err := prog.EvaluateWithMetadata(Facts{TargetPath: "/bin/sh"})
	if err != nil || !d.Block || !meta.DisabledExceptions[p.ID] {
		t.Fatalf("unknown exception lifted deny: %+v %v", d, err)
	}
}

func TestExecDefaultWinnerMetadata(t *testing.T) {
	standalone := base()
	standalone.Default = Deny
	standalone.DefaultMode = Audit
	standalone.DefaultOrigin = "catalog/A1"
	sp, err := CompileReference([]Policy{standalone})
	if err != nil {
		t.Fatal(err)
	}
	sd, sm, err := sp.EvaluateWithMetadata(Facts{})
	if err != nil || sd.Block || sd.Mode != Audit || !reflect.DeepEqual(sm.DefaultOrigins, []string{"catalog/A1"}) {
		t.Fatalf("explicit audit default must override enforce policy mode: %+v %+v %v", sd, sm, err)
	}
	a, b, c := base(), base(), base()
	a.ID = "a"
	b.ID = "b"
	c.ID = "c"
	a.Default = Deny
	a.DefaultMode = Audit
	a.DefaultOrigin = "z"
	b.Default = Deny
	b.DefaultMode = Enforce
	b.DefaultOrigin = "a"
	c.Default = Allow
	c.DefaultOrigin = "loser"
	prog, err := CompileReference([]Policy{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	d, meta, err := prog.EvaluateWithMetadata(Facts{})
	if err != nil || !d.Block || d.Mode != Enforce || !reflect.DeepEqual(meta.DefaultOrigins, []string{"a", "z"}) {
		t.Fatalf("merged default: %+v %v", d, err)
	}
	a.Default = Allow
	b.Default = Allow
	c.Default = Allow
	c.DefaultMode = Audit
	c.DefaultOrigin = "a"
	prog, err = CompileReference([]Policy{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	d, meta, err = prog.EvaluateWithMetadata(Facts{})
	if err != nil || d.Block || d.Mode != Enforce || !reflect.DeepEqual(meta.DefaultOrigins, []string{"a", "z"}) {
		t.Fatalf("all allow default: %+v %v", d, err)
	}
}

func TestExecExceptionValidationAndOwnership(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "d", Action: Deny, Except: []Exception{{Target: Target{Path: []string{"/bin/sh"}}}}}}
	prog, err := CompileReference([]Policy{p})
	if err != nil {
		t.Fatal(err)
	}
	p.Rules[0].Except[0].Target.Path[0] = "/bin/other"
	d, err := prog.Evaluate(Facts{TargetPath: "/bin/sh"})
	if err != nil || d.Block {
		t.Fatalf("aliased exception: %+v %v", d, err)
	}
	for _, bad := range []Exception{{}, {Target: Target{SetRole: "x"}}, {Target: Target{Path: []string{"relative"}}}} {
		p := base()
		p.Rules = []Rule{{Name: "d", Action: Deny, Except: []Exception{bad}}}
		if _, err := CompileReference([]Policy{p}); err == nil {
			t.Fatalf("accepted invalid exception %+v", bad)
		}
	}
	p = base()
	p.Rules = []Rule{{Name: "a", Action: Allow, Except: []Exception{{Actor: Actor{Role: []string{"x"}}}}}}
	if _, err := CompileReference([]Policy{p}); err == nil {
		t.Fatal("accepted allow exception")
	}
	p = base()
	p.DefaultMode = Mode("off")
	if _, err := CompileReference([]Policy{p}); err == nil {
		t.Fatal("accepted invalid default mode")
	}
	p = base()
	p.Rules = []Rule{{Name: "d", Action: Deny, Except: make([]Exception, MaxValues+1)}}
	if _, err := CompileReference([]Policy{p}); err == nil {
		t.Fatal("accepted exception capacity overflow")
	}
	p = base()
	image := true
	p.Rules = []Rule{{Name: "d", Action: Deny, Except: []Exception{{Actor: Actor{FromImage: &image}}}}}
	prog, err = CompileReference([]Policy{p})
	if err != nil {
		t.Fatal(err)
	}
	image = false
	d, err = prog.Evaluate(Facts{ActorFromImage: ptr(true)})
	if err != nil || d.Block {
		t.Fatalf("aliased exception pointer: %+v %v", d, err)
	}
}

func TestExecOriginPresence(t *testing.T) {
	for _, change := range []func(*Policy){
		func(p *Policy) { p.DefaultOriginPresent = true },
		func(p *Policy) { p.Rules = []Rule{{Name: "r", Action: Allow, OriginPresent: true}} },
	} {
		p := base()
		change(&p)
		if _, err := Compile([]Policy{p}); err == nil {
			t.Fatal("Compile accepted explicit empty origin")
		}
		if _, err := CompileKernel([]Policy{p}, 1, "app"); err == nil {
			t.Fatal("CompileKernel accepted explicit empty origin")
		}
	}
	for _, tc := range []struct {
		name    string
		value   string
		present bool
		want    []string
	}{
		{name: "omitted", want: []string{}},
		{name: "explicit-empty", present: true, want: []string{""}},
		{name: "legacy-nonempty", value: "catalog/A1", want: []string{"catalog/A1"}},
		{name: "marked-nonempty", value: "catalog/A1", present: true, want: []string{"catalog/A1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			p.DefaultOrigin = tc.value
			p.DefaultOriginPresent = tc.present
			prog, err := CompileReference([]Policy{p})
			if err != nil {
				t.Fatal(err)
			}
			_, meta, err := prog.EvaluateWithMetadata(Facts{})
			if err != nil || !reflect.DeepEqual(meta.DefaultOrigins, tc.want) {
				t.Fatalf("default origins=%q want=%q err=%v", meta.DefaultOrigins, tc.want, err)
			}
			defaultJSON, err := json.Marshal(meta.DefaultOrigins)
			wantJSON, _ := json.Marshal(tc.want)
			if err != nil || string(defaultJSON) != string(wantJSON) {
				t.Fatalf("default JSON origins=%s want=%s err=%v", defaultJSON, wantJSON, err)
			}
			p.Rules = []Rule{{Name: "r", Action: Allow, Origin: tc.value, OriginPresent: tc.present}}
			prog, err = CompileReference([]Policy{p})
			if err != nil {
				t.Fatal(err)
			}
			_, meta, err = prog.EvaluateWithMetadata(Facts{})
			if err != nil || len(meta.RuleOrigins) != 1 || !reflect.DeepEqual(meta.RuleOrigins[0].Origins, tc.want) {
				t.Fatalf("rule origins=%+v want=%q err=%v", meta.RuleOrigins, tc.want, err)
			}
			ruleJSON, err := json.Marshal(meta.RuleOrigins[0].Origins)
			if err != nil || string(ruleJSON) != string(wantJSON) {
				t.Fatalf("rule JSON origins=%s want=%s err=%v", ruleJSON, wantJSON, err)
			}
			encoded, err := json.Marshal(meta)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				DefaultOrigins json.RawMessage
				RuleOrigins    []struct{ Origins json.RawMessage }
			}
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			if string(wire.DefaultOrigins) != "[]" || string(wire.RuleOrigins[0].Origins) != string(wantJSON) {
				// A matched rule suppresses the default; its origin is still list-shaped.
				t.Fatalf("metadata JSON origin shape: %s", encoded)
			}
			if tc.present && tc.value == "" {
				if _, err = Compile([]Policy{p}); err == nil {
					t.Fatal("native accepted explicit empty origins")
				}
				if _, err = CompileKernel([]Policy{p}, 1, "app"); err == nil {
					t.Fatal("kernel accepted explicit empty origins")
				}
			}
		})
	}
	// A losing default, even an explicitly empty one, cannot contribute origin.
	a, b := base(), base()
	a.ID = "a"
	b.ID = "b"
	a.Default = Deny
	b.Default = Allow
	a.DefaultOriginPresent = true
	b.DefaultOrigin = "loser"
	prog, err := CompileReference([]Policy{a, b})
	if err != nil {
		t.Fatal(err)
	}
	_, meta, err := prog.EvaluateWithMetadata(Facts{})
	if err != nil || !reflect.DeepEqual(meta.DefaultOrigins, []string{""}) {
		t.Fatalf("winner-only explicit-empty origin: %+v %v", meta, err)
	}
	winnerJSON, err := json.Marshal(meta.DefaultOrigins)
	if err != nil || string(winnerJSON) != `[""]` {
		t.Fatalf("winner JSON origins=%s err=%v", winnerJSON, err)
	}
	c, d := base(), base()
	c.ID = "c"
	d.ID = "d"
	c.Default = Deny
	d.Default = Deny
	c.DefaultOrigin = "z"
	d.DefaultOrigin = "z"
	prog, err = CompileReference([]Policy{a, b, c, d})
	if err != nil {
		t.Fatal(err)
	}
	_, meta, err = prog.EvaluateWithMetadata(Facts{})
	if err != nil {
		t.Fatal(err)
	}
	winnerJSON, err = json.Marshal(meta.DefaultOrigins)
	if err != nil || string(winnerJSON) != `["","z"]` {
		t.Fatalf("merged sorted/distinct winner origins=%s err=%v", winnerJSON, err)
	}
	label := "catalog/A1"
	p := base()
	p.DefaultOrigin = label
	p.Rules = []Rule{{Name: "r", Action: Allow, Origin: label}}
	prog, err = CompileReference([]Policy{p})
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.StringData(prog.policies[0].source.DefaultOrigin) == unsafe.StringData(p.DefaultOrigin) || unsafe.StringData(prog.policies[0].rules[0].source.Origin) == unsafe.StringData(p.Rules[0].Origin) {
		t.Fatal("reference retained caller origin string backing")
	}
}
