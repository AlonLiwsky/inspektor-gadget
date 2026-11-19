// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	jsonformatter "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// Policy is host-owned startup map data. It never enters the gadget parameter
// protocol, and changing rules requires creating a replacement instance.
func newEnforceExecCommand(runtime *local.Runtime) *cobra.Command {
	var policyFile string
	var revision uint64
	ociParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()
	globals := map[string]*params.Params{}
	ops := make([]operators.DataOperator, 0)
	for _, op := range operators.GetDataOperators() {
		ops = append(ops, op)
		globals[op.Name()] = apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
	}
	cmd := &cobra.Command{
		Use:          "enforce-exec IMAGE --policy FILE",
		Short:        "Enforce immutable execution rules for a live set of containers",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if policyFile == "" {
				return fmt.Errorf("--policy is required")
			}
			entries, targets, err := readExecPolicy(policyFile, revision)
			if err != nil {
				return err
			}
			for _, op := range ops {
				if err := common.SetFlagsForParams(cmd, globals[op.Name()], config.OperatorKey+"."+op.Name()); err != nil {
					return err
				}
			}
			if err := common.SetFlagsForParams(cmd, ociParams, config.OperatorKey+".oci"); err != nil {
				return err
			}
			if err := runtime.Init(runtime.GlobalParamDescs().ToParams()); err != nil {
				return err
			}
			defer runtime.Close()
			for _, op := range ops {
				if err := op.Init(globals[op.Name()]); err != nil {
					return fmt.Errorf("initializing operator %s: %w", op.Name(), err)
				}
			}
			output := simple.New("exec-json", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
				verdict := gc.GetDataSources()["verdict"]
				if verdict == nil {
					return fmt.Errorf("missing execution verdict datasource")
				}
				formatter, err := jsonformatter.New(verdict)
				if err != nil {
					return err
				}
				return verdict.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
					_, err := fmt.Fprintln(cmd.OutOrStdout(), string(formatter.Marshal(data)))
					return err
				}, 1000001)
			}))
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			instanceID := uuid.NewString()
			var gc *gadgetcontext.GadgetContext
			gc = gadgetcontext.New(ctx, args[0], gadgetcontext.WithID(instanceID), gadgetcontext.WithDataOperators(ops...), gadgetcontext.WithAdditionalDataOperators(output), execruntime.WithConfig(execruntime.Config{Entries: entries, Targets: targets}), gadgetcontext.WithOnStarted(func() error {
				bindings, err := execruntime.GetBindings(gc)
				if err != nil {
					return err
				}
				status := bindings.Status()
				if status.Error != nil {
					return fmt.Errorf("execution binding startup: %w", status.Error)
				}
				if !status.Ready {
					return fmt.Errorf("execution bindings are not ready")
				}
				_, err = fmt.Fprintf(cmd.ErrOrStderr(), "enforce_exec ready: instance=%s revision=%d bindings=%d\n", instanceID, revision, status.Bound)
				return err
			}))
			values := api.ParamValues{}
			ociParams.CopyToMap(values, "operator.oci.")
			return runtime.RunGadget(gc, runtime.ParamDescs().ToParams(), values)
		},
	}
	cmd.Flags().StringVar(&policyFile, "policy", "", "Container identities and execution rules YAML")
	cmd.Flags().Uint64Var(&revision, "revision", 1, "Nonzero policy revision stamped on verdicts; use a new revision for replacements")
	common.AddOCIFlags(cmd, ociParams, nil, runtime)
	for _, op := range ops {
		common.AddOCIFlags(cmd, globals[op.Name()], nil, runtime)
	}
	return cmd
}

func readExecPolicy(filename string, revision uint64) ([execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry, []execpolicy.Container, error) {
	var empty [execpolicy.KernelMaxRules + 1]execpolicy.KernelEntry
	f, err := os.Open(filename)
	if err != nil {
		return empty, nil, fmt.Errorf("opening policy: %w", err)
	}
	defer f.Close()
	doc, err := execpolicy.Parse(io.LimitReader(f, execpolicy.DefaultLimits().MaxBytes+1), execpolicy.DefaultLimits())
	if err != nil {
		return empty, nil, err
	}
	entries, err := execpolicy.CompileKernel(doc, revision)
	if err != nil {
		return empty, nil, err
	}
	return entries, doc.Binding.Targets(), nil
}
