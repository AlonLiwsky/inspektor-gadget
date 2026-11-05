// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpfoperator

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
)

func TestGetFormattersForEnums(t *testing.T) {
	nonBitfieldEnum := constructNValuedEnum([]string{"A", "B", "C"}, "field1", false)
	bitfieldEnum := constructNValuedEnum([]string{"A", "B", "C"}, "field1", true)

	type testCaseDatum struct {
		enum                    *enum
		inputValue              uint64
		expectedOutput          string
		expectedTargetFieldName string
		separator               string
		targetAnnotation        string
		isMatch                 bool
	}

	type testCase struct {
		name        string
		noOfMatches uint8
		data        []testCaseDatum
	}

	testCases := []testCase{
		{
			name:        "Single non-bitfield enum valid",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Single non-bitfield enum valid no target annotation",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    constructNValuedEnum([]string{"A", "B", "C"}, "field1_raw", false),
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Single bitfield enum multiple flags",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    bitfieldEnum,
					inputValue:              3,
					expectedOutput:          "A|B|C",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Non-bitfield enum unknown",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					inputValue:              5,
					expectedOutput:          "UNKNOWN",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Non-bitfield enum with multiple similar values",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Bitfield enum no flags set",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    bitfieldEnum,
					inputValue:              0,
					expectedOutput:          "",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Bitfield enum custom separator",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    bitfieldEnum,
					inputValue:              3,
					expectedOutput:          "A, B, C",
					expectedTargetFieldName: "field1",
					separator:               ", ",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Multiple enums, first non-match then match",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					expectedTargetFieldName: "nonmatch_field1",
					targetAnnotation:        "target1",
					isMatch:                 false,
				},
				{
					enum:                    constructNValuedEnum([]string{"Match"}, "field2", false),
					inputValue:              1,
					expectedOutput:          "Match",
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Multiple non-bitfield enums both matching",
			noOfMatches: 2,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
				{
					enum:                    constructNValuedEnum([]string{"Second"}, "field2", false),
					inputValue:              1,
					expectedOutput:          "Second",
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Non-bitfield then bitfield enum, bitfield wins",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    constructNValuedEnum([]string{"Plain"}, "nonmatch_field2", false),
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 false,
				},
				{
					enum:                    bitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Multiple bitfield enums, last wins",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    constructNValuedEnum([]string{"FirstFlag"}, "nonmatch_field2", true),
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 false,
				},
				{
					enum:                    bitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds, _ := datasource.New(datasource.TypeSingle, "formatters")
			fas := make(map[string]datasource.FieldAccessor)

			for _, test := range tc.data {
				var fn string
				if test.targetAnnotation != "" {
					fn = test.expectedTargetFieldName
				} else {
					fn = test.expectedTargetFieldName + "_raw"
				}
				in, err := ds.AddField(fn, api.Kind_Uint64)
				require.NoError(t, err)
				require.NotNil(t, in)
				if test.separator != "" {
					in.AddAnnotation(enumBitfieldSeparatorAnnotation, test.separator)
				}
				if test.targetAnnotation != "" {
					in.AddAnnotation(enumTargetNameAnnotation, test.targetAnnotation)
				}
				fas[test.expectedTargetFieldName] = in
			}

			lg := logger.DefaultLogger()

			var enums []*enum
			for _, test := range tc.data {
				enums = append(enums, test.enum)
			}
			formatters, err := getFormattersForEnums(enums, ds, nil, lg)
			require.NoError(t, err)
			require.Len(t, formatters, int(tc.noOfMatches))

			formattersIndex := 0
			for _, test := range tc.data {
				if !test.isMatch {
					continue
				}
				data, _ := ds.NewPacketSingle()
				in := fas[test.expectedTargetFieldName]
				in.PutUint64(data, test.inputValue)

				err = formatters[formattersIndex](ds, data)
				require.NoError(t, err)

				var out datasource.FieldAccessor
				if test.targetAnnotation != "" {
					out = ds.GetField(test.targetAnnotation)
				} else {
					out = ds.GetField(test.expectedTargetFieldName)
				}
				res, _ := out.String(data)
				require.Equal(t, test.expectedOutput, res)
				formattersIndex++
			}
		})
	}
}

func TestFetchAndFormatStackTrace(t *testing.T) {
	type testCase struct {
		name          string
		stackEntries  [ebpftypes.KernelPerfMaxStackDepth]uint64
		expectedTrace string
	}

	testCases := []testCase{
		{
			name: "Valid stack trace",
			stackEntries: [ebpftypes.KernelPerfMaxStackDepth]uint64{
				0xabcdef, 0x123456, 0x312414, 0,
			},
			expectedTrace: "funcA; funcB; unknown; ",
		},
		{
			name: "Empty stack trace",
			stackEntries: [ebpftypes.KernelPerfMaxStackDepth]uint64{
				0, 0, 0, 0,
			},
			expectedTrace: "",
		},
		{
			name: "Single valid entry",
			stackEntries: [ebpftypes.KernelPerfMaxStackDepth]uint64{
				0xabcdef, 0, 0, 0,
			},
			expectedTrace: "funcA; ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Custom stack lookup function for this test case.
			stackLookup := func(key interface{}, valueOut interface{}) error {
				stack := valueOut.(*[ebpftypes.KernelPerfMaxStackDepth]uint64)
				*stack = tc.stackEntries
				return nil
			}

			result, err := fetchAndFormatStackTrace(42, stackLookup, lookupByInstructionPointer)
			require.NoError(t, err)
			require.Equal(t, tc.expectedTrace, result)
		})
	}
}

func lookupByInstructionPointer(addr uint64) (string, error) {
	switch addr {
	case 0xabcdef:
		return "funcA", nil
	case 0x123456:
		return "funcB", nil
	default:
		return "unknown", nil
	}
}

func constructNValuedEnum(keys []string, memberName string, isBitField bool) *enum {
	var vals []btf.EnumValue
	for i, v := range keys {
		vals = append(vals, btf.EnumValue{Name: v, Value: uint64(i + 1)})
	}

	name := "testenum"
	if isBitField {
		name += "_set"
	}
	return &enum{
		Enum: &btf.Enum{
			Name:   name,
			Values: vals,
			Signed: false,
		},
		memberName: memberName,
	}
}

// Embed the unused context methods: initialization only needs data sources.
type stackFormatterContext struct {
	operators.GadgetContext
	ds datasource.DataSource
}

func (c stackFormatterContext) GetDataSources() map[string]datasource.DataSource {
	return map[string]datasource.DataSource{"stacks": c.ds}
}

func TestInitStackConverter(t *testing.T) {
	constructorErr := errors.New("cannot read kernel symbols")
	for _, tc := range []struct {
		name           string
		tagged         bool
		constructorErr error
	}{
		{name: "symbolizes installed converters", tagged: true},
		{name: "untagged fields need no resolver"},
		{name: "constructor error is cached after first nonempty stack", tagged: true, constructorErr: constructorErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds, err := datasource.New(datasource.TypeSingle, "stacks")
			require.NoError(t, err)
			for _, name := range []string{"first_raw", "second_raw"} {
				in, err := ds.AddField(name, api.Kind_Uint32)
				require.NoError(t, err)
				if tc.tagged {
					in.AddTags("type:" + ebpftypes.KernelStackTypeName)
				}
			}
			i := &ebpfInstance{
				logger:         logger.DefaultLogger(),
				collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{ebpftypes.KernelStackMapName: {}}},
				formatters:     make(map[datasource.DataSource][]func(datasource.DataSource, datasource.Data) error),
			}
			constructorCalls, lookupCalls := 0, 0
			err = i.initStackConverterWithDependencies(stackFormatterContext{ds: ds}, func() (*kallsyms.KAllSyms, error) {
				constructorCalls++
				if tc.constructorErr != nil {
					return nil, tc.constructorErr
				}
				return kallsyms.NewKAllSymsFromReader(strings.NewReader("0000000000001000 T first_symbol\n0000000000002000 T second_symbol\n"))
			}, func(key, valueOut interface{}) error {
				lookupCalls++
				require.Equal(t, uint32(42), key)
				*valueOut.(*[ebpftypes.KernelPerfMaxStackDepth]uint64) = [ebpftypes.KernelPerfMaxStackDepth]uint64{0x1004, 0x2008}
				return nil
			})
			require.NoError(t, err)
			if !tc.tagged {
				require.Zero(t, constructorCalls)
				require.Empty(t, i.formatters)
				require.Zero(t, lookupCalls)
				return
			}
			require.Len(t, i.formatters[ds], 2)
			require.Zero(t, constructorCalls, "symbol loading must be deferred until a stack is formatted")
			data, err := ds.NewPacketSingle()
			require.NoError(t, err)
			for _, name := range []string{"first_raw", "second_raw"} {
				ds.GetField(name).PutUint32(data, 42)
			}
			for _, converter := range i.formatters[ds] {
				require.NoError(t, converter(ds, data))
			}
			for _, name := range []string{"first", "second"} {
				result, err := ds.GetField(name).String(data)
				require.NoError(t, err)
				if tc.constructorErr != nil {
					require.Empty(t, result, "failed symbol resolution clears the formatted field")
				} else {
					require.Equal(t, "first_symbol; second_symbol; ", result)
				}
			}
			require.Equal(t, 1, constructorCalls, "resolver is shared across stack fields")
			require.Equal(t, 2, lookupCalls)
		})
	}
}

func TestInitStackConverterUsesMapAssignedAfterInitialization(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "stacks")
	require.NoError(t, err)
	in, err := ds.AddField("stack_raw", api.Kind_Uint32, datasource.WithTags("type:"+ebpftypes.KernelStackTypeName))
	require.NoError(t, err)
	i := &ebpfInstance{
		logger:         logger.DefaultLogger(),
		collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{ebpftypes.KernelStackMapName: {}}},
		formatters:     make(map[datasource.DataSource][]func(datasource.DataSource, datasource.Data) error),
	}
	// Production initializes formatters before loading and assigning the map.
	require.NoError(t, i.initStackConverter(stackFormatterContext{ds: ds}))
	require.Len(t, i.formatters[ds], 1)
	i.kernelStackMap = &ebpf.Map{}
	// A zero-value map rejects this key before making a syscall. This tests
	// late binding without requiring BPF privileges; symbolization is covered
	// separately with nonempty stacks in TestInitStackConverter.
	stack := [ebpftypes.KernelPerfMaxStackDepth]uint64{}
	require.ErrorContains(t, i.kernelStackMap.Lookup(uint32(42), &stack), "marshal key")
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	in.PutUint32(data, 42)
	require.NotPanics(t, func() {
		require.NoError(t, i.formatters[ds][0](ds, data))
	})
}

func TestInitEnumFormatterLoadsKernelBTFOnlyForEnums(t *testing.T) {
	loads := 0
	orig := loadKernelSpec
	loadKernelSpec = func() (*btf.Spec, error) {
		loads++
		return nil, btf.ErrNotFound
	}
	t.Cleanup(func() { loadKernelSpec = orig })

	newInstance := func(enums []*enum) *ebpfInstance {
		return &ebpfInstance{
			logger:     logger.DefaultLogger(),
			enums:      enums,
			formatters: make(map[datasource.DataSource][]func(datasource.DataSource, datasource.Data) error),
		}
	}

	ctx := newResolverGadgetCtx(t, nil)
	t.Cleanup(ctx.Cancel)
	ds, err := ctx.RegisterDataSource(datasource.TypeSingle, "events")
	require.NoError(t, err)
	in, err := ds.AddField("field1", api.Kind_Uint32)
	require.NoError(t, err)
	in.AddAnnotation(enumTargetNameAnnotation, "field1_str")

	require.NoError(t, newInstance(nil).initEnumFormatter(ctx))
	require.Zero(t, loads, "a gadget without enum fields must not load the kernel BTF")

	withEnum := newInstance([]*enum{constructNValuedEnum([]string{"A", "B"}, "field1", false)})
	require.NoError(t, withEnum.initEnumFormatter(ctx))
	require.Equal(t, 1, loads)
	require.Len(t, withEnum.formatters[ds], 1, "the gadget's own enum is still formatted without kernel BTF")
}

func TestStopDetachesRawProgramsOnceAfterFailedStart(t *testing.T) {
	ctx := newResolverGadgetCtx(t, nil)
	defer ctx.Cancel()
	calls := 0
	instance := &ebpfInstance{
		done:   make(chan struct{}),
		logger: logger.DefaultLogger(),
		rawDetachers: []func() error{func() error {
			calls++
			return errors.New("already detached")
		}},
	}
	// Stop may run without PreStop after a failed Start, then again during Close.
	require.NoError(t, instance.Stop(ctx))
	require.NoError(t, instance.Stop(ctx))
	require.NoError(t, instance.Close(ctx))
	require.Equal(t, 1, calls)
	require.Empty(t, instance.rawDetachers)
	select {
	case <-instance.done:
	default:
		t.Fatal("Stop did not signal readers")
	}
}

func TestStartWithoutOperatorStillValidatesBeforeAllocation(t *testing.T) {
	ctx := newResolverGadgetCtx(t, nil)
	defer ctx.Cancel()
	want := errors.New("native resource budget exceeded")
	validated := false
	ctx.SetVar(operators.NativeResourceValidatorKey, func(resources *operators.NativeResources) error {
		validated = true
		require.Equal(t, uint32(1<<25), resources.Maps["state"].MaxEntries)
		return want
	})
	instance := &ebpfInstance{
		logger:      ctx.Logger(),
		params:      map[string]*param{ParamTraceKernel: {Param: &api.Param{Key: ParamTraceKernel, TypeHint: api.TypeBool, DefaultValue: "false"}}},
		paramValues: api.ParamValues{},
		collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
			"state": {Name: "state", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1 << 25},
		}},
	}
	require.ErrorIs(t, instance.Start(ctx), want)
	require.True(t, validated)
	require.Nil(t, instance.collection, "validation must precede BPF allocation")
}
