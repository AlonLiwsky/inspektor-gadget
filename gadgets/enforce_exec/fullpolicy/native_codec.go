// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "encoding/binary"

// These concrete codecs preserve every byte of the existing fixed ABI, including
// invalid padding for subsequent validation. They do not validate record content.
// Generic Decode/encode remain independent compatibility APIs and test oracles.
func encodeKernelHeader(v KernelHeader) (b Blob) {
	binary.LittleEndian.PutUint64(b[0:8], v.Generation)
	binary.LittleEndian.PutUint32(b[8:12], v.PolicyCount)
	binary.LittleEndian.PutUint32(b[12:16], v.RuleBase)
	binary.LittleEndian.PutUint32(b[16:20], v.RuleCount)
	binary.LittleEndian.PutUint32(b[20:24], v.ContainerRef)
	copy(b[24:], v.Padding[:])
	return
}

func decodeKernelHeader(b Blob) (v KernelHeader) {
	v.Generation = binary.LittleEndian.Uint64(b[0:8])
	v.PolicyCount = binary.LittleEndian.Uint32(b[8:12])
	v.RuleBase = binary.LittleEndian.Uint32(b[12:16])
	v.RuleCount = binary.LittleEndian.Uint32(b[16:20])
	v.ContainerRef = binary.LittleEndian.Uint32(b[20:24])
	copy(v.Padding[:], b[24:])
	return
}

func encodeKernelPolicy(v KernelPolicy) (b Blob) {
	binary.LittleEndian.PutUint64(b[0:8], v.UID)
	binary.LittleEndian.PutUint64(b[8:16], v.RootRole)
	binary.LittleEndian.PutUint32(b[16:20], v.Default)
	binary.LittleEndian.PutUint32(b[20:24], v.Mode)
	binary.LittleEndian.PutUint64(b[24:32], v.RootEpoch)
	copy(b[32:], v.Padding[:])
	return
}

func decodeKernelPolicy(b Blob) (v KernelPolicy) {
	v.UID = binary.LittleEndian.Uint64(b[0:8])
	v.RootRole = binary.LittleEndian.Uint64(b[8:16])
	v.Default = binary.LittleEndian.Uint32(b[16:20])
	v.Mode = binary.LittleEndian.Uint32(b[20:24])
	v.RootEpoch = binary.LittleEndian.Uint64(b[24:32])
	copy(v.Padding[:], b[32:])
	return
}

// The callers pass the exact eight-byte field slices at their explicit offsets.
func putKernelList(b []byte, v KernelList) {
	binary.LittleEndian.PutUint32(b[0:4], v.Base)
	binary.LittleEndian.PutUint32(b[4:8], v.Count)
}

func readKernelList(b []byte) KernelList {
	return KernelList{Base: binary.LittleEndian.Uint32(b[0:4]), Count: binary.LittleEndian.Uint32(b[4:8])}
}

func encodeKernelRule(v KernelRule) (b Blob) {
	binary.LittleEndian.PutUint32(b[0:4], v.PolicyIndex)
	binary.LittleEndian.PutUint32(b[4:8], v.Mode)
	binary.LittleEndian.PutUint32(b[8:12], v.Deny)
	binary.LittleEndian.PutUint32(b[12:16], uint32(v.ActorImage))
	binary.LittleEndian.PutUint32(b[16:20], uint32(v.TargetImage))
	binary.LittleEndian.PutUint32(b[20:24], uint32(v.Stdin))
	binary.LittleEndian.PutUint32(b[24:28], v.AncestorDepth)
	binary.LittleEndian.PutUint32(b[28:32], v.Reserved)
	binary.LittleEndian.PutUint64(b[32:40], v.SetRole)
	putKernelList(b[40:48], v.ActorPath)
	putKernelList(b[48:56], v.TargetPath)
	putKernelList(b[56:64], v.AncestorPath)
	putKernelList(b[64:72], v.ActorRole)
	putKernelList(b[72:80], v.UID)
	putKernelList(b[80:88], v.Container)
	putKernelList(b[88:96], v.FSType)
	putKernelList(b[96:104], v.ArgContains)
	putKernelList(b[104:112], v.ArgPrefix)
	copy(b[112:], v.Padding[:])
	return
}

func decodeKernelRule(b Blob) (v KernelRule) {
	v.PolicyIndex = binary.LittleEndian.Uint32(b[0:4])
	v.Mode = binary.LittleEndian.Uint32(b[4:8])
	v.Deny = binary.LittleEndian.Uint32(b[8:12])
	v.ActorImage = int32(binary.LittleEndian.Uint32(b[12:16]))
	v.TargetImage = int32(binary.LittleEndian.Uint32(b[16:20]))
	v.Stdin = int32(binary.LittleEndian.Uint32(b[20:24]))
	v.AncestorDepth = binary.LittleEndian.Uint32(b[24:28])
	v.Reserved = binary.LittleEndian.Uint32(b[28:32])
	v.SetRole = binary.LittleEndian.Uint64(b[32:40])
	v.ActorPath = readKernelList(b[40:48])
	v.TargetPath = readKernelList(b[48:56])
	v.AncestorPath = readKernelList(b[56:64])
	v.ActorRole = readKernelList(b[64:72])
	v.UID = readKernelList(b[72:80])
	v.Container = readKernelList(b[80:88])
	v.FSType = readKernelList(b[88:96])
	v.ArgContains = readKernelList(b[96:104])
	v.ArgPrefix = readKernelList(b[104:112])
	copy(v.Padding[:], b[112:])
	return
}

func encodeKernelString(v KernelString) (b Blob) {
	binary.LittleEndian.PutUint32(b[0:4], v.Length)
	copy(b[4:260], v.Bytes[:])
	copy(b[260:], v.Padding[:])
	return
}

func decodeKernelString(b Blob) (v KernelString) {
	v.Length = binary.LittleEndian.Uint32(b[0:4])
	copy(v.Bytes[:], b[4:260])
	copy(v.Padding[:], b[260:])
	return
}

func encodeKernelValue(v KernelValue) (b Blob) {
	binary.LittleEndian.PutUint64(b[0:8], v.Value)
	copy(b[8:], v.Padding[:])
	return
}

func decodeKernelValue(b Blob) (v KernelValue) {
	v.Value = binary.LittleEndian.Uint64(b[0:8])
	copy(v.Padding[:], b[8:])
	return
}

func encodeKernelPattern(v KernelPattern) (b Blob) {
	binary.LittleEndian.PutUint32(b[0:4], v.CodeBase)
	binary.LittleEndian.PutUint32(b[4:8], v.Start)
	binary.LittleEndian.PutUint32(b[8:12], v.Count)
	copy(b[12:], v.Padding[:])
	return
}

func decodeKernelPattern(b Blob) (v KernelPattern) {
	v.CodeBase = binary.LittleEndian.Uint32(b[0:4])
	v.Start = binary.LittleEndian.Uint32(b[4:8])
	v.Count = binary.LittleEndian.Uint32(b[8:12])
	copy(v.Padding[:], b[12:])
	return
}

func encodeKernelInstruction(v KernelInstruction) (b Blob) {
	binary.LittleEndian.PutUint32(b[0:4], v.Op)
	binary.LittleEndian.PutUint32(b[4:8], v.Out)
	binary.LittleEndian.PutUint32(b[8:12], v.Arg)
	binary.LittleEndian.PutUint32(b[12:16], v.Count)
	for i, value := range v.Ranges {
		binary.LittleEndian.PutUint32(b[16+4*i:20+4*i], value)
	}
	copy(b[80:], v.Padding[:])
	return
}

func decodeKernelInstruction(b Blob) (v KernelInstruction) {
	v.Op = binary.LittleEndian.Uint32(b[0:4])
	v.Out = binary.LittleEndian.Uint32(b[4:8])
	v.Arg = binary.LittleEndian.Uint32(b[8:12])
	v.Count = binary.LittleEndian.Uint32(b[12:16])
	for i := range v.Ranges {
		v.Ranges[i] = binary.LittleEndian.Uint32(b[16+4*i : 20+4*i])
	}
	copy(v.Padding[:], b[80:])
	return
}
