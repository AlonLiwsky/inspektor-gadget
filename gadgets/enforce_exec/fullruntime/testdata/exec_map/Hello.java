// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// A JIT workload for TestSharedNodeExecMapAttached (HotSpot).
public class Hello {
	public static void main(String[] a) {
		long s = 0;
		for (int i = 0; i < 200000000; i++) {
			s += i % 7;
		}
		System.out.println("java-ok " + s);
	}
}
