/* SPDX-License-Identifier: GPL-2.0 */
#ifndef GATEA_INGRESS_LSM_RESULT_H
#define GATEA_INGRESS_LSM_RESULT_H
/* The LSM's int result must reach BPF R0 as a signed 64-bit errno. Preserve
 * every valid prior denial, but never turn an invalid nonzero result into allow. */
static __inline __attribute__((always_inline)) long in_lsm_result(int prior)
{
	long result = prior;
#ifdef __BPF__
	/* Clang 21 can check the original w-register while returning a separately
  * sign-extended r-register; the verifier cannot transfer that lower bound.
  * Keep extension, both signed bounds and the returned value on ONE register.
  * These five instructions are opaque to C-level narrowing optimizations. */
	__asm__ __volatile__("%[value] <<= 32;\n"
			     "%[value] s>>= 32;\n"
			     "if %[value] s> 0 goto 1f;\n"
			     "if %[value] s>= -4095 goto 2f;\n"
			     "1: %[value] = -1;\n"
			     "2:\n"
			     : [value] "+r"(result));
#else
	if (result < -4095 || result > 0)
		result = -1;
#endif
	return result;
}
#endif
