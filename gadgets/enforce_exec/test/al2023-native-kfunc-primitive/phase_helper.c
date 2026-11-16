/* SPDX-License-Identifier: GPL-2.0 */
/* Controlled shebang interpreter: no subprocesses, no policy behavior. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
	const char *script = getenv("IG_EXPECT_SCRIPT");
	const char *nonce = getenv("IG_EXPECT_NONCE");
	if (argc != 4 || !script || !nonce ||
	    strcmp(argv[1], "--ig-argv-phase") || strcmp(argv[2], script) ||
	    strcmp(argv[3], nonce))
		return 77;
	return puts("IG_PHASE_HELPER_OK") < 0 ? 78 : 0;
}
