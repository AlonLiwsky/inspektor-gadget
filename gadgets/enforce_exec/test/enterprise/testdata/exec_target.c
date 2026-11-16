// SPDX-License-Identifier: Apache-2.0
// Owned, single-threaded synthetic exec. No subprocess tree or payload reporting.
#include <unistd.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--after-exec") == 0) {
		// Keep the PID alive until the parent finishes observation and releases it.
		if (write(4, "R", 1) != 1)
			return 5;
		char done;
		return read(3, &done, 1) == 1 && done == 'X' ? 0 : 3;
	}
	uint32_t identity[2] = { (uint32_t)getpid(), (uint32_t)getppid() };
	if (write(4, identity, sizeof(identity)) != sizeof(identity))
		return 6;
	char token;
	if (argc != 1 || read(3, &token, 1) != 1 || token != 'G')
		return 2;
	char *args[] = { argv[0], "--after-exec", 0 };
	char *env[] = { 0 };
	execve(argv[0], args, env);
	return 4;
}
