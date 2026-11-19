#include <assert.h>
#include "nesting.h"
int main(void)
{
	for (int prior = -4095; prior <= 0; prior++)
		for (int fault = 0; fault < 2; fault++) {
			assert(nest_result(prior, 0, fault) == prior);
			assert(nest_result(prior, 1, fault) ==
			       (prior ? prior : (fault ? -13 : 0)));
		}
	return 0;
}
