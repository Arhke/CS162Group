/* Wait for a grandchild process to finish.
   The wait call must return -1 immediately.
 */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  msg("wait(exec()) = %d", wait(exec("child-more")));
}
