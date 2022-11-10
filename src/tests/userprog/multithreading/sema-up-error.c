/* Ensure sema up on an uninitialized sema fails */

#include "tests/lib.h"
#include "tests/main.h"
#include <syscall.h>

void test_main(void) {
  sema_t sema;
  sema_up(&sema);
  fail("Uninitialized up succeeded");
}
