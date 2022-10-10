/* Tries to open the same file twice,
   which must succeed and must return a different file descriptor
   in each case. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "tests/userprog/sample.inc"

void test_main(void) {
  int h1 = open("sample.txt");
  int h2 = open("sample.txt");

  CHECK((h1 = open("sample.txt")) > 1, "open \"sample.txt\" once");
  CHECK((h2 = open("sample.txt")) > 1, "open \"sample.txt\" again");
  
  close(h2);

  check_file_handle(h1, "sample.txt", sample, sizeof sample - 1);
}
