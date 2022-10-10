/* Opens the same file twice, then closes the second file descriptor.
   Then, checks that the first file descriptor is still valid. */

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
