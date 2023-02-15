// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s


#include "globallocal_shared.h"
#include "test_helpers.h"
#include <windows.h>

int main() {
  char *buffer;
  buffer = (char*)ALLOC(FixedType, 32),
  print_addr("buffer", buffer);
// CHECK: buffer: [[ADDR:0x[0-9a-f]+]]
  FREE(buffer);
  buffer[0] = 'a';
// CHECK: AddressSanitizer: heap-use-after-free on address [[ADDR]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
}
