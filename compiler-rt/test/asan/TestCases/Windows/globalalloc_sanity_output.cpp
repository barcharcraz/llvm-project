// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s

#include <windows.h>
#include "globallocal_shared.h"

int main() {
  char *buffer;
  buffer = (char*)ALLOC(FixedType, 32),
  buffer[33] = 'a';
// CHECK: AddressSanitizer: heap-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
}
