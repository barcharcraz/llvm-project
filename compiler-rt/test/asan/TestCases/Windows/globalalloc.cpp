// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL
// RUN: not %run %t 2>&1 | FileCheck %s

#include "globallocal_shared.h"
#include "test_helpers.h"
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

int main() {
  fprintf(stderr, "Test type: %s\n", TEST_TYPE);
// CHECK: Test type: [[TYPE:(Global|Local)]]

  char *buffer;
  buffer = (char*)ALLOC(GMEM_FIXED, 32),

  print_addr("target-ptr", reinterpret_cast<void *>(reinterpret_cast<uint64_t>(buffer) + 33));
// CHECK: target-ptr: [[ADDR:0x[0-9a-f]+]]

  buffer[33] = 'a';
// CHECK: AddressSanitizer: heap-buffer-overflow on address [[ADDR]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
// CHECK: allocated by thread T0 here:
// CHECK: __asan_wrap_[[TYPE]]Alloc
}
