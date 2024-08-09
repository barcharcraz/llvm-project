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

  auto buffer = LOCK(ALLOC(MOVEABLE | NO_DISCARD, 0));

  print_addr("target-ptr",
             reinterpret_cast<void *>(reinterpret_cast<uint64_t>(buffer) + 1));
  // CHECK: target-ptr: [[ADDR:0x[0-9a-f]+]]

  SIZE(buffer);
  // CHECK-NOT: ERROR: AddressSanitizer: attempting to call malloc_usable_size() for pointer which is not owned

  static_cast<char *>(buffer)[1] = 'a';
  // CHECK: AddressSanitizer: heap-buffer-overflow on address [[ADDR]]
  // CHECK: WRITE of size 1 at [[ADDR]] thread T0
  // CHECK: allocated by thread T0 here:
  // CHECK: [[TYPE]]Alloc
}
