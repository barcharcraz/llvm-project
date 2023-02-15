// RUN: %clang_cl_asan /Od -o %t %s -DTEST_GLOBAL
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od -o %t %s -DTEST_LOCAL
// RUN: %run %t 2>&1 | FileCheck %s

#include "../defines.h"
#include "globallocal_shared.h"
#include "test_helpers.h"
#include <stdio.h>
#include <winbase.h>
#include <windows.h>
#include <stdint.h>

int main() {
  fprintf(stderr, "Test type: %s\n", TEST_TYPE);
  // CHECK: Test type: [[TYPE:(Global|Local)]]

  void *handle = ALLOC(MOVEABLE, 4);
  CHECK(SIZE(handle) == 4);

  void *ptr = LOCK(handle);
  CHECK(ptr != handle);

  print_addr("ptr", ptr);
  // CHECK: ptr: [[PTR:0x[0-9a-f]+]]

  FREE(handle);

  // CHECK: attempting to call malloc_usable_size() for pointer which is not owned: [[PTR]]
  // CHECK: freed by thread T0 here
  // CHECK: __asan_wrap_[[TYPE]]Free
  // CHECK: previously allocated by thread T0 here
  // CHECK: __asan_wrap_[[TYPE]]Alloc
  CHECK(SIZE(handle) == 0);
  return 0;
}
