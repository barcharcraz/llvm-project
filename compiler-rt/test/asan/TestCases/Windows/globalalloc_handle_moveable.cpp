// RUN: %clang_cl_asan /Od -o %t %s -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od -o %t %s -DTEST_LOCAL
// RUN: not %run %t 2>&1 | FileCheck %s

#include "../defines.h"
#include "globallocal_shared.h"
#include "test_helpers.h"
#include <stdio.h>
#include <winbase.h>
#include <windows.h>

int main() {
  fprintf(stderr, "Test type: %s\n", TEST_TYPE);
  // CHECK: Test type: [[TYPE:(Global|Local)]]

  void *handle = ALLOC(MOVEABLE, 4);
  print_addr("handle", handle);
  // CHECK: handle: [[HANDLE:0x[0-9a-f]+]]

  void *ptr = LOCK(handle);
  CHECK(ptr != handle);
  print_addr("ptr", ptr);
  // CHECK: ptr: [[PTR:0x[0-9a-f]+]]

  CHECK(HANDLE_FUNC(ptr) == handle);
  FREE(ptr);

  // CHECK: heap-use-after-free on address [[PTR]]
  // CHECK: freed by thread T0 here
  // CHECK: [[TYPE]]Free
  // CHECK: previously allocated by thread T0 here
  // CHECK: [[TYPE]]Alloc
  CHECK(HANDLE_FUNC(ptr) == nullptr);
  CHECK(GetLastError() == ERROR_INVALID_HANDLE);
}
