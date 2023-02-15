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

  void *handle1 = ALLOC(MOVEABLE, 4);
  void *ptr1 = LOCK(handle1);
  print_addr("ptr1", ptr1);
  // CHECK: ptr1: [[ptr1:0x[0-9a-fA-F]+]]
  CHECK(ptr1);

  void *handle2 = REALLOC(handle1, 4, ZEROINIT);
  CHECK(handle1 == handle2);
  void *ptr2 = LOCK(handle2);
  print_addr("ptr2", ptr2);
  // CHECK: ptr2: [[ptr2:0x[0-9a-fA-F]+]]
  CHECK(ptr2 != ptr1);

  void *handle3 = REALLOC(handle1, 0, ZEROINIT); // Same as free
  CHECK(handle3 == nullptr);

  FREE(handle1);
  // CHECK: AddressSanitizer: attempting double-free on [[ptr2]] in thread T0:
  // CHECK: freed by thread T0 here
  // CHECK: __asan_wrap_[[TYPE]]ReAlloc
  // CHECK: previously allocated by thread T0 here
  // CHECK: __asan_wrap_[[TYPE]]ReAlloc
}

