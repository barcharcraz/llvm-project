// RUN: %clang_cl_asan /Od -o %t %s -DTEST_GLOBAL
// RUN: %env_asan_opts=windows_hook_legacy_allocators=true %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od -o %t %s -DTEST_LOCAL
// RUN: %env_asan_opts=windows_hook_legacy_allocators=true %run %t 2>&1 | FileCheck %s

#include "../defines.h"
#include "globallocal_shared.h"
#include <cassert>
#include <stdio.h>
#include <winbase.h>
#include <windows.h>

int main() {
  void *ptr = ALLOC(FixedType, 4);
  assert(ptr);
  void *ptr2 = REALLOC(ptr, 0, ZEROINIT);
  assert(ptr2);
  GlobalFree(ptr2);

  ptr = ALLOC(MOVEABLE, 4);
  assert(ptr);
  ptr2 = REALLOC(ptr, 0, ZEROINIT);
  assert(!ptr2);

  fprintf(stderr, "passed!\n");
}

// CHECK-NOT: double-free
// CHECK-NOT: AddressSanitizer
// CHECK: passed!
