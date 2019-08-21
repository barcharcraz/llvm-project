// RUN: %clang_cl_asan /Od -o %t %s
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 | FileCheck %s
// RUN: %env_asan_opts=windows_hook_rtl_allocators=false %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl /Od -o %t %s
// RUN: %run %t 2>&1 | FileCheck %s
// UNSUPPORTED: asan-64-bits
#include <cassert>
#include <stdio.h>
#include <windows.h>
#include <winbase.h>

int main() {
  void *ptr = GlobalAlloc(GMEM_FIXED, 4);
  assert(ptr);
  void *ptr2 = GlobalReAlloc(ptr, 0, GMEM_ZEROINIT);
  assert(ptr2);
  GlobalFree(ptr2);
  fprintf(stderr, "passed!\n");
}

// CHECK-NOT: double-free
// CHECK-NOT: AddressSanitizer
// CHECK: passed!