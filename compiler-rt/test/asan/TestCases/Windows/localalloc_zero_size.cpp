// RUN: %clang_cl_asan /Od -o %t %s
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 | FileCheck %s
// RUN: %env_asan_opts=windows_hook_rtl_allocators=false %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl /Od -o %t %s
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 | FileCheck %s
// UNSUPPORTED: asan-64-bits
#include <cassert>
#include <stdio.h>
#include <windows.h>
#include <winbase.h>

int main() {
  void *ptr = LocalAlloc(LMEM_FIXED, 4);
  assert(ptr);
  void *ptr2 = LocalReAlloc(ptr, 0, LMEM_ZEROINIT);
  assert(ptr2);
  LocalFree(ptr2);
  fprintf(stderr, "passed!\n");

}

// CHECK-NOT: double-free
// CHECK-NOT: AddressSanitizer
// CHECK: passed!