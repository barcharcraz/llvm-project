#include "sanitizer\allocator_interface.h"
#include <cassert>
#include <stdio.h>
#include <windows.h>
#include "../defines.h"

// RUN: %clang_cl_asan %s -o%t
// RUN: %run %t 2>&1 | FileCheck %s

int main() {
  //owned by rtl
  void *alloc = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, 100);
  assert(alloc);
  // still owned by rtl
  alloc = HeapReAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, alloc, 100);
  assert(alloc && !__sanitizer_get_ownership(alloc) && HeapValidate(GetProcessHeap(), 0, alloc));
  //convert to asan owned
  void *realloc = HeapReAlloc(GetProcessHeap(), 0, alloc, 500);
  alloc = nullptr;
  assert(realloc && __sanitizer_get_ownership(realloc));
  //convert back to rtl owned;
  alloc = HeapReAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, realloc, 100);
  assert(alloc && !__sanitizer_get_ownership(alloc) && HeapValidate(GetProcessHeap(), 0, alloc));
  printf("Success\n");
}

// CHECK-NOT: assert
// CHECK-NOT: AddressSanitizer
// CHECK: Success