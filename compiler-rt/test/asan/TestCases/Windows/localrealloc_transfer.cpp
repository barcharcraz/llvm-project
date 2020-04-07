#include "sanitizer\allocator_interface.h"
#include <cassert>
#include <stdio.h>
#include <windows.h>
#include "../defines.h"

// RUN: %clang_cl_asan %s -o%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 | FileCheck %s
// UNSUPPORTED: asan-64-bits

int main() {
  void *buffer, *realloc;
  HLOCAL hMem1, hMem2, hMem3;
  
  //owned by rtl
  hMem1 = LocalAlloc(LMEM_MOVEABLE, 100);
  buffer = (void *) LocalLock(hMem1);
  assert(buffer);

  // still owned by rtl
  hMem2 = LocalReAlloc(buffer, 100, LMEM_MOVEABLE);
  LocalUnlock(hMem1);
  buffer = (void *) LocalLock(hMem2);
  assert(buffer);
  assert(!__sanitizer_get_ownership(buffer));
  assert(HeapValidate(GetProcessHeap(), 0, buffer));
  
  //convert to asan owned
  realloc = LocalReAlloc(buffer, 500, LMEM_FIXED);
  LocalUnlock(hMem2);
  buffer = nullptr;
  assert(realloc);
  assert(__sanitizer_get_ownership(realloc));
  
  //convert back to rtl owned;
  hMem3 = LocalReAlloc(realloc, 100, LMEM_MOVEABLE);
  buffer = (void*) LocalLock(hMem3);
  assert(buffer);
  assert(!__sanitizer_get_ownership(buffer));
  assert(HeapValidate(GetProcessHeap(), 0, buffer));
  
  LocalUnlock(hMem3);
  printf("Success\n");
}

// CHECK-NOT: assert
// CHECK-NOT: AddressSanitizer
// CHECK: Success

