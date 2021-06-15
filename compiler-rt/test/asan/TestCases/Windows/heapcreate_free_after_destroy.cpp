#include <Windows.h>
#include <stdio.h>
#include "sanitizer\allocator_interface.h"

// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

int main() {
  void *newHeap = HeapCreate(0, 0, 0);
  void *newAlloc = HeapAlloc(newHeap, 0, 100);
  HeapDestroy(newHeap);

  HeapFree(newHeap, 0, newAlloc);
  printf("failure\n");
  return 1;
}

// We need to add an address sanitizer error for using a heap after it has
// been destroyed. For now we get an access-violation error.
// CHECK: AddressSanitizer:
// CHECK-NOT: failure;
