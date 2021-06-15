#include <Windows.h>
#include <stdio.h>
#include "sanitizer\allocator_interface.h"

// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

int main() {
  void *newHeap = HeapCreate(0, 0, 0);
  void *newAlloc = HeapAlloc(newHeap, 0, 100);

  HeapFree(newHeap, 0, newAlloc);
  HeapFree(newHeap, 0, newAlloc);
  printf("failure\n");
  return 1;
}

// CHECK: AddressSanitizer: double-free
// CHECK-NOT: failure;
