#include <Windows.h>
#include <stdio.h>
#include "sanitizer\allocator_interface.h"

// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

int main() {
  void *newHeap = HeapCreate(0, 0, 0);
  char *newAlloc = (char *)HeapAlloc(newHeap, 0, 100);
  HeapDestroy(newHeap);
  newAlloc[0] = 0xff;
  return 1;
}

// CHECK: AddressSanitizer: heap-use-after-free on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
