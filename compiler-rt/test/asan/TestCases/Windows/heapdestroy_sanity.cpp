// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan -Od %s -Fe%t_dbg /link /INFERASANLIBS:DEBUG
// RUN: %run %t_dbg 2>&1 | FileCheck %s

#include <Windows.h>
#include <stdio.h>
#include "sanitizer\allocator_interface.h"

int main() {
  void *newHeap = HeapCreate(0, 0, 0);
  void *newAlloc = HeapAlloc(newHeap, 0, 100);
  HeapDestroy(newHeap);
  printf("success\n");
  return 0;
}

// CHECK-NOT: AddressSanitizer
// CHECK: success
