#include <Windows.h>
#include <stdio.h>
#include "sanitizer\allocator_interface.h"

// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s

int main() {
  void *newHeap = HeapCreate(0, 1000, 5000);           // make a new heap with accepted flags for the asan interceptors
  char *newAlloc = (char *)HeapAlloc(newHeap, 0, 100); // Allocate, this should belong to the sanitizer runtime
  // check that we've created a new heap and that the allocation belongs where we think it should
  if (newHeap != GetProcessHeap() && __sanitizer_get_ownership(newAlloc)) {
    //touch the allocations and make sure nothing unexpected happens.
    newAlloc[0] = 0xff;
    newAlloc[99] = 0xff;
    printf("success\n");
    return 0;
  }
  printf("fail\n");
  return 1;
}

// CHECK: success
// CHECK-NOT: fail
// CHECK-NOT: AddressSanitizer
