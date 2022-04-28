// RUN: %clang_asan /Od -o %t %s
// RUN: %run %t
// UNSUPPORTED: clang-dynamic-runtime

#include "malloc.h"
#include <iostream>
#include <stdio.h>

// No valid memory operations should report invalid behavior
// on memory that is allocated prior to asan init

int *allocatedPriorToAsan;
#pragma section(".CRT$XIB", long, read)

int TestAllocPriorToAsan() {
  allocatedPriorToAsan = (int *)malloc(sizeof(int));
  *allocatedPriorToAsan = 64;
  return 0;
}

__declspec(allocate(".CRT$XIB")) int (*testAllocPriorToAsan)() =
    TestAllocPriorToAsan;

int main() {
  // number here doesn’t matter, should not produce invalid asan free
  // due to piob being reallocated
  _setmaxstdio(*allocatedPriorToAsan);

  //_msize, realloc, cmp, free to test memory usage 
  auto resultingSize = static_cast<int>(_msize(allocatedPriorToAsan));
  allocatedPriorToAsan = (int *)realloc(0, 32);
  allocatedPriorToAsan[0] = resultingSize;

  int compareTo[] = {resultingSize};
  int result = memcmp(allocatedPriorToAsan, compareTo, 1);

  free(allocatedPriorToAsan);
  return 0;
}