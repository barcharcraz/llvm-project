// UNSUPPORTED: MSVC
// Tracked by vso1226261, ( GeneralTestSuite_amd64chk_MD.txt )
// RUN: %clangxx_asan -O0 -mllvm -asan-instrument-dynamic-allocas %s -o %t
// RUN: %clangxx_asan -O3 -mllvm -asan-instrument-dynamic-allocas %s -o %t
// RUN: %run %t 2>&1
//
// UNSUPPORTED: MSVC

#include "defines.h"
#include "sanitizer/asan_interface.h"
#include <assert.h>
ATTRIBUTE_NOINLINE void foo(int index, int len) {
#if defined(_MSC_VER) && !defined(__clang__)
  volatile char ATTRIBUTE_ALIGNED(32) *str = (volatile char *)_alloca(len);
#else
  volatile char str[len] __attribute__((aligned(32)));
#endif
assert(!(reinterpret_cast<long>(str) & 31L));
  char *q = (char *)__asan_region_is_poisoned((char *)str, 64);
  assert(q && ((q - str) == index));
}

int main(int argc, char **argv) {
  for (int i = 1; i < 33; ++i)
    foo(i, i);

  for (int i = 1; i < 33; ++i)
    foo(i, i);

  return 0;
}
