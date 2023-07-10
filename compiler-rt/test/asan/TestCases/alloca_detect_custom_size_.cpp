// UNSUPPORTED: msvc-host
// Tracked by vso1226261, ( GeneralTestSuite_amd64chk_MD.txt GeneralTestSuite_amd64chk_MT.txt )
// RUN: %clangxx_asan -O0 -mllvm -asan-instrument-dynamic-allocas %s -o %t
// RUN: not %run %t 2>&1 | FileCheck %s
//

#include "defines.h"
#include <assert.h>
#include <stdint.h>

struct A {
  char a[3];
  int b[3];
};

ATTRIBUTE_NOINLINE void foo(int index, int len) {
  ATTRIBUTE_ALIGNED(32)
#ifdef MSVC
  volatile struct A *str = (volatile struct A *)_alloca(len * sizeof(struct A));
#else
  volatile struct A str[len] __attribute__((aligned(32)));
#endif
  assert(!(reinterpret_cast<uintptr_t>(str) & 31L));
  str[index].a[0] = '1'; // BOOM
  // CHECK: ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
  // CHECK: WRITE of size 1 at [[ADDR]] thread T0
}

int main(int argc, char **argv) {
  foo(10, 10);
  return 0;
}
