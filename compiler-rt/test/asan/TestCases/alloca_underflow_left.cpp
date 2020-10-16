// UNSUPPORTED: msvc-host
// Tracked by vso1226261, ( GeneralTestSuite_amd64chk_MD.txt GeneralTestSuite_amd64chk_MT.txt )
// RUN: %clangxx_asan -O0 -mllvm -asan-instrument-dynamic-allocas %s -o %t
// RUN: not %run %t 2>&1 | FileCheck %s
//

#include "defines.h"
#include <assert.h>
ATTRIBUTE_NOINLINE void foo(int index, int len) {
ATTRIBUTE_ALIGNED(32)
#ifdef MSVC
  volatile char *str = (volatile char *)_alloca(len);
#else
  volatile char str[len];
#endif
assert(!(reinterpret_cast<long>(str) & 31L));
  str[index] = '1'; // BOOM
// CHECK: ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
// CHECK: WRITE of size 1 at [[ADDR]] thread T0
}

int main(int argc, char **argv) {
  foo(-1, 10);
  return 0;
}
