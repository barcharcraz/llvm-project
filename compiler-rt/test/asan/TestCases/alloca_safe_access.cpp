// RUN: %clangxx_asan -O0 -mllvm -asan-instrument-dynamic-allocas %s -o %t
// RUN: %run %t 2>&1
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
  str[index] = '1';
}

int main(int argc, char **argv) {
  foo(4, 5);
  foo(39, 40);
  return 0;
}
