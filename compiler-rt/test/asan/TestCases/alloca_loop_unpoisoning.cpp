// RUN: %clangxx_asan -O0 -mllvm -asan-instrument-dynamic-allocas %s -o %t
// RUN: %run %t 2>&1
//
// REQUIRES: stable-runtime

// This testcase checks that allocas and VLAs inside loop are correctly unpoisoned.

#include "defines.h"
#include "sanitizer/asan_interface.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
// MSVC provides _alloca instead of alloca.
#if defined(_MSC_VER) && !defined(alloca)
#define alloca _alloca
#endif

#if defined(__sun__) && defined(__svr4__)
#include <alloca.h>
#endif

void *top, *bot;

ATTRIBUTE_NOINLINE void foo(int len) {
  char x;
  top = &x;

  ATTRIBUTE_ALIGNED(32)
#ifdef MSVC
  char *array = (char *)alloca(len);
#else
  char array[len];
#endif
  assert(!(reinterpret_cast<uintptr_t>(array) & 31L));
  alloca(len);
  for (int i = 0; i < 32; ++i) {
    ATTRIBUTE_ALIGNED(32)
#ifdef MSVC
    char *array = (char *)alloca(i);
#else
    char array[i];
#endif
    bot = alloca(i);
    assert(!(reinterpret_cast<uintptr_t>(bot) & 31L));
  }
}

int main(int argc, char **argv) {
  foo(32);
  void *q = __asan_region_is_poisoned(bot, (char *)top - (char *)bot);
  assert(!q);
  return 0;
}
