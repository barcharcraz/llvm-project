// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t
// TODO: this should really be a unit test

#include <malloc.h>
#include <stdlib.h>

#define CHECK_ALIGNED(ptr, alignment)                                          \
  do {                                                                         \
    if (((uintptr_t)(ptr) % (alignment)) != 0)                                 \
      return __LINE__;                                                         \
  } while (0)

int main() {
  size_t alignments[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};
  size_t offsets[] = {3, 4, 5, 19, 25, 40, 41, 7, 12, 23};
  for (size_t i = 0; i < sizeof(alignments) / sizeof(size_t); ++i) {
    size_t off = offsets[i];
    char *buff = (char *)_aligned_offset_malloc(1024, alignments[i], offsets[i]);
    uintptr_t address = (uintptr_t)(buff + off);
    CHECK_ALIGNED(address, alignments[i]);
    _aligned_free(buff);
  }

  return 0;
}