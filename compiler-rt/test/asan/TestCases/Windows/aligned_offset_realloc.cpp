// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t
#include <malloc.h>
#include <stdlib.h>

#define CHECK_ALIGNED(ptr, alignment)                                          \
  do {                                                                         \
    if (((uintptr_t)(ptr) % (alignment)) != 0)                                 \
      return __LINE__;                                                         \
  } while (0)

#define CHECK_ZERO(ptr, sz)                                                    \
  do {                                                                         \
    for (size_t i = 0; i < sz; ++i)                                            \
      if (ptr[i] != 0)                                                         \
        return __LINE__;                                                       \
  } while (0)

int main() {
  size_t alignments[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};
  size_t offsets[] = {3, 4, 5, 19, 25, 40, 41, 7, 12, 23};
  char *buf = (char *)_aligned_malloc(10, 1);
  char *buf_z = (char *)_aligned_recalloc(nullptr, 10, 1, 1);
  CHECK_ALIGNED(buf, 1);
  CHECK_ALIGNED(buf_z, 1);
  CHECK_ZERO(buf_z, 10);
  for (size_t i = 0; i < sizeof(alignments) / sizeof(size_t); ++i) {
    buf = (char *)_aligned_offset_realloc(buf, 1024, alignments[i], offsets[i]);
    buf_z =
        (char *)_aligned_offset_recalloc(buf_z, 1024, 1, alignments[i], offsets[i]);
    uintptr_t address = (uintptr_t)(buf + offsets[i]);
    uintptr_t address_z = (uintptr_t)(buf_z + offsets[i]);
    CHECK_ALIGNED(address, alignments[i]);
    CHECK_ALIGNED(address_z, alignments[i]);
    CHECK_ZERO(buf_z, 1024);
  }
  return 0;
}