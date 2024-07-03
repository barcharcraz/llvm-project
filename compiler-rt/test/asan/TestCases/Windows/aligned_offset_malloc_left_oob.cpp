// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 0 2>&1 | FileCheck %s
// RUN: not %run %t 1 2>&1 | FileCheck %s
// RUN: not %run %t 2 2>&1 | FileCheck %s
// RUN: not %run %t 3 2>&1 | FileCheck %s
// RUN: not %run %t 4 2>&1 | FileCheck %s
// RUN: not %run %t 5 2>&1 | FileCheck %s
// RUN: not %run %t 6 2>&1 | FileCheck %s
// RUN: not %run %t 7 2>&1 | FileCheck %s
// RUN: not %run %t 8 2>&1 | FileCheck %s
// RUN: not %run %t 9 2>&1 | FileCheck %s

#include <malloc.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  size_t alignments[] = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512};
  size_t offsets[] = {3, 4, 5, 19, 25, 40, 41, 7, 12, 23};

  int i = atoi(argv[1]);
  size_t off = offsets[i];
  char *buff = (char *)_aligned_offset_malloc(1024, alignments[i], off);
  char *test_buf = buff;
  for (; ((uintptr_t)test_buf & 7) != 0; --test_buf) {
    // note, because using an offset means the allocation's beginning isn't
    // always aligned on 8 we can't keep track of the validity of the bytes
    // in the "gap" between the start of the "real" allocation and the preceding
    // 8 byte boundary, at least not in the redzone.
    *test_buf = 42;
  }
  test_buf[-1] = 42;
  // CHECK: AddressSanitizer: heap-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
  // CHECK: WRITE of size 1 at [[ADDR]] thread T0
  // CHECK:   {{#0 .* main .*aligned_offset_malloc_left_oob.cpp}}:[[@LINE-3]]
  // CHECK: [[ADDR]] is located 1 bytes before 1024-byte region
  // CHECK: allocated by thread T0 here:
  // CHECK:   {{#0 .* _aligned_offset_malloc}}
  // CHECK:   {{#[1-2] .* main .*aligned_offset_malloc_left_oob.cpp}}:[[@LINE-16]]
  return 0;
}