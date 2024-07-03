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
  size_t offset = 25;

  int i = atoi(argv[1]);
  char *buff = (char *)_aligned_offset_malloc(1024, alignments[i], 25);
  buff[1023] = 42;
  buff[1024] = 42;
  // CHECK: AddressSanitizer: heap-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
  // CHECK: WRITE of size 1 at [[ADDR]] thread T0
  // CHECK:   {{#0 .* main .*aligned_offset_malloc_right_oob.cpp}}:[[@LINE-3]]
  // CHECK: [[ADDR]] is located 7 bytes after 1024-byte region
  // CHECK: allocated by thread T0 here:
  // CHECK:   {{#0 .* _aligned_offset_malloc}}
  // CHECK:   {{#[1-2] .* main .*aligned_offset_malloc_right_oob.cpp}}:[[@LINE-9]]
  return 0;
}