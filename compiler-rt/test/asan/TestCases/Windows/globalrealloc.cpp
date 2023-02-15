// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: not %run %t 2>&1 | FileCheck %s

// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: not %run %t 2>&1 | FileCheck %s

#include <stdio.h>
#include <windows.h>
#include <winbase.h>
#include "globallocal_shared.h"

int main() {
  char *oldbuf;
  size_t sz = 8;
  oldbuf = (char *)ALLOC(FixedType, sz);
  char *newbuf = oldbuf;
  while (oldbuf == newbuf) {
    sz *= 2;
    newbuf = (char *)REALLOC(oldbuf, sz, ZEROINIT);
  }

  newbuf[0] = 'a';
  oldbuf[0] = 'a';
  // CHECK: AddressSanitizer: heap-use-after-free on address [[ADDR:0x[0-9a-f]+]]
  // CHECK: WRITE of size 1 at [[WRITE2:0x[0-9a-f]+]] thread T0
  // CHECK: #0 {{0x[0-9a-f]+ in main.*}}:[[@LINE-3]]
}
