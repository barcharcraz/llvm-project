// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %run %t again 2>&1 | FileCheck %s

#include "Windows.h"
#include "malloc.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  // Calling _setmaxstdio at all before system allocation tracking prior to ASAN initialization would cause an incorrect asan error to output.
  // Calling it multiple times identified an issue with /MDd tracking.
  // Calling it with a size that was not a power of 2 identified an issue with /MDd tracking.
  if (argc >= 2) {
    _setmaxstdio(64);
    _setmaxstdio(4);
    _setmaxstdio(2064);
  } else {
    _setmaxstdio(2048);
  }
  fputs("Success", stderr);
  // CHECK: Success
  return 0;
}