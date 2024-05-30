// Without ASan's new/delete overrides, alloc/dealloc mismatch errors are not detected.

// RUN: %clang_cl_asan -Od %s -Fe%t /link /INFERASANLIBS:NO %nonewdelete_libasan /WHOLEARCHIVE:%asan_thunk
// RUN: %env_asan_opts=alloc_dealloc_mismatch=true %run %t 2 2>&1 | FileCheck %s

#include <stdio.h>
#include <stdlib.h>

// Taken from: https://docs.microsoft.com/en-us/cpp/sanitizers/error-alloc-dealloc-mismatch
int main(int argc,char *argv[] ) {

  if (argc != 2) return -1;

  switch (atoi(argv[1])) {
  case 1:
    delete [] (new int[10]);
    break;
  case 2:
    delete (new int[10]);      // Boom! alloc-dealloc-mismatch (legitimate error but should be missed without new/delete overrides)
    break;
  default:
    printf("arguments: 1: no error 2: runtime error\n");
    return -1;
  }

  printf("success\n");
  return 0;
}
// CHECK: success