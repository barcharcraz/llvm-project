// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %env_asan_opts=alloc_dealloc_mismatch=true not %run %t 2 2>&1 | FileCheck %s

#include <stdio.h>
#include <stdlib.h>

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-alloc-dealloc-mismatch
int main(int argc,char *argv[] ) {

  if (argc != 2) return -1;

  switch (atoi(argv[1])) {
  case 1: 
    delete [] (new int[10]);
    break;
  case 2: 
    delete (new int[10]);      // Boom!
    // CHECK: ERROR: AddressSanitizer: alloc-dealloc-mismatch (operator new [] vs operator delete) on [[ADDR:0x[0-9a-f]+]]
    // CHECK: [[ADDR]] is located {{[0-9]+}} bytes inside of {{[0-9]+}}-byte region
    // CHECK: allocated by thread T0 here:
    // CHECK: SUMMARY: AddressSanitizer: alloc-dealloc-mismatch
    // CHECK: HINT: if you don't care about these errors you may set ASAN_OPTIONS=alloc_dealloc_mismatch=0
    break;
  default: 
    printf("arguments: 1: no error 2: runtime error\n");
    return -1;
  }

  return 0;
}