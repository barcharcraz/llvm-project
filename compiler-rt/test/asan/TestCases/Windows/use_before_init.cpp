// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s

#include <malloc.h>
#include <stdio.h>

// Using _malloca will pull in _MarkAllocS, which is declared inline and is used during CRT init.
// The linker will choose the version of _MarkAllocS that has ASan instrumentation.
// This test ensures that ASan is starting early enough such that all the ASan variables are
// initialized and closed such that any use of the instrumented _MarkAllocS in CRT init won't crash.

int main() {
  (void) _malloca(16);
  puts("Success");
  // CHECK: Success
  return 0;
}