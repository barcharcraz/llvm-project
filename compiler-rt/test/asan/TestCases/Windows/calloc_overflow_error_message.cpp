// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <stdio.h>
#include <stdlib.h>

int number = -1;
int element_size = 1000;

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-calloc-overflow
int main() {

  void *p = calloc(number, element_size);      // Boom!
  // CHECK: ERROR: AddressSanitizer: calloc parameters overflow: count * size ({{.*}} * {{.*}}) cannot be represented in type size_t (thread T0)
  // CHECK: HINT: if you don't care about these errors you may set allocator_may_return_null=1
  // SUMMARY: AddressSanitizer: {{.*}} in calloc

  printf("calloc returned: %zu\n", (size_t)p);

  return 0;
}