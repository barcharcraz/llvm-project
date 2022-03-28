// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <string.h>

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-strncat-param-overlap
void bad_function() {

  char buffer[] = "hello\0XXX";

  strncat(buffer, buffer + 1, 3); // BOOM
  // CHECK: ERROR: AddressSanitizer: strncat-param-overlap: memory ranges [{{.*}}[[ADDR1:0x[0-9a-f]+]],{{.*}}{{0x[0-9a-f]+}}) and [{{.*}}[[ADDR2:0x[0-9a-f]+]], {{.*}}{{0x[0-9a-f]+}}) overlap
  // CHECK: Address [[ADDR1]] is located in stack of thread T0 at offset {{[0-9]+}} in frame
  // CHECK: This frame has {{[0-9]+}} object(s):
  // CHECK: [{{[0-9]+}}, {{[0-9]+}}) 'buffer' <== Memory access at offset {{[0-9]+}} is inside this variable
  // CHECK: HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
  // CHECK: (longjmp, SEH and C++ exceptions *are* supported)
  // CHECK: Address [[ADDR2]] is located in stack of thread T0 at offset {{[0-9]+}} in frame
  // CHECK: This frame has {{[0-9]+}} object(s):
  // CHECK: [{{[0-9]+}}, {{[0-9]+}}) 'buffer' <== Memory access at offset {{[0-9]+}} is inside this variable
  // CHECK: HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
  // CHECK: (longjmp, SEH and C++ exceptions *are* supported)
  // CHECK: SUMMARY: AddressSanitizer: strncat-param-overlap

  return;
}

int main(int argc, char **argv) {

  bad_function();
  return 0;
}