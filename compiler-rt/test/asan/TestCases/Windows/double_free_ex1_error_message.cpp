// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-double-free
int main() {

  int *x = new int[42];
  delete [] x;

  // ... some complex body of code

  delete [] x;
  // CHECK: ERROR: AddressSanitizer: attempting double-free on [[ADDR:0x[0-9a-f]+]] in thread T0:
  // CHECK: [[ADDR]] is located {{[0-9]+}} bytes inside of {{[0-9]+}}-byte region [{{0x[0-9a-f]+}},{{0x[0-9a-f]+}})
  // CHECK: freed by thread T0 here:
  // CHECK: previously allocated by thread T0 here:
  // CHECK: SUMMARY: AddressSanitizer: double-free {{.*}} in operator delete[](void *)
  return 0;
}
