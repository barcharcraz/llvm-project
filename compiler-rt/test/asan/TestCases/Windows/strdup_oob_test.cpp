// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s

//REQUIRES: msvc-host

#include <string.h>

char kString[] = "foo";

int main(int argc, char **argv) {
  char *copy = strdup(kString);
  int x = copy[4 + argc];  // BOOM
  // CHECK: AddressSanitizer: heap-buffer-overflow
  // CHECK: #0 {{.*}}main {{.*}}strdup_oob_test.cpp:[[@LINE-2]]
  // CHECK-LABEL: allocated by thread T{{.*}} here:
  // CHECK: #{{[01]}} {{.*}}strdup
  // CHECK: #{{.*}}main {{.*}}strdup_oob_test.cpp:[[@LINE-6]]
  // CHECK-LABEL: SUMMARY
  // CHECK: strdup_oob_test.cpp:[[@LINE-7]]
  return x;
}
