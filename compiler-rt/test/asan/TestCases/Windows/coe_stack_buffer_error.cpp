// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefixes=NO-WARNING,CHECK
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --check-prefixes=NO-WARNING,CHECK
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1:verbosity=1:suppress_equal_pcs=false %run %t 2>&1 | FileCheck %s --check-prefixes=NO-WARNING,CHECK
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2:verbosity=1:suppress_equal_pcs=false %run %t 2>&1 | FileCheck %s --check-prefixes=NO-WARNING,CHECK
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1:verbosity=1 %run %t 2>&1 | FileCheck %s --check-prefixes=WARNING,CHECK
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2:verbosity=1 %run %t 2>&1 | FileCheck %s --check-prefixes=WARNING,CHECK

#include <iostream>
#include <string.h>

int main(void) {
  char buf1[0x10] = {0};
  char buf2[0x10] = {0};
  memset(buf1, 0x41, 0x20); // intentional oob
  memset(buf1, 0x41, 0x20); // intentional oob
  std::cerr << "Success.\n";
  return 0;
}

// NO-WARNING-NOT: Disabling suppress_equal_pcs.
// WARNING: Disabling suppress_equal_pcs.
// CHECK-COUNT-2: {{.*ERROR: AddressSanitizer}}
// CHECK: Success.
// CHECK: Total: 2 Unique Memory Safety Issues