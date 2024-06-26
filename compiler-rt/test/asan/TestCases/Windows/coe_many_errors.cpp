// RUN: %clang_asan /std:c++17 /EHsc -Od /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s

#include <Windows.h>
#include <filesystem>
#include <iostream>

#ifdef DEFAULT_OPTION_TEST
extern "C" const char *__asan_default_options() {
  return "continue_on_error=1";
}
#endif

double x[5];

int main() {
  int returnCode = 0;
  for (int i = 0; i < 1000; i++) {
    returnCode = (int)x[5]; // Boom!
  }

  //CHECK: AddressSanitizer: global-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
  //CHECK: {{.*}}==CONTINUE ON ERROR
  //CHECK: Success.
  //CHECK: {{.*}} Unique call stacks: 1

  //CHECK: Raw HitCnt: 1000
  std::cerr << "Success.\n";
  return returnCode;
}