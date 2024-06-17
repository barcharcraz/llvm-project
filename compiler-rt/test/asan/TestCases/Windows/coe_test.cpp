// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /std:c++17 /EHsc -Od /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1
// RUN: %clang_asan /std:c++17 /EHsc -Od /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1
// RUN: %clang_asan /std:c++17 /EHsc -Od /DDEFAULT_OPTION_TEST /DWMAIN_TEST %s -Fe%t && %run %t 2>&1

#include <Windows.h>
#include <filesystem>
#include <iostream>

#ifdef DEFAULT_OPTION_TEST
extern "C" const char *__asan_default_options() {
  return "continue_on_error=1";
}
#endif

double x[5];

#ifdef WMAIN_TEST
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine,
                   int nCmdShow) {
#else
int main() {
#endif
  int returnCode = 0;
#ifdef ERROR_TEST
  returnCode = (int)x[5]; // Boom!
#endif

  //CHECK-ASAN-COE: AddressSanitizer: global-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
  //CHECK-ASAN-COE: {{.*}}==CONTINUE ON ERROR
  //CHECK-ASAN-COE-NO-WINMAIN: Success.
  //CHECK-ASAN-COE: {{.*}} Unique call stacks: 1
  //CHECK-NOT: Failed
  std::cerr << "Success.\n";
  return returnCode;
}