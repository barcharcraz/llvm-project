// RUN: %clang_asan /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-PASS
// RUN: %clang_asan /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-PASS
// RUN: %clang_asan /EHsc -Od /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-PASS
// RUN: %clang_asan /EHsc -Od /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /EHsc -Od /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /EHsc -Od /DERROR_TEST /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /EHsc -Od /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1
// RUN: %clang_asan /EHsc -Od /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1
// RUN: %clang_asan /EHsc -Od /DDEFAULT_OPTION_TEST /DWMAIN_TEST %s -Fe%t && %run %t 2>&1

// Many Errors
// RUN: %clang_asan /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-MANY-ERROR
// RUN: %clang_asan /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE -check-prefix=CHECK-ASAN-COE-MANY-ERROR
// RUN: %clang_asan /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE -check-prefix=CHECK-ASAN-COE-MANY-ERROR
// RUN: %clang_asan /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE -check-prefix=CHECK-ASAN-COE-MANY-ERROR

// TODO: Fix this test for piping/reading from coe log file.
// %clang_asan /EHsc -Od /DERROR_TEST /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --input-file %s/../asan_coe.log --check-prefix=CHECK-ASAN-COE
// %clang_asan /EHsc -Od /DERROR_TEST /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --input-file %s/../asan_coe.log --check-prefix=CHECK-ASAN-COE
// %clang_asan /EHsc -Od /DERROR_TEST /DDEFAULT_OPTION_TEST /DWMAIN_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --input-file %s/../asan_coe.log --check-prefix=CHECK-ASAN-COE

#include <Windows.h>
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
#ifdef MANY_ERROR_TEST
  for (int i = 0; i < 1000; i++) {
#endif
#ifdef ERROR_TEST
    returnCode = (int)x[5]; // Boom!
#endif
#ifdef MANY_ERROR_TEST
  }
#endif

  //CHECK-ASAN-COE: AddressSanitizer: global-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
  //CHECK-ASAN-COE: {{.*}}==CONTINUE ON ERROR
  //CHECK-ASAN-COE-NO-WINMAIN: Success.
  //CHECK-ASAN-COE: {{.*}} Unique call stacks: 1

  //CHECK-ASAN-COE-MANY-ERROR: Raw HitCnt: 1000
  //CHECK-PASS: Success.
  std::cerr << "Success.\n";
  return returnCode;
}