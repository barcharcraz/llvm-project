// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DMANY_THREAD_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-MANY_THREAD_TEST
// RUN: %clang_asan /std:c++17 /EHsc -Od /DDEFAULT_OPTION_TEST /DMANY_THREAD_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-MANY_THREAD_TEST

// Derived from TestCases\error_report_callback.cpp, just with continue-on-error enabled.

#include <iostream>
#include <sanitizer/asan_interface.h>
#include <stdio.h>
#include <vector>
#include <windows.h>

#ifdef DEFAULT_OPTION_TEST
extern "C" const char *__asan_default_options() {
  return "continue_on_error=1";
}
#endif

DWORD WINAPI ThreadPrint(void *) {
  std::cerr << "Thread called!\n";
  return 0;
}

void ErrorFn() {
  std::vector<HANDLE> threads;
  for (auto i = 0; i < 10; ++i) {
    HANDLE thr = CreateThread(NULL, 0, ThreadPrint, NULL, 0, NULL);
    if (thr == 0) {
      std::cerr << "Failed to create thread!\n";
    }

    threads.push_back(thr);
  }

  for (auto thr : threads) {
    if (WAIT_OBJECT_0 != WaitForSingleObject(thr, INFINITE)) {
      std::cerr << "Failed to wait on thread!\n";
    }
  }
}

static void ErrorReportCallbackOneToZ(const char *report) {
  std::cerr << "ABCDEF" << report << "GHIJKL\n";
#ifdef MANY_THREAD_TEST
  ErrorFn();
#endif
  fflush(stderr);
}

int main(int argc, char **argv) {
  __asan_set_error_report_callback(ErrorReportCallbackOneToZ);
  __asan_report_error((void *)_ReturnAddress(), 0, 0, 0, true, 1);
  // CHECK: ABCDEF
  // CHECK: ERROR: AddressSanitizer
  // CHECK: GHIJKL
  // CHECK-MANY_THREAD_TEST-COUNT-10: Thread called!
  // CHECK: Success.
  // CHECK-NOT: {{Failed.*}}
  std::cerr << "Success.\n";
  return 0;
}