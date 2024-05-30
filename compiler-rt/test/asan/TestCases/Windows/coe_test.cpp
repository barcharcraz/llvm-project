// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE
// RUN: %clang_asan /std:c++17 /EHsc -Od /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1
// RUN: %clang_asan /std:c++17 /EHsc -Od /DWMAIN_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1
// RUN: %clang_asan /std:c++17 /EHsc -Od /DDEFAULT_OPTION_TEST /DWMAIN_TEST %s -Fe%t && %run %t 2>&1

// Many Errors
// RUN: %clang_asan /std:c++17 /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-MANY-ERROR
// RUN: %clang_asan /std:c++17 /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=1 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE -check-prefix=CHECK-ASAN-COE-MANY-ERROR
// RUN: %clang_asan /std:c++17 /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST %s -Fe%t && %env_asan_opts=continue_on_error=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE -check-prefix=CHECK-ASAN-COE-MANY-ERROR
// RUN: %clang_asan /std:c++17 /EHsc -Od /DMANY_ERROR_TEST /DERROR_TEST /DDEFAULT_OPTION_TEST %s -Fe%t && %run %t 2>&1 | FileCheck %s --check-prefix=CHECK-ASAN-COE-NO-WINMAIN --check-prefix=CHECK-ASAN-COE -check-prefix=CHECK-ASAN-COE-MANY-ERROR

// %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST /DCOE_FILE %s -Fe%t
// RUN: env COE_LOG_FILE=coe_test.log %run %t 2>&1 | FileCheck %s
// %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST /DCOE_FILE2 /DWMAIN_TEST %s -Fe%t
// RUN: env COE_LOG_FILE=coe_test2.log %run %t 2>&1 | FileCheck %s
// %clang_asan /std:c++17 /EHsc -Od /DERROR_TEST /DCOE_FILE3 /DCOE_PROGRAMMATIC %s -Fe%t
// RUN: env COE_LOG_FILE= %run %t 2>&1 | FileCheck %s

#include <Windows.h>
#include <filesystem>
#include <iostream>

#ifdef COE_FILE
std::string CoeFileName = "coe_test.log"
#endif
#ifdef COE_FILE2
std::string CoeFileName = "coe_test2.log"
#endif
#ifdef COE_FILE3
std::string CoeFileName = "coe_test3.log"
#endif

#ifdef DEFAULT_OPTION_TEST
                              extern "C" const char *
                              __asan_default_options() {
#ifndef COE_PROGRAMMATIC
  return "continue_on_error=1";
#else
  SetEnvironmentVariableA("COE_LOG_FILE", CoeFileName);
  return "";
#endif
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

#ifdef COE_FILE || COE_FILE2 || COE_FILE3
  bool found = false;
  for (const auto &entry :
       std::filesystem::directory_iterator(std::filesystem::current_path())) {
    if (entry.is_regular_file()) {
      std::string fileName = entry.path().filename().string();
      if (fileName == CoeFileName) {
        found = true;
        break;
      }
    }
  }

  if (!found) {
    std::cerr << "Failed\n";
    return 1;
  }
#endif

  //CHECK-ASAN-COE: AddressSanitizer: global-buffer-overflow on address [[ADDR:0x[0-9a-f]+]]
  //CHECK-ASAN-COE: {{.*}}==CONTINUE ON ERROR
  //CHECK-ASAN-COE-NO-WINMAIN: Success.
  //CHECK-ASAN-COE: {{.*}} Unique call stacks: 1

  //CHECK-ASAN-COE-MANY-ERROR: Raw HitCnt: 1000
  //CHECK: Success.
  //CHECK-NOT: Failed
  std::cerr << "Success.\n";
  return returnCode;
}