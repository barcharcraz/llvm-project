// RUN: %clang_cl_asan /Od /LD /EHsc /DBUILD_DLL1_TEST %s -Fe%todr1.dll
// RUN: %clang_cl_asan /Od /LD /EHsc /DBUILD_DLL2_TEST %s -Fe%todr2.dll
// RUN: %clang_cl_asan /Od /EHsc /DBUILD_EXE %s %todr1.lib %todr2.lib -Fe%t
// RUN: %env_asan_opts=detect_odr_violation=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK1
// RUN: %clang_cl_asan /Od /LD /EHsc /DBUILD_DLL2_TEST /DFAIL_CASE %s -Fe%todr2.dll
// RUN: %clang_cl_asan /Od /EHsc /DBUILD_EXE %s %todr1.lib %todr2.lib -Fe%t
// RUN: %env_asan_opts=detect_odr_violation=2 %run %t 2>&1 | FileCheck %s --check-prefix=CHECK2

// REQUIRES: asan-dynamic-runtime

// This only happens on x86. On x64, we use the odr_indicator to check violations rather than
// poisoning, and the odr_indicator is always set to UINTPTR_MAX, so the check is skipped
// REQUIRES: asan-32-bits

#include "windows.h"
#include <iostream>

#ifdef BUILD_DLL1_TEST
thread_local float threadId1;
__declspec(dllexport) void SetThreadId1(float f) { threadId1 = f; }
#endif

#ifdef BUILD_DLL2_TEST
#ifdef FAIL_CASE
// TODO:
// Right now, this only fails because of thread_local because of the addresses that are
// used for those variables by the compiler and referenced in asan_globals.
// If we were to remove thread_local, we still want the test case to fail with an ODR violation.
// BUG #1643067
thread_local float threadId1;
__declspec(dllexport) void SetThreadId2(float f) { threadId1 = f; }
#else
thread_local float threadId2;
__declspec(dllexport) void SetThreadId2(float f) { threadId2 = f; }
#endif
#endif

#ifdef BUILD_EXE
__declspec(dllimport) void SetThreadId1(float d);
__declspec(dllimport) void SetThreadId2(float d);
int main(int, char **) {
  SetThreadId1(1);
  SetThreadId2(2);
  std::cerr << "Pass." << std::endl;
  // CHECK1: Pass.
  // CHECK1-NOT: {{AddressSanitizer: odr-violation*}}
  // CHECK2: {{AddressSanitizer: odr-violation*}}
  // CHECK2-NEXT: {{threadId1*}}
  // CHECK2-NEXT: {{threadId1*}}
  return 0;
}
#endif