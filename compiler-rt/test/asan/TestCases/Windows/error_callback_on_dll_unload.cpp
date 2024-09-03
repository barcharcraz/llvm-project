// RUN: %clang_cl_asan /EHsc /std:c++17 -LD -Od %p/../Helpers/asan_dll.cpp -Fe%t.dll
// RUN: %clang /EHsc /std:c++17 -Od %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// RUN: %env_asan_opts=verbosity=1 not %run %t %t.dll 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-VERBOSE
// RUN: %clang /EHsc /std:c++17 -Od /DCONTINUE_ON_ERROR %s -Fe%t
// RUN: %env_asan_opts=continue_on_error=1 %run %t %t.dll 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-COE
// RUN: %env_asan_opts=continue_on_error=1:verbosity=1 %run %t %t.dll 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-COE,CHECK-VERBOSE

// RUN: %clang_cl_asan /EHsc /std:c++17 -LD -Od %p/../Helpers/asan_dll.cpp -Fe%t.dll /link vcasan.lib
// RUN: %clang /EHsc /std:c++17 -Od %s -Fe%t
// RUN: not %run %t %t.dll 2>&1 | FileCheck %s
// UNSUPPORTED: debug-crt

#include "Windows.h"
#include <iostream>

extern "C" void SetErrorReportCallback();

int main(int argc, char **argv) {
  const char *dllName = argv[1];
  HINSTANCE lib = LoadLibrary(dllName);

  // Initialize ASAN from runtime DLL load
  if (!lib) {
    std::cerr << "Unable to load DLL.\n";
    return -1;
    // CHECK-NOT: Unable to load DLL.
  }

  // The error_report_callback needs to live in another DLL
  auto initASanOnErrorReportCallback =
      reinterpret_cast<decltype(SetErrorReportCallback) *>(
          GetProcAddress(lib, "SetErrorReportCallback"));
  initASanOnErrorReportCallback();

  auto errorBeforeUnload = malloc(100);
  auto errorAfterUnload = malloc(100);

#if CONTINUE_ON_ERROR
  free(errorBeforeUnload);
  free(errorBeforeUnload);
#endif
  // CHECK-COE: __asan_on_error called
  // CHECK-COE: SetCallback called

  // Unload the DLL where callbacks exist
  FreeLibrary(lib);

  free(errorAfterUnload);
  free(errorAfterUnload);
  // CHECK-NOT: __asan_on_error called
  // CHECK-NOT: SetCallback called
  // CHECK-VERBOSE: __asan_on_error exception: invalid address.
  // CHECK-VERBOSE: Exception in callback registered from __asan_set_error_report_callback: invalid address.
  // CHECK-VERBOSE-NOT: __asan_on_error exception: unknown exception.
  // CHECK-VERBOSE-NOT: Exception in callback registered from __asan_set_error_report_callback: unknown exception.

  std::cerr << "Success.\n";
  // CHECK-COE: Success.

  // CHECK-NOT: AddressSanitizer: nested bug in the same thread, aborting.
  return 0;
}