// RUN: %clang_asan /std:c++17 /EHsc -Od /DCOE_FILE %s -Fe%t
// RUN: env COE_LOG_FILE=coe_test.log %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DCOE_FILE2 /DWMAIN_TEST %s -Fe%t
// RUN: env COE_LOG_FILE=coe_test2.log %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od /DCOE_FILE3 %s -Fe%t
// RUN: env COE_LOG_FILE= %run %t 2>&1 | FileCheck %s

#include <Windows.h>
#include <filesystem>
#include <iostream>

#ifdef COE_FILE
const char *CoeFileName = "coe_test.log";
#endif
#ifdef COE_FILE2
const char *CoeFileName = "coe_test2.log";
#endif
#ifdef COE_FILE3
const char *CoeFileName = "coe_test3.log";
#endif

extern "C" const char *__asan_default_options() {
  SetEnvironmentVariable("COE_LOG_FILE", CoeFileName);
  return "";
}

double x[5];

#ifdef WMAIN_TEST
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine,
                   int nCmdShow) {
#else
int main() {
#endif
  auto returnCode = (int)x[5]; // Boom!

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

  //CHECK: Success.
  //CHECK-NOT: Failed
  std::cerr << "Success.\n";
  return returnCode;
}