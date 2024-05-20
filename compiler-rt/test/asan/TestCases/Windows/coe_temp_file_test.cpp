// RUN: %clang_asan /std:c++17 /EHsc -Od /DINVALID_NAME %s -Fe%t && %run %t 2>&1 | FileCheck %s
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && %run %t 2>&1 | FileCheck %s

#include <Windows.h>
#include <filesystem>
#include <iostream>

extern "C" const char *__asan_default_options() {
#ifdef INVALID_NAME
  auto CoeFileName = "\U0001F600"; // emoji file name
#else
  auto CoeFileName =
      "this\\is\\a\\very\\long\\file\\path\\that\\is\\more\\than\\260\\characte"
      "rs\\in\\length\\and\\should\\cause\\an\\error\\on\\Windows\\but\\should"
      "\\work\\just\\fine\\on\\Linux.txt";
#endif
  SetEnvironmentVariableA("COE_LOG_FILE", CoeFileName);
  return "";
}

double x[5];
int main() {
  //CHECK: Failed to open file {{.*}}. Internal error
  //CHECK: Trying to default to a newly created temp file.
  //CHECK: Using {{.*}} file for logging.
  //CHECK: Success.
  auto returnCode = (int)x[5]; // Boom!
  std::cerr << "Success.\n";
  return returnCode;
}