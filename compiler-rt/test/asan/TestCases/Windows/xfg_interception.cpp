// RUN: %clang_cl_asan %s -Fe%t /EHsc /guard:xfg
// RUN: %run %t 2>&1 | FileCheck %s

#include <cwchar>
#include <iostream>

void foo() {
  std::cout << "foo" << std::endl;
}

size_t bar() {
  return std::wcslen(L"Test");
}

void (*test[1])() = {foo};

int main() {
  test[0]();
  std::cout << bar() << std::endl;
  // CHECK: success
  std::cout << "success" << std::endl;
  return 0;
}
