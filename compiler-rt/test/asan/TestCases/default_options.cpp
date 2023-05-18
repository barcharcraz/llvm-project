// RUN: %clangxx_asan -O2 %s -o %t
// RUN: %run %t 2>&1 | FileCheck %s

#include "defines.h"
const char *kAsanDefaultOptions = "verbosity=1 help=1";

extern "C"
ATTRIBUTE_NO_SANITIZE_ADDRESS
const char *__asan_default_options() {
  // CHECK: Available flags for AddressSanitizer:
  return kAsanDefaultOptions;
}

int main() {
  return 0;
}
