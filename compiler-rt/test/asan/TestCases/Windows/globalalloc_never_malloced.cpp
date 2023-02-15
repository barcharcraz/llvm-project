// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_FREE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-FREE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_SIZE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-SIZE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_HANDLE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-GENERAL
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_LOCK
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-GENERAL
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_FREE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-FREE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_SIZE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-SIZE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_HANDLE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-GENERAL
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_LOCK
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-GENERAL

#include "globallocal_shared.h"
#include "test_helpers.h"
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

int data;

int main() {
  void *random_ptr = &data;
  print_addr("ptr", random_ptr);
  // CHECK: ptr: [[PTR:0x[0-9a-f]+]]

  #if defined(TEST_FREE)
    FREE(random_ptr);
  // #elif defined(TEST_REALLOC)
  // Realloc skipped for fixed since that will be detected as unowned,
  // go to asan_realloc and produce a different error.
  //   REALLOC(random_ptr, 32, 0);
  #elif defined(TEST_SIZE)
    SIZE(random_ptr);
  #elif defined(TEST_HANDLE)
    HANDLE_FUNC(random_ptr);
  #elif defined(TEST_LOCK)
    LOCK(random_ptr);
  #else
    #error Invalid test configuration
  #endif

  // CHECK-FREE: attempting free on address which was not malloc()-ed: [[PTR]]
  // CHECK-SIZE: attempting to call malloc_usable_size() for pointer which is not owned: [[PTR]]
  // CHECK-GENERAL: global-buffer-overflow on address [[PTR]]
  return 0;
}