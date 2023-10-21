// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_FREE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-FREE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_REALLOC
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-FREE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_SIZE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-SIZE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_HANDLE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-GENERAL
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_LOCK
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-GENERAL
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_FREE
// RUN: not %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-FREE
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_REALLOC
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

int main() {
  void *unallocated_handle = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(ALLOC(MOVEABLE, 32)) + 1);
  print_addr("handle", unallocated_handle);
  // CHECK: handle: [[HANDLE:0x[0-9a-f]+]]

  #if defined(TEST_FREE)
    FREE(unallocated_handle);
  #elif defined(TEST_REALLOC)
    REALLOC(unallocated_handle, 32, 0);
  #elif defined(TEST_SIZE)
    SIZE(unallocated_handle);
  #elif defined(TEST_HANDLE)
    HANDLE_FUNC(unallocated_handle);
  #elif defined(TEST_LOCK)
    LOCK(unallocated_handle);
  #else
    #error Invalid test configuration
  #endif

  // CHECK-FREE: attempting free on address which was not malloc()-ed: [[HANDLE]]
  // CHECK-SIZE: attempting to call malloc_usable_size() for pointer which is not owned: [[HANDLE]]
  // TODO: Provide AddressDescription for moveable handle reservation, improving below error message.
  // CHECK-GENERAL: unknown-crash on address [[HANDLE]]
  return 0;
}