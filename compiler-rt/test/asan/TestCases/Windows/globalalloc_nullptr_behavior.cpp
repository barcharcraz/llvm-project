// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_SIZE
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_HANDLE
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_LOCK
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_UNLOCK
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_SIZE
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_HANDLE
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_LOCK
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_UNLOCK
// RUN: not %run %t 2>&1 | FileCheck %s

#include "globallocal_shared.h"
#include "test_helpers.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main() {
    fprintf(stderr, "Test type: %s\n", TEST_TYPE);

    fprintf(stderr, "nullptr: 0x%0*llx\n", sizeof(void *) == 4 ? 8 : 12, 0ULL);
    // CHECK: nullptr: [[NULLPTR:0x0+]]

    // CHECK: AddressSanitizer: unknown-crash on address [[NULLPTR]] at pc
#if defined(TEST_SIZE)
    TRACE(SIZE(nullptr));
#elif defined(TEST_HANDLE)
    TRACE(HANDLE_FUNC(nullptr));
#elif defined(TEST_LOCK)
    TRACE(LOCK(nullptr));
#elif defined(TEST_UNLOCK)
    TRACE(UNLOCK(nullptr));
#else
    #error Invalid test case
#endif
    fputs("Pass", stderr);
    // CHECK-NOT: Pass
    return 0;
}