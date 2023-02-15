// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_ALLOC1
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_ALLOC2
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_ALLOC3
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_ALLOC4
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_REALLOC1
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_REALLOC2
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_REALLOC3
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_REALLOC4
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_REALLOC5
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL -DTEST_REALLOC6
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_ALLOC1
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_ALLOC2
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_ALLOC3
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_ALLOC4
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_REALLOC1
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_REALLOC2
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_REALLOC3
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_REALLOC4
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_REALLOC5
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL -DTEST_REALLOC6
// RUN: not %run %t 2>&1 | FileCheck %s

#include "globallocal_shared.h"
#include "test_helpers.h"
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int main() {
    fprintf(stderr, "Test type: %s\n", TEST_TYPE);
    fprintf(stderr, "max-size: 0x%" PRIxPTR "\n", static_cast<uintptr_t>(-1ULL));
    // CHECK: max-size: [[MAXSIZE:0x[0-9a-f]+]]

    fprintf(stderr, "max-supp: 0x%" PRIxPTR "\n", static_cast<uintptr_t>(sizeof(void *) == 4 ? 0xc0000000 : 0x10000000000));
    // CHECK: max-supp: [[MAXSUPP:0x[0-9a-f]+]]

    // CHECK: AddressSanitizer: requested allocation size [[MAXSIZE]] (0x800 after adjustments for alignment, red zones etc.) exceeds maximum supported size of [[MAXSUPP]] (thread T0)
#if defined(TEST_ALLOC1)
    TRACE(ALLOC(FixedType, -1));
#elif defined(TEST_ALLOC2)
    TRACE(ALLOC(FixedType | ZEROINIT, -1));
#elif defined(TEST_ALLOC3)
    TRACE(ALLOC(MOVEABLE, -1));
#elif defined(TEST_ALLOC4)
    TRACE(ALLOC(MOVEABLE | ZEROINIT, -1));
#elif defined(TEST_REALLOC1)
    TRACE(REALLOC(ALLOC(FixedType, 4), -1, 0));
#elif defined(TEST_REALLOC2)
    TRACE(REALLOC(ALLOC(FixedType, 4), -1, ZEROINIT));
#elif defined(TEST_REALLOC3)
    TRACE(REALLOC(ALLOC(MOVEABLE, 4), -1, 0));
#elif defined(TEST_REALLOC4)
    TRACE(REALLOC(ALLOC(MOVEABLE, 4), -1, ZEROINIT));
#elif defined(TEST_REALLOC5)
    TRACE(REALLOC(LOCK(ALLOC(MOVEABLE, 4)), -1, 0));
#elif defined(TEST_REALLOC6)
    TRACE(REALLOC(LOCK(ALLOC(MOVEABLE, 4)), -1, ZEROINIT));
#else
    #error Invalid test case
#endif
    fputs("Pass", stderr);
    // CHECK-NOT: Pass
    return 0;
}