// RUN: %clang_cl_asan -Od %s -Fe%t -DTEST_REALLOC_ZERO_FALSE
// RUN: %env_asan_opts=allocator_frees_and_returns_null_on_realloc_zero=false %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-REALLOC-ZERO-FALSE
// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %env_asan_opts=allocator_frees_and_returns_null_on_realloc_zero=true %run %t 2>&1 | FileCheck %s

#include "test_helpers.h"
#include <malloc.h>

int main() {
    CHECK(malloc(0) != nullptr);

    CHECK(calloc(0, 4) != nullptr);
    CHECK(calloc(4, 0) != nullptr);
    CHECK(calloc(0, 0) != nullptr);

#if !defined(TEST_REALLOC_ZERO_FALSE)
    // Default behavior
    CHECK(realloc(malloc(0), 0) == nullptr);

    CHECK(_recalloc(malloc(0), 0, 4) == nullptr);
    CHECK(_recalloc(malloc(0), 4, 0) == nullptr);
    CHECK(_recalloc(malloc(0), 0, 0) == nullptr);
#else // ^^ realloc(0) returns nullptr ^^ | vv realloc(0) returns valid vv
    CHECK(realloc(malloc(0), 0) != nullptr);

    CHECK(_recalloc(malloc(0), 0, 4) != nullptr);
    CHECK(_recalloc(malloc(0), 4, 0) != nullptr);
    CHECK(_recalloc(malloc(0), 0, 0) != nullptr);
#endif

    CHECK(realloc(nullptr, 0) != nullptr);
    CHECK(_recalloc(nullptr, 0, 4) != nullptr);
    CHECK(_recalloc(nullptr, 4, 0) != nullptr);
    CHECK(_recalloc(nullptr, 0, 0) != nullptr);
    // CHECK-REALLOC-ZERO-FALSE: WARNING: allocator_frees_and_returns_null_on_realloc_zero is set to FALSE. This is not consistent with libcmt/ucrt/msvcrt behavior.

    puts("Pass");
    // CHECK: Pass

    return 0;
}
