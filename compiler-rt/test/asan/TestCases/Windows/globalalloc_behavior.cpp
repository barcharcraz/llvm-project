// RUN: %clang_cl_asan /Od %s /std:c++17 -Fe%t -DTEST_LOCAL
// RUN: %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s /std:c++17 -Fe%t -DTEST_GLOBAL
// RUN: %run %t 2>&1 | FileCheck %s

// Test all non-failing behavior cases to ensure it is the same as when ASAN is not attached.

#include "globallocal_shared.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

int num_errors = 0;

void check_fail(const char * const expr, const char * const file, const size_t line) {
    // NDEBUG is set in debug to avoid CRT assertion that trigger prior to ASAN report
    // Use CHECK in place of assert.
    fprintf(stderr, "Expression '%s' failed at '%s' on line '%zd'.\n", expr, file, line);
    ++num_errors;
}

void check_fail_gle(unsigned int gle, const char * const file, const size_t line) {
    fprintf(stderr, "GetLastError() returned '0x%x' unexpectedly at '%s' on line '%zd'.\n", gle, file, line);
    ++num_errors;
}

#define CHECK_BASE(EXPR) do { if (!(EXPR)) { check_fail(#EXPR, __FILE__, __LINE__); } } while (0)

// ASAN Bug: Because we call Win32 functions without guarding GLE, frequently the GetLastError value_comp
// is set to ERROR_NO_MORE_ITEMS due to calling HeapWalk. Omit that as an error when GLE should not change.

#define CHECK(EXPR) do { SetLastError(1234); CHECK_BASE(EXPR); if (GetLastError() != 1234 && GetLastError() != ERROR_NO_MORE_ITEMS) { check_fail_gle(GetLastError(), __FILE__, __LINE__); } } while (0)
#define CHECK_GLE(EXPR, ERR) do { SetLastError(1234); CHECK_BASE(EXPR); CHECK_BASE(GetLastError() == (ERR)); } while (0)

// Macros to conveniently showcase behavior differences when building without /fsanitize=address.
#ifdef __SANITIZE_ADDRESS__
#define ASAN_ONLY_CHECK(EXPR) CHECK(EXPR)
#define ASAN_ONLY_CHECK_GLE(EXPR, ERR) CHECK_GLE(EXPR, ERR)
#define NOT_ASAN_CHECK(EXPR)
#define NOT_ASAN_CHECK_GLE(EXPR, ERR)
#else
#define ASAN_ONLY_CHECK(EXPR)
#define ASAN_ONLY_CHECK_GLE(EXPR, ERR)
#define NOT_ASAN_CHECK(EXPR) CHECK(EXPR)
#define NOT_ASAN_CHECK_GLE(EXPR, ERR) CHECK_GLE(EXPR, ERR)
#endif

#define TRACE(EXPR) do { printf(#EXPR " returned %p\n", (EXPR)); } while (0)

// Fixed Helpers
void *this_handle = nullptr;
void *valid_handle() {
    return this_handle = ALLOC(FixedType, 4);
}

void *valid_locked_handle() {
    void *h = valid_handle();
    LOCK(h);
    return h;
}

void *this_locked_ptr;
void *valid_locked_ptr(void *handle = valid_handle()) {
    return this_locked_ptr = LOCK(handle);
}

auto valid_locked_alloc() {
    struct alloc {
        void *handle;
        void *ptr;
    };

    void *h = valid_handle();
    return alloc{h, valid_locked_ptr(h)};
}

// Moveable Helpers
void *this_moveable_handle = nullptr;
void *valid_moveable_handle() {
    return this_moveable_handle = ALLOC(MOVEABLE, 4);
}

void *valid_locked_moveable_handle() {
    void *h = valid_moveable_handle();
    LOCK(h);
    return h;
}

void *this_locked_moveable_ptr;
void *valid_locked_moveable_ptr(void *handle = valid_moveable_handle()) {
    return this_locked_moveable_ptr = LOCK(handle);
}

auto valid_locked_moveable_alloc() {
    struct alloc {
        void *handle;
        void *ptr;
    };

    void *h = valid_moveable_handle();
    return alloc{h, valid_locked_moveable_ptr(h)};
}

void test_fixed() {
    // Allocations
    {
        CHECK(ALLOC(FixedType, 4) != nullptr);
        CHECK(ALLOC(FixedType | ZEROINIT, 4) != nullptr);

        CHECK(ALLOC(FixedType, 0) != nullptr);
        CHECK(ALLOC(FixedType | ZEROINIT, 0) != nullptr);

        // Should report error - see globalalloc_max_alloc_behavior.cpp.
        // CHECK_GLE(ALLOC(FixedType, -1) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(ALLOC(FixedType | ZEROINIT, -1) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
    }

    // Frees
    {
        CHECK(FREE(valid_handle()) == nullptr);
        CHECK(FREE(valid_locked_handle()) == nullptr);
        CHECK(FREE(valid_locked_ptr()) == nullptr);
        CHECK(FREE(nullptr) == nullptr);
    }

    // Size
    {
        CHECK(SIZE(valid_handle()) == 4);
        CHECK(SIZE(valid_locked_handle()) == 4);
        CHECK(SIZE(valid_locked_ptr()) == 4);

        // Should report error - see globalalloc_nullptr_behavior.cpp.
        // CHECK_GLE(SIZE(nullptr) == 0, ERROR_INVALID_HANDLE);
    }

    // Handles
    {
        CHECK(HANDLE_FUNC(valid_handle()) == this_handle);
        // Should report error - see globalalloc_nullptr_behavior.cpp.
        //CHECK_GLE(HANDLE_FUNC(nullptr) == nullptr, ERROR_INVALID_HANDLE);
    }

    // Lock
    {
        CHECK(LOCK(valid_handle()) != nullptr);

        auto [h, p] = valid_locked_alloc();
        CHECK(LOCK(h) == p);
        CHECK(LOCK(p) == p);

        // Should report error - see globalalloc_nullptr_behavior.cpp.
        // CHECK_GLE(LOCK(nullptr) == nullptr, ERROR_INVALID_HANDLE);
    }

    // Unlock
    {
        CHECK(UNLOCK(valid_handle()) == TRUE);

        auto [h, p] = valid_locked_alloc(); // 1
        LOCK(h);                            // 2
        CHECK(UNLOCK(h) == TRUE);           // 1
        CHECK(UNLOCK(p) == TRUE);           // 1
        CHECK(UNLOCK(h) == TRUE);           // 0

        // Should report error - see globalalloc_nullptr_behavior.cpp.
        // CHECK(UNLOCK(nullptr) == TRUE);
    }

    // ReAlloc
    // Implementation Note: Actual REALLOC for Fixed pointers behavior depends on the underlying
    // Heap implementation and how it responds to HEAP_REALLOC_IN_PLACE_ONLY. For example, LFH heap will
    // reject all requests. Segment heap will allow keeping the same size, but not growing/shrinking.
    // The ASAN implementation currently permits a new address to be assigned since our allocator does
    // not support "in-place-only realloc". Therefore, the below behavior sanity checks marked ASAN_ONLY are
    // informed only via how moveable allocations react.
    {
        ASAN_ONLY_CHECK(REALLOC(valid_handle(), 4, 0) != nullptr);
        ASAN_ONLY_CHECK(REALLOC(valid_handle(), 4, ZEROINIT) != nullptr);

        ASAN_ONLY_CHECK(REALLOC(valid_locked_ptr(), 0, 0) == nullptr);
        ASAN_ONLY_CHECK(REALLOC(valid_locked_ptr(), 0, ZEROINIT) == nullptr);

        // Should report error - see globalalloc_max_alloc_behavior.cpp.
        // ASAN_ONLY_CHECK_GLE(REALLOC(valid_handle(), -1, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // ASAN_ONLY_CHECK_GLE(REALLOC(valid_handle(), -1, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK_GLE(REALLOC(nullptr, 4, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, 4, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK_GLE(REALLOC(nullptr, 0, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, 0, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK_GLE(REALLOC(nullptr, -1, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, -1, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
    }
}

void test_moveable() {
    // Allocations
    {
        CHECK(ALLOC(MOVEABLE, 4) != nullptr);
        CHECK(ALLOC(MOVEABLE | ZEROINIT, 4) != nullptr);

        CHECK(ALLOC(MOVEABLE, 0) != nullptr);
        CHECK(ALLOC(MOVEABLE | ZEROINIT, 0) != nullptr);

        // Should report error - see globalalloc_max_alloc_behavior.cpp.
        // CHECK_GLE(ALLOC(MOVEABLE, -1) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(ALLOC(MOVEABLE | ZEROINIT, -1) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
    }

    // Frees
    {
        CHECK(FREE(valid_moveable_handle()) == nullptr);
        CHECK(FREE(valid_locked_moveable_handle()) == nullptr);
        CHECK(FREE(valid_locked_moveable_ptr()) == nullptr);
        CHECK(FREE(nullptr) == nullptr);
    }

    // Size
    {
        CHECK(SIZE(valid_moveable_handle()) == 4);
        CHECK(SIZE(valid_locked_moveable_handle()) == 4);
        CHECK(SIZE(valid_locked_moveable_ptr()) == 4);

        // Should report error - see globalalloc_nullptr_behavior.cpp.
        // CHECK_GLE(SIZE(nullptr) == 0, ERROR_INVALID_HANDLE);
    }

    // Handles
    {
        // Should report error - see globalalloc_handle_invalid.cpp.
        // CHECK_GLE(HANDLE_FUNC(valid_moveable_handle()) == nullptr, ERROR_INVALID_HANDLE); // crash

        auto [h, p] = valid_locked_moveable_alloc();
        // CHECK(HANDLE_FUNC(h) == h); // crash
        CHECK(HANDLE_FUNC(p) == h);

        // Should report error - see globalalloc_nullptr_behavior.cpp.
        // CHECK_GLE(HANDLE_FUNC(nullptr) == nullptr, ERROR_INVALID_HANDLE);
    }

    // Lock
    {
        CHECK(LOCK(valid_moveable_handle()) != nullptr);

        auto [h, p] = valid_locked_moveable_alloc();       // 1
        CHECK(LOCK(h) == p);                     // 2
        CHECK(LOCK(p) == p);                     // 2
        CHECK(UNLOCK(h) == TRUE);                // 1
        CHECK_GLE(UNLOCK(h) == FALSE, NO_ERROR); // 0

        // Should report error - see globalalloc_nullptr_behavior.cpp.
        // CHECK_GLE(LOCK(nullptr) == nullptr, ERROR_INVALID_HANDLE);
    }

    // Unlock
    {
        CHECK_GLE(UNLOCK(valid_moveable_handle()) == FALSE, ERROR_NOT_LOCKED);

        auto [h, p] = valid_locked_moveable_alloc();       // 1
        LOCK(h);                                     // 2
        CHECK(UNLOCK(h) == TRUE);                // 1
        CHECK(UNLOCK(p) == TRUE);                // 1
        CHECK_GLE(UNLOCK(h) == FALSE, NO_ERROR); // 0

        // Should report error - see globalalloc_nullptr_behavior.cpp.
        // CHECK(UNLOCK(nullptr) == TRUE);
    }

    // ReAlloc
    {
        CHECK(REALLOC(valid_moveable_handle(), 4, 0) != nullptr);
        CHECK(REALLOC(valid_moveable_handle(), 4, ZEROINIT) != nullptr);
        CHECK(REALLOC(valid_moveable_handle(), 4, ZEROINIT | MOVEABLE) != nullptr);

        CHECK(REALLOC(valid_moveable_handle(), 0, 0) == nullptr);
        CHECK(REALLOC(valid_moveable_handle(), 0, ZEROINIT) == nullptr);

        // ASAN Bug:
        NOT_ASAN_CHECK(REALLOC(valid_moveable_handle(), 0, ZEROINIT | MOVEABLE) == this_moveable_handle);

        // Should report error - see globalalloc_max_alloc_behavior.cpp.
        // CHECK_GLE(REALLOC(valid_moveable_handle(), -1, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(REALLOC(valid_moveable_handle(), -1, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(REALLOC(valid_moveable_handle(), -1, ZEROINIT | MOVEABLE) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK(REALLOC(valid_locked_moveable_handle(), 4, 0) != nullptr);
        CHECK(REALLOC(valid_locked_moveable_handle(), 4, ZEROINIT) != nullptr);
        CHECK(REALLOC(valid_locked_moveable_handle(), 4, ZEROINIT | MOVEABLE) != nullptr);

        CHECK(REALLOC(valid_locked_moveable_handle(), 0, 0) == nullptr);
        CHECK(REALLOC(valid_locked_moveable_handle(), 0, ZEROINIT) == nullptr);
        CHECK(REALLOC(valid_locked_moveable_handle(), 0, ZEROINIT | MOVEABLE) == nullptr);

        // Should report error - see globalalloc_max_alloc_behavior.cpp.
        // CHECK_GLE(REALLOC(valid_locked_moveable_handle(), -1, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(REALLOC(valid_locked_moveable_handle(), -1, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(REALLOC(valid_locked_moveable_handle(), -1, ZEROINIT | MOVEABLE) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK(REALLOC(valid_locked_moveable_ptr(), 4, 0) != nullptr);
        CHECK(REALLOC(valid_locked_moveable_ptr(), 4, ZEROINIT) != nullptr);
        CHECK(REALLOC(valid_locked_moveable_ptr(), 4, ZEROINIT | MOVEABLE) != nullptr);

        // ReAlloc(0) is heap-dependant behavior, ASAN mimics Segment heap since this is consistent with
        // default allocator_frees_and_returns_null_on_realloc_zero=TRUE behavior.
        // LFH: CHECK(REALLOC(valid_locked_moveable_ptr(), 0, 0) == this_locked_moveable_ptr);
        // Seg: CHECK_GLE(REALLOC(valid_locked_moveable_ptr(), 0, 0) == 0, ERROR_NOT_ENOUGH_MEMORY);

        // Asan Bug: We don't set ERROR_NOT_ENOUGH_MEMORY in this zero case.
        ASAN_ONLY_CHECK(REALLOC(valid_locked_moveable_ptr(), 0, 0) == nullptr);
        ASAN_ONLY_CHECK(REALLOC(valid_locked_moveable_ptr(), 0, ZEROINIT) == nullptr);

        // ASAN Bug:
        ASAN_ONLY_CHECK(REALLOC(valid_locked_moveable_ptr(), 0, ZEROINIT | MOVEABLE) == nullptr);
        NOT_ASAN_CHECK(REALLOC(valid_locked_moveable_ptr(), 0, ZEROINIT | MOVEABLE) != nullptr);

        // Should report error - see globalalloc_max_alloc_behavior.cpp.
        // CHECK_GLE(REALLOC(valid_locked_moveable_ptr(), -1, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(REALLOC(valid_locked_moveable_ptr(), -1, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        // CHECK_GLE(REALLOC(valid_locked_moveable_ptr(), -1, ZEROINIT | MOVEABLE) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK_GLE(REALLOC(nullptr, 4, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, 4, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, 4, ZEROINIT | MOVEABLE) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK_GLE(REALLOC(nullptr, 0, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, 0, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, 0, ZEROINIT | MOVEABLE) == nullptr, ERROR_NOT_ENOUGH_MEMORY);

        CHECK_GLE(REALLOC(nullptr, -1, 0) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, -1, ZEROINIT) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
        CHECK_GLE(REALLOC(nullptr, -1, ZEROINIT | MOVEABLE) == nullptr, ERROR_NOT_ENOUGH_MEMORY);
    }
}

int main() {
    test_fixed();
    test_moveable();
    if (num_errors == 0) {
        puts("Pass");
        // CHECK: Pass
    }

    return num_errors;
}
