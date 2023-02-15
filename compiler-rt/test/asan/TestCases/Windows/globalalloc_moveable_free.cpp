// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "globallocal_shared.h"
#include <string>
#include <system_error>

[[noreturn]] void report_win32_error(const char * const expr,
                               const char * const filename, const int line)
{
    auto gle = GetLastError();
    printf("ERROR on %s(%d): '%s'. Win32 Error %lx: %s\n",
        filename, line, expr, gle, std::system_category().message(gle).c_str());
    exit(-1);
}

#define WIN32_CHECK(EXPR) {                            \
    if (!(EXPR)) {                                     \
        report_win32_error(#EXPR, __FILE__, __LINE__); \
    }                                                  \
} while (0)

int main(){
    { // alloc -> free
        HGLOBAL moveable = ALLOC(MOVEABLE, 100);
        WIN32_CHECK(moveable != nullptr);

        WIN32_CHECK(FREE(moveable) == nullptr);
    }

    { // alloc -> realloc -> free
        HGLOBAL moveable = ALLOC(MOVEABLE, 100);
        WIN32_CHECK(moveable != nullptr);

        HGLOBAL realloced = REALLOC(moveable, 200, 0);
        WIN32_CHECK(realloced != nullptr);

        WIN32_CHECK(FREE(moveable) == nullptr);
    }

    { // alloc -> lock -> free by pointer
        HGLOBAL moveable = ALLOC(MOVEABLE, 100);
        WIN32_CHECK(moveable != nullptr);

        void * const ptr = LOCK(moveable);
        WIN32_CHECK(ptr != nullptr);

        WIN32_CHECK(FREE(ptr) == nullptr);
    }

    { // alloc -> realloc -> lock -> free by pointer
        HGLOBAL moveable = ALLOC(MOVEABLE, 100);
        WIN32_CHECK(moveable != nullptr);

        HGLOBAL realloced = REALLOC(moveable, 200, 0);
        WIN32_CHECK(realloced != nullptr);

        void * const ptr = LOCK(realloced);
        WIN32_CHECK(ptr != nullptr);

        WIN32_CHECK(FREE(ptr) == nullptr);
    }

    { // alloc -> lock -> realloc by pointer -> free
        HGLOBAL moveable = ALLOC(MOVEABLE, 100);
        WIN32_CHECK(moveable != nullptr);

        void * const ptr = LOCK(moveable);
        WIN32_CHECK(ptr != nullptr);

        HGLOBAL realloced = REALLOC(ptr, 200, 0);
        WIN32_CHECK(realloced != nullptr);

        WIN32_CHECK(FREE(realloced) == nullptr);
    }

    { // alloc -> lock -> realloc by pointer -> lock -> free by pointer
        HGLOBAL moveable = ALLOC(MOVEABLE, 100);
        WIN32_CHECK(moveable != nullptr);

        void * const ptr = LOCK(moveable);
        WIN32_CHECK(ptr != nullptr);

        HGLOBAL realloced = REALLOC(ptr, 200, 0);
        WIN32_CHECK(realloced != nullptr);

        void * const ptr2 = LOCK(realloced);
        WIN32_CHECK(ptr2 != nullptr);

        WIN32_CHECK(FREE(ptr2) == nullptr);
    }

    fprintf(stderr,"Passed\n");
    return 1;
}
// CHECK-NOT: AddressSanitizer
// CHECK-NOT: Failure!
// CHECK-NOT: attempting free on address which was not malloc()-ed
// CHECK: Passed
