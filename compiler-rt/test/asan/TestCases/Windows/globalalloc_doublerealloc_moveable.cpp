// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s

#include "../defines.h"
#include "globallocal_shared.h"
#include "test_helpers.h"
#include <stdio.h>
#include <windows.h>

int main(){
    fprintf(stderr, "Test type: %s\n", TEST_TYPE);
    // CHECK: Test type: [[TYPE:(Global|Local)]]

    void* allocation = ALLOC(MOVEABLE, 10);
    CHECK(allocation != 0);

    void* ptr = LOCK(allocation);
    print_addr("addr", ptr);
    // CHECK: addr: [[addr:0x[0-9a-fA-F]+]]

    // Realloc will always reuse the handle, so realloc 0 to free.
    CHECK( REALLOC(allocation, 0, 0) == NULL );
    REALLOC(allocation, 32, 0); //will dump
    CHECK(0 && "GlobalReAlloc double free should produce an ASAN dump\n" );
    return 0;
}

// CHECK: AddressSanitizer: attempting double-free on [[addr]] in thread T0:
// CHECK: freed by thread T0 here
// CHECK: __asan_wrap_[[TYPE]]ReAlloc
// CHECK: previously allocated by thread T0 here
// CHECK: __asan_wrap_[[TYPE]]Alloc
