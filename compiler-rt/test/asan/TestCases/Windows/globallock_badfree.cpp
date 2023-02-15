// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: not %run %t 2>&1 | FileCheck %s

// CHECK: RETURNED_HANDLE: 0
// CHECK: AddressSanitizer: heap-use-after-free

#include <Windows.h>
#include <stdio.h>
#include "globallocal_shared.h"

int main() { 
    void *alloc = ALLOC(MOVEABLE, 100);
    fprintf(stderr, "RETURNED_PTR: %p\n", alloc);
    void *ptr = LOCK(alloc);
    ptr = LOCK(alloc);
    fprintf(stderr, "RETURNED_PTR: %p\n", ptr);
    void *result = FREE(alloc);
    fprintf(stderr, "RETURNED_HANDLE: %p\n", result);
    ((char *)ptr)[0] = 0xff;

    return 0;
}
