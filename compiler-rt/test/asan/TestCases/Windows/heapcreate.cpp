#include <Windows.h>
#include <stdio.h>
#include "sanitizer\allocator_interface.h"

// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t 2>&1 | FileCheck %s

int main() {
    void* newHeap = HeapCreate(0, 1000, 5000);
    void* newAlloc = HeapAlloc(newHeap, 0, 100);
    if (__sanitizer_get_ownership(newAlloc)){
        printf("success\n");
        return 1;
    }
    printf("fail\n");
    return 1;
}

// CHECK: success
// CHECK-NOT: fail