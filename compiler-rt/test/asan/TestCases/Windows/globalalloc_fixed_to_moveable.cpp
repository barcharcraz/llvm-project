// RUN: %clang_cl_asan /Od -o %t %s -DTEST_GLOBAL
// RUN: %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-GLOBAL
// RUN: %clang_cl_asan /Od -o %t %s -DTEST_LOCAL
// RUN: %run %t 2>&1 | FileCheck %s --check-prefixes CHECK,CHECK-LOCAL

#include "../defines.h"
#include "globallocal_shared.h"
#include "test_helpers.h"
#include <stdint.h>
#include <stdio.h>

int main() {
    fprintf(stderr, "Test type: %s\n", TEST_TYPE);
    // CHECK: Test type: [[TYPE:(Global|Local)]]

    char *ptr1 = (char *)ALLOC(FixedType, 4);
    print_addr("ptr1", ptr1);
    // CHECK: ptr1: [[PTR:0x[0-9a-f]+]]

    auto handle = REALLOC(ptr1, 0, MODIFY | MOVEABLE); // Passthrough no-op with LocalReAlloc, allocation remains fixed.

#if defined(TEST_GLOBAL)
    CHECK(handle != ptr1);
#elif defined(TEST_LOCAL)
    CHECK(handle == ptr1);
#endif

    char *ptr2 = (char*)LOCK(handle); // With Local, will still be fixed: passthrough no-op.

#if defined(TEST_GLOBAL)
    CHECK(ptr2 != ptr1);
#elif defined(TEST_LOCAL)
    CHECK(ptr2 == ptr1);
#endif

    ptr2[0] = 'a';
    UNLOCK(handle);
    auto freed_handle = FREE(handle);
    CHECK(freed_handle == nullptr);

    ptr1[0] = 'a';
    // CHECK: AddressSanitizer: heap-use-after-free on address [[PTR]]
    // CHECK: WRITE of size 1 at [[PTR]] thread T0
    // CHECK: freed by thread T0 here
    // CHECK-GLOBAL: __asan_wrap_GlobalReAlloc
    // CHECK-LOCAL: __asan_wrap_LocalFree
    // CHECK: previously allocated by thread T0 here
    // CHECK: __asan_wrap_[[TYPE]]Alloc

    return 0;
}