// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true not %run %t 2>&1 | FileCheck %s

// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true not %run %t 2>&1 | FileCheck %s



#include <windows.h>
#include <cassert>
#include "../defines.h"
#include "globallocal_shared.h"

int main(){
    void* allocation = ALLOC(GMEM_FIXED, 10);
    assert(allocation != 0);
    assert( FREE(allocation) == NULL );
    FREE(allocation); //will dump
    assert(0 && "GlobalFree double free should produce an ASAN dump\n" );
    return 0;
}

// CHECK: AddressSanitizer: attempting double-free on [[addr:0x[0-9a-fA-F]+]] in thread T0: