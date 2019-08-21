// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true not %run %t 2>&1 | FileCheck %s


#include <windows.h>
#include <cassert>

int main(){
    void* allocation = GlobalAlloc(GMEM_FIXED, 10);
    assert(allocation != 0);
    assert( GlobalFree(allocation) == NULL );
    GlobalFree(allocation); //will dump
    assert(0 && "GlobalFree double free should produce an ASAN dump\n" );
    return 0;
}

// CHECK: AddressSanitizer: attempting double-free on [[addr:0x[0-9a-fA-F]+]] in thread T0: