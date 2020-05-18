// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true not %run %t 2>&1 | FileCheck %s


#include <Windows.h>
#include <stdio.h>
int main(){
    HGLOBAL moveable = GlobalAlloc(GMEM_MOVEABLE, 100);
    if (moveable == nullptr) {
        fprintf(stderr,"Alloc Failure!\n");
        return -1;
    }
    
    if( GlobalFree(moveable) != nullptr ){
        fprintf(stderr,"Free Failure!\n");
        return -1;
    }
    fprintf(stderr,"Passed\n");
    return 1; 
}
// CHECK-NOT: AddressSanitizer
// CHECK-NOT: Failure!
// CHECK-NOT: attempting free on address which was not malloc()-ed
// CHECK: Passed
