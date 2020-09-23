#include <windows.h>
#include <winbase.h>
#include <stdlib.h>
#include <stdio.h>

// realloc a handle to handle path and make sure functions still work on that item.

// RUN: %clang_cl_asan /Od %s -Fe%t 
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run not %t 2>&1 | FileCheck %s


int __cdecl main() {
    HANDLE hMem    = NULL;
    HANDLE hMemNew = NULL;
    DWORD  cbSize = 0;
    BYTE*  pGlobal;
    DWORD size = 10;
    hMem = GlobalAlloc (GMEM_SHARE | GMEM_MOVEABLE, size);
    BYTE* old_data = (BYTE*) GlobalLock(hMem); //pre-realloc pointer
    GlobalUnlock(hMem);

    size_t size2 = size;
    do {
        size2 *= 2;
        hMemNew = GlobalReAlloc(hMem, size2,
                                GMEM_SHARE | GMEM_MOVEABLE | GMEM_ZEROINIT);
    
        pGlobal = (BYTE *)GlobalLock (hMemNew);
    } while (old_data == pGlobal);

    GlobalFree(old_data);
    printf("Failed!\n");

  

}

// CHECK-NOT: Failed!
// CHECK: AddressSanitizer: attempting double-free

