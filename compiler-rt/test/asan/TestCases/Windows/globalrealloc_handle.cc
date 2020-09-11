#include <windows.h>
#include <winbase.h>
#include <stdlib.h>

// realloc a handle to handle path and make sure functions still work on that item.

// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 | FileCheck %s

int __cdecl main() {
    HANDLE hMem    = NULL;
    HANDLE hMemNew = NULL;
    DWORD  cbSize = 0;
    BYTE*  pGlobal;
    BYTE*  pData     = NULL;
    DWORD size = 0x100;
    hMem = GlobalAlloc (GMEM_SHARE | GMEM_MOVEABLE, size);
    pData = (BYTE*) GlobalLock(hMem);
    GlobalUnlock(hMem);

    hMemNew = GlobalReAlloc(hMem, 1,
                                GMEM_SHARE | GMEM_MOVEABLE | GMEM_ZEROINIT);

    pGlobal = (BYTE *)GlobalLock (hMemNew);
    GlobalUnlock(hMemNew);
    GlobalFree(hMemNew);
    printf("success\n");
}

// CHECK: success
// CHECK-NOT: AddressSanitizer

