#include <windows.h>
#include <winbase.h>
#include <stdlib.h>
#include <stdio.h>
#include "globallocal_shared.h"

// realloc a handle to handle path and make sure functions still work on that item.

// RUN: %clang_cl_asan /Od %s -Fe%t 
// RUN: %run not %t 2>&1 | FileCheck %s

// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: %run not %t 2>&1 | FileCheck %s

int __cdecl main() {
    HANDLE hMem    = NULL;
    HANDLE hMemNew = NULL;
    DWORD  cbSize = 0;
    BYTE*  pGlobal;
    DWORD size = 10;
    hMem = ALLOC (MOVEABLE, size);
    BYTE* old_data = (BYTE*) LOCK(hMem); //pre-realloc pointer
    UNLOCK(hMem);

    size_t size2 = size;
    do {
        size2 *= 2;
        hMemNew = REALLOC(hMem, size2, MOVEABLE | ZEROINIT);
        pGlobal = (BYTE *)LOCK(hMemNew);
    } while (old_data == pGlobal);

    FREE(old_data);
    printf("Failed!\n");

  

}

// CHECK-NOT: Failed!
// CHECK: AddressSanitizer: attempting double-free

