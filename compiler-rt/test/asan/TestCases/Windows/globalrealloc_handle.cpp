// UNSUPPORTED: msvc-host
// Tracked by vso1226261, ( WindowsSuite_x86chk_MD.txt WindowsSuite_x86chk_MT.txt )
#include "globallocal_shared.h"
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <windows.h>


// realloc a handle to handle path and make sure functions still work on that item.

// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_GLOBAL
// RUN: %env_asan_opts=windows_hook_legacy_allocators=true %run %t 2>&1 | FileCheck %s
// RUN: %clang_cl_asan /Od %s -Fe%t -DTEST_LOCAL
// RUN: %env_asan_opts=windows_hook_legacy_allocators=true %run %t 2>&1 | FileCheck %s

int __cdecl main() {
  HANDLE hMem = NULL;
  HANDLE hMemNew = NULL;
  DWORD cbSize = 0;
  BYTE *pGlobal;
  BYTE *pData = NULL;
  DWORD size = 0x100;
  hMem = ALLOC(MOVEABLE, size);
  pData = (BYTE *)LOCK(hMem);
  UNLOCK(hMem);
  hMemNew = REALLOC(hMem, 1, MOVEABLE | ZEROINIT);
  pGlobal = (BYTE *)LOCK(hMemNew);
  UNLOCK(hMemNew);
  FREE(hMemNew);
  printf("success\n");
}

// CHECK: success
// CHECK-NOT: AddressSanitizer
