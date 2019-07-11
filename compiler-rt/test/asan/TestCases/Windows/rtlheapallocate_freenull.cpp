// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %env_asan_opts=windows_hook_rtl_allocators=true %run %t 2>&1 | FileCheck %s
// UNSUPPORTED: asan-64-bits

#include <stdio.h>
#include <windows.h>

using AllocateFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, SIZE_T);
using FreeFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, PVOID);

int main() {
  HMODULE NtDllHandle = GetModuleHandle("ntdll.dll");
  if (!NtDllHandle) {
    puts("Couldn't load ntdll??");
    return -1;
  }

  auto RtlFreeHeap_ptr = (FreeFunctionPtr)GetProcAddress(NtDllHandle, "RtlFreeHeap");
  if (RtlFreeHeap_ptr == 0) {
    puts("Couldn't RtlAllocateHeap");
    return -1;
  }

  RtlFreeHeap_ptr(GetProcessHeap(), 0, (void *)0);
  printf("ok!\n");
  return 0;
  // CHECK-NOT: assertion
}
