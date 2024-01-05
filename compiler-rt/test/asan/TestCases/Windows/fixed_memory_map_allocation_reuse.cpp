// RUN: %clang_cl_asan /Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

// CHECK: Success.
#include <Windows.h>
#include <iostream>

using AllocateFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, SIZE_T);
using FreeFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, PVOID);

// In practice, it was observed that after at least 2310292 calls
// to LocalAlloc then RtlFreeHeap will stress the FixedMemoryMap enough to
// cause an address to be resued.
constexpr int AddressWillBeReusedAfterCount = 2320000;

int main() {
  HMODULE NtDllHandle = GetModuleHandle("ntdll.dll");
  if (!NtDllHandle) {
    std::cerr << "Couldn't load ntdll" << std::endl;
    return -1;
  }

  auto RtlFreeHeap_ptr =
      (FreeFunctionPtr)GetProcAddress(NtDllHandle, "RtlFreeHeap");
  if (RtlFreeHeap_ptr == 0) {
    std::cerr << "Couldn't find RtlFreeHeap" << std::endl;
    return -1;
  }
  auto count = 0;
  while (count < AddressWillBeReusedAfterCount) {
    auto x = LocalAlloc(0, 108);
    RtlFreeHeap_ptr(GetProcessHeap(), 0, x);
    ++count;
  }
  std::cerr << "Success." << std::endl;
  return 0;
}