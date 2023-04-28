#include "sanitizer\allocator_interface.h"
#include <cassert>
#include <stdio.h>
#include <windows.h>
#include "../defines.h"


// RUN: %clang_cl_asan %s -o%t
// RUN: %run %t 2>&1 | FileCheck %s

using AllocateFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, SIZE_T);
using ReAllocateFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, PVOID, SIZE_T);

using FreeFunctionPtr = PVOID(__stdcall *)(PVOID, ULONG, PVOID);

int main() {
  HMODULE NtDllHandle = GetModuleHandle("ntdll.dll");
  if (!NtDllHandle) {
    puts("Couldn't load ntdll??");
    return -1;
  }

  auto RtlAllocateHeap_ptr = (AllocateFunctionPtr)GetProcAddress(NtDllHandle, "RtlAllocateHeap");
  if (RtlAllocateHeap_ptr == 0) {
    puts("Couldn't find RtlAllocateHeap");
    return -1;
  }

  auto RtlReAllocateHeap_ptr = (ReAllocateFunctionPtr)GetProcAddress(NtDllHandle, "RtlReAllocateHeap");
  if (RtlReAllocateHeap_ptr == 0) {
    puts("Couldn't find RtlReAllocateHeap");
    return -1;
  }

  //owned by rtl
  void *alloc = RtlAllocateHeap_ptr(GetProcessHeap(),
                                    HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, 100);
  assert(alloc);
  for (int i = 0; i < 100; i++) {
    assert(((char *)alloc)[i] == 0);
    ((char *)alloc)[i] = '\xcc';
  }

  // still owned by rtl
  alloc = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, alloc, 500);
  assert(alloc && !__sanitizer_get_ownership(alloc) && HeapValidate(GetProcessHeap(), 0, alloc));
  for (int i = 0; i < 100; i++) {
    assert(((char *)alloc)[i] == '\xcc');
  }
  for (int i = 100; i < 500; i++) {
    assert(((char *)alloc)[i] == 0);
    ((char *)alloc)[i] = '\xcc';
  }

  //convert to asan owned
  void *realloc = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                        HEAP_ZERO_MEMORY, alloc, 600);
  alloc = nullptr;
  assert(realloc && __sanitizer_get_ownership(realloc));

  for (int i = 0; i < 500; i++) {
    assert(((char *)realloc)[i] == '\xcc');
  }
  for (int i = 500; i < 600; i++) {
    assert(((char *)realloc)[i] == 0);
    ((char *)realloc)[i] = '\xcc';
  }
  realloc = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                  HEAP_ZERO_MEMORY, realloc, 2048);
  assert(realloc && __sanitizer_get_ownership(realloc));

  for (int i = 0; i < 600; i++) {
    assert(((char *)realloc)[i] == '\xcc');
  }
  for (int i = 600; i < 2048; i++) {
    assert(((char *)realloc)[i] == 0);
    ((char *)realloc)[i] = '\xcc';
  }
  //convert back to rtl owned;
  alloc = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, realloc, 100);
  assert(alloc && !__sanitizer_get_ownership(alloc) && HeapValidate(GetProcessHeap(), 0, alloc));
  for (int i = 0; i < 100; i++) {
    assert(((char *)alloc)[i] == '\xcc');
    ((char *)alloc)[i] = 0;
  }

  auto usable_size = HeapSize(GetProcessHeap(), 0, alloc);
  for (int i = 100; i < usable_size; i++) {
    assert(((char *)alloc)[i] == 0);
  }

  // HEAP_REALLOC_IN_PLACE_ONLY
  // convert back to ASAN owned
  realloc = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                        HEAP_ZERO_MEMORY, alloc, 600);
  auto SizeNeeded = 10000; // Just way larger than before

  // This should return nullptr, similar to RtlReAllocateHeap
  auto ReallocResult = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                      HEAP_REALLOC_IN_PLACE_ONLY,
                                      realloc,
                                      SizeNeeded);
  assert(!ReallocResult && !__sanitizer_get_ownership(ReallocResult));

  // Allocate a new buffer, which ASAN will own
  ReallocResult = RtlAllocateHeap_ptr(GetProcessHeap(), 0, SizeNeeded);

  auto sizeBeforeCalls = __sanitizer_get_allocated_size(ReallocResult);

  // TODO: BUG #1802790
  // This isn't exactly correct behavior. If ASAN owns the heap, and a user calls
  // RtlReAllocateHeap with a size smaller than what is currently allocated, ASAN
  // should be shrinking the heap in place and adjusting poisoning. However, currently
  // no change should happen if we pass in same size
  auto ReallocResultNoChange = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                      HEAP_REALLOC_IN_PLACE_ONLY,
                                      ReallocResult,
                                      SizeNeeded);
  assert(ReallocResultNoChange && __sanitizer_get_ownership(ReallocResultNoChange));
  assert(ReallocResultNoChange == ReallocResult);
  assert(sizeBeforeCalls == __sanitizer_get_allocated_size(ReallocResult));

  // Same as above, no change should happen if we pass in smaller size
  ReallocResultNoChange = RtlReAllocateHeap_ptr(GetProcessHeap(),
                                      HEAP_REALLOC_IN_PLACE_ONLY,
                                      ReallocResult,
                                      SizeNeeded - (SizeNeeded / 2));
  assert(ReallocResultNoChange && __sanitizer_get_ownership(ReallocResultNoChange));
  assert(ReallocResultNoChange == ReallocResult);
  assert(sizeBeforeCalls == __sanitizer_get_allocated_size(ReallocResult));

  printf("Success\n");
}

// CHECK-NOT: Assertion failed:
// CHECK-NOT: AddressSanitizer
// CHECK: Success
