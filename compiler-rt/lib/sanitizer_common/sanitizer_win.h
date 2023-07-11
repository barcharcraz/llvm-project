//===-- sanitizer_win.h -----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Windows-specific declarations.
//
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_WIN_H
#define SANITIZER_WIN_H

#include "sanitizer_platform.h"
#if SANITIZER_WINDOWS
#include "sanitizer_internal_defs.h"

// Typedef for VirtualQuery to avoid including windows headers
typedef struct _MEMORY_BASIC_INFORMATION* PMemory_Basic_Information;

namespace __sanitizer {
// Check based on flags if we should handle the exception.
bool IsHandledDeadlyException(DWORD exceptionCode);

// Checks ProcessEnvironmentBlock's IsShutdownInProgress to determine if
// sanitizer runtime operations should continue normal intercepted execution or
// not during process termination. Currently, only the Windows implementation
// relies on this function for preventing deadlocks on process termination.
bool IsProcessTerminating();

// Checks whether a user-space debugger is present, and if so,
// whether the user has not disabled special debugger behaviour by setting the
// %ASAN_DEBUGGING% environment variable to 0, no, or false.
bool IsInDebugger();

// Checks if the address is part of a memory mapping.
bool IsMemoryMapped(void* Handle);

// Initializes module information of ntdll for referencing callee addresses
void InitializeNtdllInfo();

// Returns whether or not the callee address lies within ntdll
bool IsNtdllCallee(void* calleeAddr);

}  // namespace __sanitizer

extern "C" {

// If memoryapi.h functions are hooked by overwriting the Import Address Table
// (IAT), Sanitizers need to be able to still call the original functions
// located in kernel32.dll. The iat_overwrite runtime option specifies the
// protection level to proceed with. 
// error: default protect level, which means error when an overwrite is detected. 
// protect: attempt to proceed by looking up the original address of the function
//          that had its IAT entry overwritten and calling it rather than the
//          replacement function.
// ignore: attempt to proceed by ignoring IAT overwrites and calling the
// function that is resolved on an invocation to func()
//
// VirtualAlloc, VirtualQuery, and VirtualProtect are currently protected from
// this behavior if iat_overwrite=protect
SANITIZER_INTERFACE_ATTRIBUTE void* __sanitizer_virtual_alloc(
    void* lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
SANITIZER_INTERFACE_ATTRIBUTE SIZE_T __sanitizer_virtual_query(
    const void* lpAddress, PMemory_Basic_Information lpBuffer, SIZE_T dwLength);
SANITIZER_INTERFACE_ATTRIBUTE int __sanitizer_virtual_protect(
    void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect);
}

#endif  // SANITIZER_WINDOWS
#endif  // SANITIZER_WIN_H
