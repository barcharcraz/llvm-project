//===-- sanitizer_win_iat_protection.cpp ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between the Sanitizer run-time libraries and
// implements windows-specific functions to handle import address table
// overwrites.
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"
#if SANITIZER_WINDOWS

#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <Windows.h>

#include "sanitizer_common.h"
#include "sanitizer_win.h"
#include "sanitizer_win_defs.h"

namespace __sanitizer {

using VirtualAllocFunc = void *(WINAPI *)(void *, SIZE_T, DWORD, DWORD);
using VirtualQueryFunc = SIZE_T(WINAPI *)(const void *,
                                          PMEMORY_BASIC_INFORMATION, SIZE_T);
using VirtualProtectFunc = int(WINAPI *)(void *, SIZE_T, DWORD, DWORD *);

enum class IATOverwriteProtectionLevel { Error, Protect, Ignore };

// NOTE: The magic statics used below depend upon /Zc:threadSafeInit
// when building ASAN to force thread safe statics. If multiple threads
// end up calling these functions at the same time, the worst case
// is GetModuleHandleA or GetProcAddress will be invoked twice. Since
// neither are mutating operations, there is no issue.
static HMODULE GetKernel32() {
  static HMODULE handle = GetModuleHandleA("kernel32.dll");
  CHECK(handle);
  return handle;
}

static VirtualAllocFunc &GetVirtualAlloc() {
  static VirtualAllocFunc virtualAlloc = reinterpret_cast<VirtualAllocFunc>(
      ::GetProcAddress(GetKernel32(), "VirtualAlloc"));
  CHECK(virtualAlloc);
  return virtualAlloc;
}

static VirtualQueryFunc &GetVirtualQuery() {
  static VirtualQueryFunc virtualQuery = reinterpret_cast<VirtualQueryFunc>(
      ::GetProcAddress(GetKernel32(), "VirtualQuery"));
  CHECK(virtualQuery);
  return virtualQuery;
}

static VirtualProtectFunc &GetVirtualProtect() {
  static VirtualProtectFunc virtualProtect =
      reinterpret_cast<VirtualProtectFunc>(
          ::GetProcAddress(GetKernel32(), "VirtualProtect"));
  CHECK(virtualProtect);
  return virtualProtect;
}

static IATOverwriteProtectionLevel GetIATOverwriteProtectionLevel() {
  static const char *IATProtect = "protect";
  static const char *IATIgnore = "ignore";

  // If the flag is yet to be defined, like in the fuzzer case, default to error
  const char *iatFlag =
      common_flags()->iat_overwrite ? common_flags()->iat_overwrite : "";

  if (UNLIKELY(internal_strcmp(iatFlag, IATProtect) == 0)) {
    return IATOverwriteProtectionLevel::Protect;
  } else if (UNLIKELY(internal_strcmp(iatFlag, IATIgnore) == 0)) {
    return IATOverwriteProtectionLevel::Ignore;
  } else {
    return IATOverwriteProtectionLevel::Error;
  }
}

static bool IATOverwriteErrorDetected = false;
template <typename SanitizerFunc, typename... Args>
auto IATOverwriteError(const char *message, SanitizerFunc sanitizerFunc,
                       Args &&...args) {
  // Report will use ::Virtual* functions. When an error is detected,
  // we only want to report once, then call the correct ::Virtual*
  // to proceed with error reporting.
  if (!IATOverwriteErrorDetected) {
    IATOverwriteErrorDetected = true;
    Report(
        "ERROR: IAT overwrite detected: %s\n"
        "\nINFO:\tTo ignore IAT overwrites, set the iat_overwrite option.\n"
        "\tThe default option, \"error\" will error on detected overwrites.\n"
        "\tSetting the option to \"protect\" will attempt to correct behavior "
        "when overwrites are found.\n"
        "\tSetting the option to \"ignore\" will attempt to proceed regardless "
        "when overwrites are found.\n",
        message);
    Die();
  } else {
    return sanitizerFunc()(args...);
  }
}

template <typename SanitizerFunc, typename KernelFunc, typename... Args>
auto IATOverwriteGuard(const char *message, SanitizerFunc sanitizerFunc,
                       KernelFunc kernelFunc, Args &&...args) {
  switch (GetIATOverwriteProtectionLevel()) {
    case IATOverwriteProtectionLevel::Protect:
      return sanitizerFunc()(args...);
    case IATOverwriteProtectionLevel::Ignore:
      return kernelFunc(args...);
    case IATOverwriteProtectionLevel::Error: {
      // We should default to using the kernel32 functions
      // until the user's options have been read in as this
      // is likely being called from a sanitizer initialization
      if (UNLIKELY(!common_flags_inited)) {
        return kernelFunc(args...);
      } else {
        if (sanitizerFunc() != kernelFunc) {
          return IATOverwriteError(message, sanitizerFunc, args...);
        } else {
          return kernelFunc(args...);
        }
      }
    }
    default:
      UNREACHABLE("Unknown IAT Overwrite option");
  }
}
}  // namespace __sanitizer

extern "C" {
void *__sanitizer_virtual_alloc(void *lpAddress, SIZE_T dwSize,
                                DWORD flAllocationType, DWORD flProtect) {
  constexpr const char *errorMessage = "VirtualAlloc IAT entry overwritten.";
  return __sanitizer::IATOverwriteGuard(
      errorMessage, __sanitizer::GetVirtualAlloc, ::VirtualAlloc, lpAddress,
      dwSize, flAllocationType, flProtect);
}

SIZE_T __sanitizer_virtual_query(const void *lpAddress,
                                 PMEMORY_BASIC_INFORMATION lpBuffer,
                                 SIZE_T dwLength) {
  constexpr const char *errorMessage = "VirtualQuery IAT entry overwritten.";
  return __sanitizer::IATOverwriteGuard(
      errorMessage, __sanitizer::GetVirtualQuery, ::VirtualQuery, lpAddress,
      lpBuffer, dwLength);
}

int __sanitizer_virtual_protect(void *lpAddress, SIZE_T dwSize,
                                DWORD flNewProtect, DWORD *lpflOldProtect) {
  constexpr const char *errorMessage = "VirtualProtect IAT entry overwritten.";
  return __sanitizer::IATOverwriteGuard(
      errorMessage, __sanitizer::GetVirtualProtect, ::VirtualProtect, lpAddress,
      dwSize, flNewProtect, lpflOldProtect);
}
}
#endif  // SANITIZER_WINDOWS
