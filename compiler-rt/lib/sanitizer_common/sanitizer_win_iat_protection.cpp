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

#  define WIN32_LEAN_AND_MEAN
#  define NOGDI
#  include <Windows.h>

#  include "sanitizer_common.h"
#  include "sanitizer_type_traits.h"
#  include "sanitizer_win.h"
#  include "sanitizer_win_defs.h"

namespace __sanitizer {

using VirtualAllocFunc = LPVOID(WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualQueryFunc = SIZE_T(WINAPI *)(LPCVOID, PMEMORY_BASIC_INFORMATION,
                                          SIZE_T);
using VirtualProtectFunc = int(WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD);

enum class IATOverwriteProtectionLevel { Error, Protect, Ignore };
constexpr const char *VirtualAllocStr = "VirtualAlloc";
constexpr const char *VirtualProtectcStr = "VirtualProtect";
constexpr const char *VirtualQueryStr = "VirtualQuery";

struct Kernel32 {
  static constexpr const char *Name = "kernel32.dll";
};

struct KernelBase {
  static constexpr const char *Name = "kernelbase.dll";
};

template <typename CoreLibrary>
struct CoreLibraryFunctions {
  CoreLibraryFunctions() {
    HMODULE mod = GetModuleHandleA(CoreLibrary::Name);
    CHECK(mod);

    VirtualAlloc = reinterpret_cast<VirtualAllocFunc>(
        ::GetProcAddress(mod, VirtualAllocStr));
    CHECK(VirtualAlloc);

    VirtualProtect = reinterpret_cast<VirtualProtectFunc>(
        ::GetProcAddress(mod, VirtualProtectcStr));
    CHECK(VirtualProtect);

    VirtualQuery = reinterpret_cast<VirtualQueryFunc>(
        ::GetProcAddress(mod, VirtualQueryStr));
    CHECK(VirtualQuery);
  }

  template <typename Function>
  constexpr auto GetFunction() {
    if constexpr (__sanitizer::is_same<Function,
                                       decltype(::VirtualAlloc)>::value) {
      return VirtualAlloc;
    } else if constexpr (__sanitizer::is_same<
                             Function, decltype(::VirtualProtect)>::value) {
      return VirtualProtect;
    } else if constexpr (__sanitizer::is_same<
                             Function, decltype(::VirtualQuery)>::value) {
      return VirtualQuery;
    }
  }

  VirtualAllocFunc VirtualAlloc;
  VirtualProtectFunc VirtualProtect;
  VirtualQueryFunc VirtualQuery;
};

// NOTE: Thread safe initialization for static locals is disabled
// ( /Zc:threadSafeInit- ) when building ASAN. If multiple threads end up
// calling these functions at the same time, the worst case is GetModuleHandleA
// or GetProcAddress will be invoked twice. Since neither are mutating
// operations, there is no issue.
template <typename Module>
auto GetCoreLibraryFunctions() {
  static CoreLibraryFunctions<Module> functions;
  return functions;
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
template <typename Function, typename... Args>
auto IATOverwriteError(const char *message, Function resolvedFunction,
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
  }
  return resolvedFunction(args...);
}

template <typename CoreLibrary, typename Function>
constexpr auto GetCoreLibraryFunction() {
  return GetCoreLibraryFunctions<CoreLibrary>().GetFunction<Function>();
}

template <typename Function, typename... Args>
auto IATOverwriteGuard(const char *message, Function resolvedFunction,
                       Args &&...args) {
  switch (GetIATOverwriteProtectionLevel()) {
    case IATOverwriteProtectionLevel::Protect: {
      // kernelbase.dll should always be present, so looking up the function
      // using GetProcAddress should provide the correct call to use
      return GetCoreLibraryFunction<KernelBase, Function>()(args...);
    }
    case IATOverwriteProtectionLevel::Ignore: {
      return resolvedFunction(args...);
    }
    case IATOverwriteProtectionLevel::Error: {
      // We should default to using the kernel functions
      // until the user's options have been read in as this
      // is likely being called from a sanitizer initialization
      if (UNLIKELY(!common_flags_inited)) {
        return resolvedFunction(args...);
      } else {
        if (auto kernelBaseFunction =
                GetCoreLibraryFunction<KernelBase, Function>();
            GetCoreLibraryFunction<Kernel32, Function>() == resolvedFunction ||
            kernelBaseFunction == resolvedFunction) {
          return resolvedFunction(args...);
        } else {
          return IATOverwriteError(message, kernelBaseFunction, args...);
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
  return __sanitizer::IATOverwriteGuard<decltype(::VirtualAlloc)>(
      errorMessage, ::VirtualAlloc, lpAddress, dwSize, flAllocationType,
      flProtect);
}

SIZE_T __sanitizer_virtual_query(const void *lpAddress,
                                 PMEMORY_BASIC_INFORMATION lpBuffer,
                                 SIZE_T dwLength) {
  constexpr const char *errorMessage = "VirtualQuery IAT entry overwritten.";
  return __sanitizer::IATOverwriteGuard<decltype(::VirtualQuery)>(
      errorMessage, ::VirtualQuery, lpAddress, lpBuffer, dwLength);
}

int __sanitizer_virtual_protect(void *lpAddress, SIZE_T dwSize,
                                DWORD flNewProtect, DWORD *lpflOldProtect) {
  constexpr const char *errorMessage = "VirtualProtect IAT entry overwritten.";
  return __sanitizer::IATOverwriteGuard<decltype(::VirtualProtect)>(
      errorMessage, ::VirtualProtect, lpAddress, dwSize, flNewProtect,
      lpflOldProtect);
}
}
#endif  // SANITIZER_WINDOWS
