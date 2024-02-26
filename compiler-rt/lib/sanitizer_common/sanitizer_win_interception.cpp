//===-- sanitizer_win_interception.cpp --------------------    --*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Windows-specific export surface to provide interception for parts of the
// runtime that are always statically linked, both for overriding user-defined
// functions as well as registering weak functions that the ASAN runtime should
// use over defaults.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"
#if SANITIZER_WINDOWS
#include "interception/interception.h"
#include "sanitizer_addrhashmap.h"
#include "sanitizer_common.h"
#include "sanitizer_internal_defs.h"
#include "sanitizer_placement_new.h"
#include "sanitizer_win_immortalize.h"
#include "sanitizer_win_interception.h"

using namespace __sanitizer;

extern "C" void *__ImageBase;

namespace __sanitizer {

static uptr GetSanitizerDllExport(const char *export_name) {
  const uptr function_address =
      __interception::InternalGetProcAddress(&__ImageBase, export_name);
  if (function_address == 0) {
    Report("ERROR: Failed to find sanitizer DLL export '%s'\n", export_name);
    CHECK("Failed to find sanitizer DLL export" && 0);
  }
  return function_address;
}

struct WeakCallbackList {
  explicit constexpr WeakCallbackList(RegisterWeakFunctionCallback cb)
      : callback(cb), next(nullptr) {}

  static void *operator new(size_t size) { return InternalAlloc(size); }

  static void operator delete(void *p) { InternalFree(p); }

  RegisterWeakFunctionCallback callback;
  WeakCallbackList *next;
};
using WeakCallbackMap = AddrHashMap<WeakCallbackList *, 11>;

static WeakCallbackMap *GetWeakCallbackMap() {
  return &immortalize<WeakCallbackMap>();
}

void AddRegisterWeakFunctionCallback(uptr export_address,
                                     RegisterWeakFunctionCallback cb) {
  WeakCallbackMap::Handle h_find_or_create(GetWeakCallbackMap(), export_address,
                                           false, true);
  CHECK(h_find_or_create.exists());
  if (h_find_or_create.created()) {
    *h_find_or_create = new WeakCallbackList(cb);
  } else {
    (*h_find_or_create)->next = new WeakCallbackList(cb);
  }
}

static void RunWeakFunctionCallbacks(uptr export_address) {
  WeakCallbackMap::Handle h_find(GetWeakCallbackMap(), export_address, false,
                                 false);
  if (!h_find.exists()) {
    return;
  }

  WeakCallbackList *list = *h_find;
  do {
    list->callback();
  } while (list = list->next);
}

}  // namespace __sanitizer

DECLARE_REAL(long, strtol_static, const char *nptr, char **endptr, int base)
DECLARE_REAL(int, atoi_static, const char *nptr)
DECLARE_REAL(long, atol_static, const char *nptr)
// For the provided static interceptor (static export), if this interceptor is uniquely reserved for static interception
// (i.e., it is not also re-used as an interceptor for dynamic-linking scenarios), return the corresponding REAL pointer dedicated
// to be used only by this static interceptor. This pointer will then presumably be populated in OverrideFunction by the static interception logic.
//
// If the export is *not* unique, but gets re-used for dynamic-linking interception too, then this function will return NULL,
// and the REAL pointer that is shared by the static and dynamic interceptors is presumed to be populated by the dynamic-linking interception logic.
__interception::uptr* GetUniqueRealAddressForStaticExport(const char* export_name)
{
  struct export_to_addr {
    const char* name;
    __interception::uptr * addr;
  };
  // It is a hard-coded fact which functions have dedicated static interceptors
  static const export_to_addr exports[] = {
    { "__asan_wrap_strtol_static", (__interception::uptr *)&REAL(strtol_static) },
    { "__asan_wrap_atoi_static", (__interception::uptr *)&REAL(atoi_static) },
    { "__asan_wrap_atol_static", (__interception::uptr *)&REAL(atol_static) },
  };

  for (const auto& e : exports) {
    if (!internal_strcmp(export_name, e.name)) {
      return e.addr;
    }
  }

  return nullptr;
}

extern "C" __declspec(dllexport) bool __cdecl __sanitizer_override_function(
    const char *export_name, const uptr user_function,
    uptr *const old_user_function) {
  CHECK(export_name);
  CHECK(user_function);

  const uptr sanitizer_function = GetSanitizerDllExport(export_name);

  // If the export is unique to static interception, then we will use a dedicated REAL pointer for this static interceptor.
  // Otherwise, the caller has the option to pass in the REAL pointer via old_user_function.
  uptr * real_address = GetUniqueRealAddressForStaticExport(export_name);
  if (!real_address)
    real_address = old_user_function;
  else
    CHECK(!old_user_function && "old_user_function is not null but function has a dedicated static interceptor");

  // If GetUniqueRealAddressForStaticExport returns nullptr, then the REAL pointer will *not* be updated, and is assumed to be be
  // set during interception for DLLs. Strictly speaking this means that the REAL function for static and dynamic linking
  // will be shared. This is currently the case for most functions, and should be fixed in the future.
  const bool function_overridden = __interception::OverrideFunction(
      user_function, sanitizer_function, real_address);
  if (!function_overridden) {
    Report(
        "ERROR: Failed to override local function at '%p' with sanitizer "
        "function '%s'\n",
        user_function, export_name);
    CHECK("Failed to replace local function with sanitizer version." && 0);
  }

  return function_overridden;
}

extern "C" __declspec(dllexport) bool __cdecl __sanitizer_override_function_by_addr(
    const uptr source_function, const uptr target_function,
    uptr *const old_target_function) {
  CHECK(source_function);
  CHECK(target_function);

  const bool function_overridden = __interception::OverrideFunction(
      target_function, source_function, old_target_function);
  if (!function_overridden) {
    Report(
        "ERROR: Failed to override function at '%p' with function at "
        "'%p'\n",
        target_function, source_function);
    CHECK("Failed to apply function override." && 0);
  }

  return function_overridden;
}

extern "C" __declspec(dllexport) bool __cdecl __sanitizer_register_weak_function(
    const char *export_name, const uptr user_function,
    uptr *const old_user_function) {
  CHECK(export_name);
  CHECK(user_function);

  const uptr sanitizer_function = GetSanitizerDllExport(export_name);

  const bool function_overridden = __interception::OverrideFunction(
      sanitizer_function, user_function, old_user_function);
  if (!function_overridden) {
    Report(
        "ERROR: Failed to register local function at '%p' to be used in "
        "place of sanitizer function '%s'\n.",
        user_function, export_name);
    CHECK("Failed to register weak function." && 0);
  }

  // Note that thread-safety of RunWeakFunctionCallbacks in InitializeFlags
  // depends on __sanitizer_register_weak_functions being called during the
  // loader lock.
  RunWeakFunctionCallbacks(sanitizer_function);

  return function_overridden;
}

#endif  // SANITIZER_WINDOWS
