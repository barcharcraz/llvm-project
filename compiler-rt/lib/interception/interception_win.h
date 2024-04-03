//===-- interception_win.h --------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Windows-specific interception methods.
//===----------------------------------------------------------------------===//

#if SANITIZER_WINDOWS

#if !defined(INCLUDED_FROM_INTERCEPTION_LIB)
#error "interception_win.h should be included from interception library only"
#endif

#ifndef INTERCEPTION_WIN_H
#define INTERCEPTION_WIN_H

#include "sanitizer_common/sanitizer_common.h"

namespace __interception {
// All the functions in the OverrideFunction() family return true on success, false on failure (including "couldn't find the function").
// They take info about the function to intercept, including optionally its REAL address `orig_old_func`.
//   If the REAL address is not null, then it will be updated to point to the function's new address post-interception.
// Note: if a function's address was already intercepted it will *not* be re-intercepted, but the REAL address will still be updated as per-above. 
//       This scenario could occur if function `bar` aliases function `foo`: if `foo` is intercepted first, `bar` won't be intercepted, 
//       but `REAL(bar) = REAL(foo)`. In these cases, `foo` should be intercepted *first* so that `REAL(foo)` is available.

// These overloads are for intercepting functions in a specific DLL.
// If `failIfDllNotFound` is false, then we will return true if the DLL is not found.
bool OverrideFunctionForDLL(const char *func_name, uptr new_func, uptr *orig_old_func,
                            DLL dll, bool failIfDllNotFound);

// These overloads are for intercepting functions for *all* available DLLs.
// If `orig_old_func` is not null, then the real address will be updated to point to the 
// function's new address post-interception inside the *last-intercepted DLL* (VSO 1943589: this is not good, and ideally all interception
// would use the per-DLL overload above).
bool OverrideFunction(const char *func_name, uptr new_func, uptr *orig_old_func);

// This interface does not do any DLL lookup but rather overrides a function directly by its address.
bool OverrideFunction(uptr old_func, uptr new_func, uptr *orig_old_func, bool guaranteed_hotpatchable = false);

// Windows-only replacement for GetProcAddress. Useful for some sanitizers.
uptr InternalGetProcAddress(void *module, const char *func_name);

// Sets a callback to be used for reporting errors by interception_win. The
// callback will be called with printf-like arguments. Intended to be used with
// __sanitizer::Report. Pass nullptr to disable error reporting (default).
void SetErrorReportCallback(void (*callback)(const char *format, ...));

#if !SANITIZER_WINDOWS64
// Exposed for unittests
bool OverrideFunctionWithDetour(uptr old_func, uptr new_func,
                                uptr *orig_old_func);
#endif

// Exposed for unittests
bool OverrideFunctionWithRedirectJump(uptr old_func, uptr new_func,
                                      uptr *orig_old_func);
bool OverrideFunctionWithHotPatch(uptr old_func, uptr new_func,
                                  uptr *orig_old_func);
bool OverrideFunctionWithTrampoline(uptr old_func, uptr new_func,
                                    uptr *orig_old_func);

// Exposed for unittests
void TestOnlyReleaseTrampolineRegions();

}  // namespace __interception

#define INTERCEPT_FUNCTION_WIN(func)             \
      ::__interception::OverrideFunction(            \
          #func, (::__interception::uptr)WRAP(func), \
          (::__interception::uptr *)&REAL(func))

#define INTERCEPT_FUNCTION_VER_WIN(func, symver) \
      INTERCEPT_FUNCTION_WIN(func)

#endif  // INTERCEPTION_WIN_H
#endif    // SANITIZER_WINDOWS
