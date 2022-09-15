//===-- sanitizer_win_dll_thunk.cpp ---------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// This file defines a family of thunks that should be statically linked into
// the DLLs that have instrumentation in order to delegate the calls to the
// shared runtime that lives in the main binary.
// See https://github.com/google/sanitizers/issues/209 for the details.
//===----------------------------------------------------------------------===//

#ifdef SANITIZER_DLL_THUNK
#include "sanitizer_win_defs.h"
#include "sanitizer_win_dll_thunk.h"
#include "interception/interception.h"

extern "C" {
void *WINAPI GetModuleHandleA(const char *module_name);
void abort();
}

namespace __sanitizer {
uptr dllThunkGetRealAddrOrDie(const char *name) {
  uptr ret =
      __interception::InternalGetProcAddress((void *)GetModuleHandleA(0), name);
  if (!ret)
    abort();
  return ret;
}

int dllThunkIntercept(const char* main_function, uptr dll_function) {
  uptr wrapper = dllThunkGetRealAddrOrDie(main_function);
  if (!__interception::OverrideFunction(dll_function, wrapper, 0))
    abort();
  return 0;
}

int dllThunkInterceptWhenPossible(const char* main_function,
    const char* default_function, uptr dll_function) {
  uptr wrapper = __interception::InternalGetProcAddress(
    (void *)GetModuleHandleA(0), main_function);
  if (!wrapper)
    wrapper = dllThunkGetRealAddrOrDie(default_function);
  if (!__interception::OverrideFunction(dll_function, wrapper, 0))
    abort();
  return 0;
}
} // namespace __sanitizer

// Include Sanitizer Common interface.
#define INTERFACE_FUNCTION(Name) INTERCEPT_SANITIZER_FUNCTION(Name)
#define INTERFACE_WEAK_FUNCTION(Name) INTERCEPT_SANITIZER_WEAK_FUNCTION(Name)
#include "sanitizer_common_interface.inc"

// Defined for thunk interception of memoryapi.h functions
// to protect from IAT overwrites. These functions can be called
// prior to and during __dll_thunk_init, meaning we cannot use
// INTERFACE_FUNCTION here.
extern "C" {
void *__sanitizer_virtual_alloc(void *arg1, SIZE_T arg2, DWORD arg3, DWORD arg4) {
  using fntype = void*(*)(void*,SIZE_T,DWORD,DWORD);
  static fntype fn =
      (fntype)__sanitizer::dllThunkGetRealAddrOrDie("__sanitizer_virtual_alloc");
  return fn(arg1, arg2, arg3, arg4);
}

typedef struct _MEMORY_BASIC_INFORMATION* PMemory_Basic_Information;
SIZE_T __sanitizer_virtual_query(const void *arg1, PMemory_Basic_Information arg2,
                             SIZE_T arg3) {
  using fntype = SIZE_T(*)(const void*, PMemory_Basic_Information, SIZE_T);
  static fntype fn =
      (fntype)__sanitizer::dllThunkGetRealAddrOrDie("__sanitizer_virtual_query");
  return fn(arg1, arg2, arg3);
}

int __sanitizer_virtual_protect(void *arg1, SIZE_T arg2, DWORD arg3, DWORD *arg4) {
  using fntype = int(*)(void*, SIZE_T, DWORD, DWORD*);
  static fntype fn =
      (fntype)__sanitizer::dllThunkGetRealAddrOrDie("__sanitizer_virtual_protect");
  return fn(arg1, arg2, arg3, arg4);
}
}

#pragma section(".DLLTH$A", read)
#pragma section(".DLLTH$Z", read)

typedef void (*DllThunkCB)();
extern "C" {
__declspec(allocate(".DLLTH$A")) DllThunkCB __start_dll_thunk;
__declspec(allocate(".DLLTH$Z")) DllThunkCB __stop_dll_thunk;
}

// Disable compiler warnings that show up if we declare our own version
// of a compiler intrinsic (e.g. strlen).
#pragma warning(disable: 4391)
#pragma warning(disable: 4392)

extern "C" int __dll_thunk_init() {
  static bool flag = false;
  // __dll_thunk_init is expected to be called by only one thread.
  if (flag) return 0;
  flag = true;

  for (DllThunkCB *it = &__start_dll_thunk; it < &__stop_dll_thunk; ++it)
    if (*it)
      (*it)();

  // In DLLs, the callbacks are expected to return 0,
  // otherwise CRT initialization fails.
  return 0;
}

// We want to call dll_thunk_init before C/C++ initializers / constructors are
// executed, otherwise functions like memset might be invoked.
#pragma section(".CRT$XIB", long, read)
__declspec(allocate(".CRT$XIB")) int (*__dll_thunk_preinit)() =
    __dll_thunk_init;

static void WINAPI dll_thunk_thread_init(void *mod, unsigned long reason,
                                         void *reserved) {
  if (reason == /*DLL_PROCESS_ATTACH=*/1) __dll_thunk_init();
}

#pragma section(".CRT$XLAB", long, read)
__declspec(allocate(".CRT$XLAB")) void (WINAPI *__dll_thunk_tls_init)(void *,
    unsigned long, void *) = dll_thunk_thread_init;

#endif // SANITIZER_DLL_THUNK
