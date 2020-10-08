//===-- asan_win_immortalize.cpp ------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Windows-specific thread-safe and pre-CRT global initialization safe
// infrastructure to create an object whose destructor is never called.
//===----------------------------------------------------------------------===//
#include "sanitizer_common/sanitizer_win_defs.h"

// These types are required to satisfy XFG which requires that the names of the
// types for indirect calls to be correct as well as the name of the original
// type for any typedefs.
typedef union _RTL_RUN_ONCE* PINIT_ONCE;
typedef void* PVOID;
typedef int BOOL;

extern "C" {
_declspec(dllimport) int WINAPI
    InitOnceExecuteOnce(void**, BOOL(WINAPI*)(PINIT_ONCE, PVOID, PVOID*), void*,
                        void*);
}

void* operator new(size_t, void* ptr) { return ptr; }

template <class Ty>
BOOL WINAPI immortalize_impl(PINIT_ONCE, PVOID storage_ptr, PVOID*) noexcept {
  ::new (storage_ptr) Ty();
  return 1;
}

template <class Ty>
Ty& immortalize() {  // return a reference to an object that will live forever
  static void* flag;
  alignas(Ty) static unsigned char storage[sizeof(Ty)];

  InitOnceExecuteOnce(&flag, immortalize_impl<Ty>, &storage, nullptr);
  return reinterpret_cast<Ty&>(storage);
}
