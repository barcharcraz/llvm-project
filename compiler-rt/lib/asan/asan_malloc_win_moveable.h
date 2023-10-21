//===-- asan_malloc_win_moveable.h ----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Moveable heap allocation manager for Global/Local Alloc interception.
//===----------------------------------------------------------------------===//
#pragma once

#include "sanitizer_common/sanitizer_win_defs.h"

#define FIXED 0x0000
#define ZEROINIT 0x0040
#define MOVEABLE 0x0002
#define MODIFY 0x0080
#define NOCOMPACT 0x0010
#define NODISCARD 0x0020
#define LOCAL_DISCARDABLE 0x0F00
#define GLOBAL_DISCARDABLE 0x0100
#define GLOBAL_NOT_BANKED 0x1000
#define GLOBAL_SHARE 0x2000  // same as GMEM_DDESHARE and SHARE
#define GLOBAL_NOTIFY 0x4000
#define INVALID_HANDLE 0x8000
#define GLOBAL_VALID_FLAGS 0x7F72
#define LOCAL_VALID_FLAGS 0x0F72

#define ERROR_OUTOFMEMORY 0xE
#define NO_ERROR 0
#define ERROR_NOT_LOCKED 0x9E
#define ERROR_INVALID_HANDLE 0x6

#define GMEM_LOCKCOUNT 0x00FF
#define GMEM_DISCARDED 0x4000

namespace __sanitizer {
    struct BufferedStackTrace;
}

using GlobalLocalLock = void*(WINAPI *)(void*);
using GlobalLocalUnlock = int(WINAPI *)(void*);

namespace __asan_win_moveable {
enum class HeapCaller { GLOBAL, LOCAL };

bool IsOwned(void *item);
void *ResolvePointerToHandle(void *item, __sanitizer::BufferedStackTrace&);
size_t GetAllocationSize(void *item, __sanitizer::BufferedStackTrace&);
void *IncrementLockCount(void *item, GlobalLocalLock, __sanitizer::BufferedStackTrace&);
bool DecrementLockCount(void *item, GlobalLocalUnlock, __sanitizer::BufferedStackTrace&);
void *Free(void *item, __sanitizer::BufferedStackTrace&);
void *Alloc(unsigned long flags, size_t size, __sanitizer::BufferedStackTrace&);
void *ReAllocate(void *item, unsigned long flags, size_t size, HeapCaller caller, __sanitizer::BufferedStackTrace&);
unsigned int Flags(void *item, __sanitizer::BufferedStackTrace&); 
}  // namespace __asan_win_moveable
