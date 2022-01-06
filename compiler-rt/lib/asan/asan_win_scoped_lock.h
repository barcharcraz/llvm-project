//===-- asan_win_scoped_lock.h --------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// RAII lock used exclusively by Windows-specific parts of ASan
//===----------------------------------------------------------------------===//
#if SANITIZER_WINDOWS
#pragma once

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_mutex.h"

extern "C" unsigned long _stdcall GetCurrentThreadId();

class RecursiveScopedLock {
 public:
  bool serialized = false;

  RecursiveScopedLock(__sanitizer::SpinMutex &_lock,
                      __sanitizer::atomic_uint32_t &_thread_id)
      : lock(_lock), thread_id(_thread_id), serialized(false) {
    // Save thread id as local volatile so it is captured in minidumps to aid
    // debugging.
    volatile __sanitizer::u32 saved_thread_id =
        atomic_load(&thread_id, __sanitizer::memory_order_seq_cst);
    if (saved_thread_id != GetCurrentThreadId()) {
      serialized = true;
      lock.Lock();
      atomic_store(&thread_id, GetCurrentThreadId(),
                   __sanitizer::memory_order_relaxed);
    }
  }

  ~RecursiveScopedLock() {
    if (serialized) {
      atomic_store(&thread_id, 0, __sanitizer::memory_order_seq_cst);
      lock.Unlock();
    }
  }

  RecursiveScopedLock(RecursiveScopedLock &&rhs)
      : lock(rhs.lock), thread_id(rhs.thread_id), serialized(rhs.serialized) {
    rhs.serialized = false;
  }

  RecursiveScopedLock &operator=(RecursiveScopedLock &&) = delete;
  RecursiveScopedLock(const RecursiveScopedLock &) = delete;
  RecursiveScopedLock &operator=(const RecursiveScopedLock &) = delete;

 private:
  __sanitizer::SpinMutex &lock;
  __sanitizer::atomic_uint32_t &thread_id;
};

#endif  // SANITIZER_WINDOWS
