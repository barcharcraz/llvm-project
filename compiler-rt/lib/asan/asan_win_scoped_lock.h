#pragma once

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_mutex.h"

extern "C" unsigned long _stdcall GetCurrentThreadId();

class RecursiveScopedLock {
 public:
  explicit RecursiveScopedLock(__sanitizer::SpinMutex &_lock,
                               __sanitizer::atomic_uint32_t &_thread_id)
      : lock(_lock), thread_id(_thread_id), serialized(false) {
    if (atomic_load_relaxed(&thread_id) != GetCurrentThreadId()) {
      lock.Lock();
      atomic_store_relaxed(&thread_id, GetCurrentThreadId());
      serialized = true;
    }
  }

  ~RecursiveScopedLock() {
    if (serialized) {
      atomic_store_relaxed(&thread_id, 0);
      lock.Unlock();
    }
  }

 private:
  __sanitizer::SpinMutex &lock;
  __sanitizer::atomic_uint32_t &thread_id;
  bool serialized;
};