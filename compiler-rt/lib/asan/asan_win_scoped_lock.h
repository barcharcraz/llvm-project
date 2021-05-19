#pragma once

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_mutex.h"

extern "C" unsigned long _stdcall GetCurrentThreadId();

class RecursiveScopedLock {
 public:
  explicit RecursiveScopedLock(__sanitizer::SpinMutex &_lock,
                               __sanitizer::atomic_uint32_t &_thread_id)
      : lock(_lock), thread_id(_thread_id), serialized(false) {
    if (atomic_load(&thread_id, __sanitizer::memory_order_seq_cst) !=
        GetCurrentThreadId()) {
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

 private:
  __sanitizer::SpinMutex &lock;
  __sanitizer::atomic_uint32_t &thread_id;
  bool serialized;
};