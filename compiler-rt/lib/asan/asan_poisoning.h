//===-- asan_poisoning.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Shadow memory poisoning by ASan RTL and by user application.
//===----------------------------------------------------------------------===//

#include "asan_interceptors.h"
#include "asan_internal.h"
#include "asan_mapping.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_platform.h"

#if SANITIZER_WINDOWS64
#include "sanitizer_common/sanitizer_win.h"
#include "sanitizer_common/sanitizer_win_defs.h"
// These definitions are duplicated from Window.h in order to avoid conflicts
// with other types in Windows.h.
// These functions and types are used to manipulate the shadow memory on
// x64 Windows.
typedef unsigned long DWORD;
typedef void *LPVOID;
typedef int BOOL;

constexpr DWORD MEM_COMMIT = 0x00001000;
constexpr DWORD MEM_DECOMMIT = 0x00004000;
constexpr DWORD PAGE_READWRITE = 0x04;

extern "C" LPVOID WINAPI VirtualAlloc(LPVOID, size_t, DWORD, DWORD);
extern "C" BOOL WINAPI VirtualFree(LPVOID, size_t, DWORD);
#endif

namespace __asan {

// Enable/disable memory poisoning.
void SetCanPoisonMemory(bool value);
bool CanPoisonMemory();

// Poisons the shadow memory for "size" bytes starting from "addr".
void PoisonShadow(uptr addr, uptr size, u8 value);

// Poisons the shadow memory for "redzone_size" bytes starting from
// "addr + size".
void PoisonShadowPartialRightRedzone(uptr addr, uptr size, uptr redzone_size,
                                     u8 value);

// Commits the shadow memory for a range of aligned memory. This only matters
// on 64-bit Windows where relying on pages to get paged in on access
// violation is inefficient when we know the memory range ahead of time.
ALWAYS_INLINE void CommitShadowMemory(uptr aligned_beg, uptr aligned_size) {
#if SANITIZER_WINDOWS64
  uptr shadow_beg = MEM_TO_SHADOW(aligned_beg);
  uptr shadow_end =
      MEM_TO_SHADOW(aligned_beg + aligned_size - ASAN_SHADOW_GRANULARITY) + 1;
  __sanitizer_virtual_alloc((LPVOID)shadow_beg,
                                     (size_t)(shadow_end - shadow_beg),
                                     MEM_COMMIT, PAGE_READWRITE);
#endif
}

// Fast versions of PoisonShadow and PoisonShadowPartialRightRedzone that
// assume that memory addresses are properly aligned. Use in
// performance-critical code with care.
ALWAYS_INLINE void FastPoisonShadow(uptr aligned_beg, uptr aligned_size,
                                    u8 value) {
  DCHECK(!value || CanPoisonMemory());
#if SANITIZER_FUCHSIA
  __sanitizer_fill_shadow(aligned_beg, aligned_size, value,
                          common_flags()->clear_shadow_mmap_threshold);
#else
  uptr shadow_beg = MEM_TO_SHADOW(aligned_beg);
  uptr shadow_end =
      MEM_TO_SHADOW(aligned_beg + aligned_size - ASAN_SHADOW_GRANULARITY) + 1;
  // Windows has a similar ability to mmap page zeroing that is used for posix
  // systems here via decomitting and recomitting virtual pages. However, it
  // is unclear that the benefits of such a strategy are worth it, as the
  // zero pages will end up getting lazily backed by real resources once a
  // write to them occurs. (e.g. on quarantine/free). We've likely just gone
  // through the effort of comitting and poisoning these pages on allocation,
  // which will have caused the system to back them with real resources. Let's
  // not double that work. Also, memset is pretty fast.
  if (value || SANITIZER_WINDOWS ||
      shadow_end - shadow_beg < common_flags()->clear_shadow_mmap_threshold) {
    REAL(memset)((void*)shadow_beg, value, shadow_end - shadow_beg);
  } else {
    uptr page_size = GetPageSizeCached();
    uptr page_beg = RoundUpTo(shadow_beg, page_size);
    uptr page_end = RoundDownTo(shadow_end, page_size);

    if (page_beg >= page_end) {
      REAL(memset)((void *)shadow_beg, 0, shadow_end - shadow_beg);
    } else {
      if (page_beg != shadow_beg) {
        REAL(memset)((void *)shadow_beg, 0, page_beg - shadow_beg);
      }
      if (page_end != shadow_end) {
        REAL(memset)((void *)page_end, 0, shadow_end - page_end);
      }
      ReserveShadowMemoryRange(page_beg, page_end - 1, nullptr);
    }
  }
#endif  // SANITIZER_FUCHSIA
}

ALWAYS_INLINE void FastPoisonShadowPartialRightRedzone(uptr aligned_addr,
                                                       uptr size,
                                                       uptr redzone_size,
                                                       u8 value) {
  DCHECK(CanPoisonMemory());
  bool poison_partial = flags()->poison_partial;
  u8 *shadow = (u8*)MEM_TO_SHADOW(aligned_addr);
  for (uptr i = 0; i < redzone_size; i += ASAN_SHADOW_GRANULARITY, shadow++) {
    if (i + ASAN_SHADOW_GRANULARITY <= size) {
      *shadow = 0;  // fully addressable
    } else if (i >= size) {
      *shadow =
          (ASAN_SHADOW_GRANULARITY == 128) ? 0xff : value;  // unaddressable
    } else {
      // first size-i bytes are addressable
      *shadow = poison_partial ? static_cast<u8>(size - i) : 0;
    }
  }
}

// Calls __sanitizer::ReleaseMemoryPagesToOS() on
// [MemToShadow(p), MemToShadow(p+size)].
void FlushUnneededASanShadowMemory(uptr p, uptr size);

}  // namespace __asan
