// MSVC-DISABLED: Flaky due to timing and unable to stop test on CI

// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t

// This test attempts to create a dead lock situation between the Win32 Heap Lock and the
// locks taken inside of the ASAN implementations for the RTL allocations/deallocation functions.
// The Win32 Heap lock can be locked or unlocked when calling any of the Heap allocation/deallocation functions,
// so our implementation must never try to take the Win32 Heap lock (which we do to walk the heap) while holding
// any other lock.
// Because this test is trying to recreate a deadlock and may return true on a re-run, any failure should be investigated.

// clang-format off
// Deadlock example (when Heaplock taken under AsanLock)
//
//               locked_thread +                + active_thread
//                             |                |
//                             |                | __asan_wrap_RtlAllocateHeap
//                             |                |
//                             | switch threads | RecursiveScopedLock
//                             <----------------+ (AsanLock)
//                    HeapLock |                |
// __asan_wrap_RtlAllocateHeap |                |
//                             | locked_thread  |
//         RecursiveScopedLock | can't progress |
//                 (ASAN lock) +----------------> HeapLock
//                             |                | active_thread can't progress
//                             +                +
// clang-format on

#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// The test works better the longer it runs, but goes very slowly on test machines and will likely hit the timeout.
// Practically, this will not catch a deadlock every time, but over multiple runs it should, or with local runs.
const DWORD timeout_in_milliseconds = 1000 * 60 * 15; // 15 minutes
const uint64_t no_progress_iterations_in_a_row_to_fail = 1000;
const uint64_t max_successful_iterations = 10000;

uint64_t successful_iterations = 0;
uint64_t max_no_progress_streak = 0;
uint64_t no_progress_iterations_count = 0;
uint64_t num_iters = 0;

[[noreturn]] DWORD WINAPI thread_proc(void *param) {
  HANDLE proc_heap = GetProcessHeap();
  const bool should_lock = reinterpret_cast<void *>(true) == param;

  if (should_lock) {
    HeapLock(proc_heap);
  }

  while (true) {
    ++num_iters;
    void *mem = HeapAlloc(proc_heap, 0, 1024);
    void *mem2 = HeapReAlloc(proc_heap, 0, mem, 2048);
    HeapFree(proc_heap, 0, mem2);
    while (!SwitchToThread())
      ;
  }

  fputs("Unreachable\n", stderr);
  TerminateProcess(GetCurrentProcess(), static_cast<UINT>(-1));
}

bool succeed_on_next_successful_iteration = false;

DWORD WINAPI timeout_proc(void *) {
  Sleep(timeout_in_milliseconds);
  succeed_on_next_successful_iteration = true;
  fprintf(stderr, " Timeout triggered after %lu milliseconds, waiting until next successful iteration to confirm no deadlock ", timeout_in_milliseconds);
  return 0;
}

// Make sure we don't timeout the whole test pipeline and diagnostic info is written to the logs.
const DWORD forced_timeout_in_milliseconds = 1000 * 60 * 60; // 1 hour
DWORD WINAPI forced_timeout_proc(void *) {
  Sleep(forced_timeout_in_milliseconds);
  fprintf(stderr, " Forced timeout triggered after %lu milliseconds (%.2f minutes).\n", forced_timeout_in_milliseconds, forced_timeout_in_milliseconds / 60000.0);
  fprintf(stderr, "Successful iterations: %llu\nCurrent failed iterations: %llu\nMax failed iterations: %llu\n", successful_iterations, no_progress_iterations_count, max_no_progress_streak);
  TerminateProcess(GetCurrentProcess(), static_cast<UINT>(-1));
  return 0;
}

int main() {
  clock_t start_time = clock();
  CreateThread(nullptr, 0, timeout_proc, nullptr, 0, nullptr);
  CreateThread(nullptr, 0, forced_timeout_proc, nullptr, 0, nullptr);
  HANDLE locked_thread = CreateThread(nullptr, 0, thread_proc, reinterpret_cast<void *>(true), CREATE_SUSPENDED, nullptr);
  HANDLE active_thread = CreateThread(nullptr, 0, thread_proc, reinterpret_cast<void *>(false), 0, nullptr);

  fprintf(stderr, "Running for %lu milliseconds (~%.2f minutes). %llu iterations without thread progress in a row = fail, %llu max successful iterations\n", timeout_in_milliseconds, timeout_in_milliseconds / 60000.0, no_progress_iterations_in_a_row_to_fail, max_successful_iterations);
  fputs(". = progress made, x = no progress made\n", stderr);
  while (successful_iterations < max_successful_iterations) {
    SuspendThread(active_thread);

    if (num_iters == 0) {
      ++no_progress_iterations_count;
      if (max_no_progress_streak < no_progress_iterations_count) {
        max_no_progress_streak = no_progress_iterations_count;
      }
      fprintf(stderr, "x");
    } else {
      ++successful_iterations;
      no_progress_iterations_count = 0;
      fprintf(stderr, ".");
      if (succeed_on_next_successful_iteration) {
        break;
      }
    }

    if (no_progress_iterations_count >= no_progress_iterations_in_a_row_to_fail) {
      const DWORD time_taken_in_ms = static_cast<DWORD>(((clock() - start_time) / CLOCKS_PER_SEC) * 1000);
      fputs(" Deadlock.\n", stderr);
      fprintf(stderr, "Test ran for %llu iterations in %lu milliseconds (~%.2f minutes) prior to hitting a potential deadlock (%llu failed iterations in a row).\n", successful_iterations, time_taken_in_ms, time_taken_in_ms / 60000.0, no_progress_iterations_count);
      fputs("Do not 're-run' and ignore this error, this should only occur if there is a possible deadlock.\n", stderr);

      if (IsDebuggerPresent()) {
        __debugbreak();
      }

      TerminateProcess(GetCurrentProcess(), static_cast<UINT>(-1));
    }

    num_iters = 0;

    ResumeThread(locked_thread);
    while (!SwitchToThread())
      ;
    SuspendThread(locked_thread);

    ResumeThread(active_thread);
    while (!SwitchToThread())
      ;
  }

  fputs(" Success.\n", stderr);
  const DWORD time_taken_in_ms = static_cast<DWORD>(((clock() - start_time) / CLOCKS_PER_SEC) * 1000);
  fprintf(stderr, "Test successfully ran %llu iterations in %lu milliseconds (~%.2f minutes) without hitting a deadlock.\n", successful_iterations, time_taken_in_ms, time_taken_in_ms / 60000.0);
  fprintf(stderr, "The maximum failed streak was %llu iterations.\n", max_no_progress_streak);
  TerminateProcess(GetCurrentProcess(), 0);
}
