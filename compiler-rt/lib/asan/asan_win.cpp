//===-- asan_win.cpp ------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Windows-specific details.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <windows.h>

#include "asan_interceptors.h"
#include "asan_internal.h"
#include "asan_mapping.h"
#include "asan_report.h"
#include "asan_stack.h"
#include "asan_thread.h"
#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_win.h"
#include "sanitizer_common/sanitizer_win_defs.h"
#include "sanitizer_common/sanitizer_win_immortalize.h"

using namespace __asan;

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
int __asan_should_detect_stack_use_after_return() {
  __asan_init();
  return __asan_option_detect_stack_use_after_return;
}

SANITIZER_INTERFACE_ATTRIBUTE
uptr __asan_get_shadow_memory_dynamic_address() {
  __asan_init();
  return __asan_shadow_memory_dynamic_address;
}
}  // extern "C"

// ---------------------- Windows-specific interceptors ---------------- {{{
static LPTOP_LEVEL_EXCEPTION_FILTER default_seh_handler;
static LPTOP_LEVEL_EXCEPTION_FILTER user_seh_handler;

extern "C" SANITIZER_INTERFACE_ATTRIBUTE long __asan_unhandled_exception_filter(
    EXCEPTION_POINTERS *info) {
  EXCEPTION_RECORD *exception_record = info->ExceptionRecord;
  CONTEXT *context = info->ContextRecord;

  // FIXME: Handle EXCEPTION_STACK_OVERFLOW here.

  SignalContext sig(exception_record, context);
  ReportDeadlySignal(sig);
  UNREACHABLE("returned from reporting deadly signal");
}

// Wrapper SEH Handler. If the exception should be handled by asan, we call
// __asan_unhandled_exception_filter, otherwise, we execute the user provided
// exception handler or the default.
static long WINAPI SEHHandler(EXCEPTION_POINTERS *info) {
  DWORD exception_code = info->ExceptionRecord->ExceptionCode;
  if (__sanitizer::IsHandledDeadlyException(exception_code))
    return __asan_unhandled_exception_filter(info);
  if (user_seh_handler)
    return user_seh_handler(info);
  // Bubble out to the default exception filter.
  if (default_seh_handler)
    return default_seh_handler(info);
  return EXCEPTION_CONTINUE_SEARCH;
}

INTERCEPTOR_WINAPI(LPTOP_LEVEL_EXCEPTION_FILTER, SetUnhandledExceptionFilter,
                   LPTOP_LEVEL_EXCEPTION_FILTER ExceptionFilter) {
  CHECK(REAL(SetUnhandledExceptionFilter));
  if (ExceptionFilter == &SEHHandler)
    return REAL(SetUnhandledExceptionFilter)(ExceptionFilter);
  // We record the user provided exception handler to be called for all the
  // exceptions unhandled by asan.
  Swap(ExceptionFilter, user_seh_handler);
  return ExceptionFilter;
}

INTERCEPTOR_WINAPI(void, RtlRaiseException, EXCEPTION_RECORD *ExceptionRecord) {
  CHECK(REAL(RtlRaiseException));
  // This is a noreturn function, unless it's one of the exceptions raised to
  // communicate with the debugger, such as the one from OutputDebugString.
  if (ExceptionRecord->ExceptionCode != DBG_PRINTEXCEPTION_C)
    __asan_handle_no_return();
  REAL(RtlRaiseException)(ExceptionRecord);
}

INTERCEPTOR_WINAPI(void, RaiseException, DWORD dwExceptionCode,
                   DWORD dwExceptionFlags, DWORD nNumberOfArguments,
                   const ULONG_PTR *lpArguments) {
  CHECK(REAL(RaiseException));
  // This is a noreturn function, unless it's one of the exceptions raised to
  // communicate with the debugger, such as the one from OutputDebugStringA.
  if (dwExceptionCode != DBG_PRINTEXCEPTION_C)
    __asan_handle_no_return();
  REAL(RaiseException)
  (dwExceptionCode, dwExceptionFlags, nNumberOfArguments, lpArguments);
}

#ifdef _WIN64

INTERCEPTOR_WINAPI(EXCEPTION_DISPOSITION, __C_specific_handler,
                   _EXCEPTION_RECORD *a, void *b, _CONTEXT *c,
                   _DISPATCHER_CONTEXT *d) {
  CHECK(REAL(__C_specific_handler));
  __asan_handle_no_return();
  return REAL(__C_specific_handler)(a, b, c, d);
}

#else

INTERCEPTOR(int, _except_handler3, void *a, void *b, void *c, void *d) {
  CHECK(REAL(_except_handler3));
  __asan_handle_no_return();
  return REAL(_except_handler3)(a, b, c, d);
}

INTERCEPTOR(int, _except_handler4, void *a, void *b, void *c, void *d) {
  CHECK(REAL(_except_handler4));
  __asan_handle_no_return();
  return REAL(_except_handler4)(a, b, c, d);
}
#endif

static thread_return_t THREAD_CALLING_CONV asan_thread_start(void *arg) {
  AsanThread *t = (AsanThread *)arg;
  SetCurrentThread(t);
  return t->ThreadStart(GetTid());
}

INTERCEPTOR_WINAPI(HANDLE, CreateThread, LPSECURITY_ATTRIBUTES security,
                   SIZE_T stack_size, LPTHREAD_START_ROUTINE start_routine,
                   void *arg, DWORD thr_flags, DWORD *tid) {
  // Strict init-order checking is thread-hostile.
  if (flags()->strict_init_order)
    StopInitOrderChecking();
  GET_STACK_TRACE_THREAD;
  // FIXME: The CreateThread interceptor is not the same as a pthread_create
  // one.  This is a bandaid fix for PR22025.
  bool detached = false;  // FIXME: how can we determine it on Windows?
  u32 current_tid = GetCurrentTidOrInvalid();
  AsanThread *t =
      AsanThread::Create(start_routine, arg, current_tid, &stack, detached);
  return REAL(CreateThread)(security, stack_size, asan_thread_start, t,
                            thr_flags, tid);
}

// }}}

#if SANITIZER_WINDOWS64

// If you change these constants, make the same changes in vcasan.lib... and any
// other future Windows, AddressSanitizer functionalities, which are closely
// integrated with the Visual Studio IDE.

// Two constants for vcasan.lib -> IDE
static constexpr unsigned kVCAsanLibSanitzer =
    ('san' | 0xE0000000);  // 0xe073616e
static constexpr unsigned kVCAsanLibAddressSanitzer =
    (kVCAsanLibSanitzer + 1);  // 0xe073616f

// Next threee constants for Asan RT -> IDE

// 0xe0736170 debugger IDE specific
static constexpr unsigned kVSEnlighten = (kVCAsanLibSanitzer + 2);

// 0xe0736171 – fake eh code used internally by the debugger to let users
// possibly stop on the first chance exception
static constexpr unsigned kVSRawThrown = (kVCAsanLibSanitzer + 3);

// 0xe0736172 – AV was not handled by the address sanitizer runtime. The
// debugger maps to STATUS_ACCESS_VIOLATION.
static constexpr unsigned kVSRealExeAVThrown = (kVCAsanLibSanitzer + 4);

__declspec(noinline) static void EnlightenVSDebugger() {
  if (::IsDebuggerPresent()) {
    // Must fire before shadow memory is boot strapped by throwing AV's
    // This is called early from AsanInitInternal()
    __try {
      RaiseException(kVSEnlighten, 0, 0, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
  }
}

static LONG CALLBACK
ShadowExceptionHandler(PEXCEPTION_POINTERS exception_pointers) {
  // Only handle access violations.
  if (exception_pointers->ExceptionRecord->ExceptionCode !=
          EXCEPTION_ACCESS_VIOLATION ||
      exception_pointers->ExceptionRecord->NumberParameters < 2) {
    __asan_handle_no_return();
    return EXCEPTION_CONTINUE_SEARCH;
  }

  // Only handle access violations that land within the shadow memory.
  uptr addr =
      (uptr)(exception_pointers->ExceptionRecord->ExceptionInformation[1]);

  // Check valid shadow range.
  if (!AddrIsInShadow(addr)) {
    if (::IsDebuggerPresent()) {
      __try {
        ULONG_PTR args[] = {
            reinterpret_cast<ULONG_PTR>(exception_pointers->ExceptionRecord),
            reinterpret_cast<ULONG_PTR>(exception_pointers->ContextRecord)};

        // Inform VS this is the AsanRuntime paging in shadow byte area.
        // Effects only if VS was previously informed this was an ASan binary.
        RaiseException(kVSRealExeAVThrown, 0, _countof(args), args);
      } __except (EXCEPTION_EXECUTE_HANDLER) {
      }
    }

    __asan_handle_no_return();
    return EXCEPTION_CONTINUE_SEARCH;
  }

  // This is an access violation while trying to read from the shadow. Commit
  // the relevant page and let execution continue.

  // Commit the page.
  if (!__sanitizer_virtual_alloc((LPVOID)addr, 1, MEM_COMMIT, PAGE_READWRITE)) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  // The page mapping succeeded, so continue execution as usual.
  return EXCEPTION_CONTINUE_EXECUTION;
}

// Manages custom exception handlers created by ASAN whenever users call
// AddVectoredExceptionHandler.
//
// NOTE: If the implementation of the shadow memory is changed and no longer
// requires ASAN to handle AVs in that region, this should be removed.
class ASANVectoredExceptionHandler {
 public:
  // Combines a VectoredExceptionHandler with the ShadowExceptionHandler to
  // always handle shadow memory access violations first.
  //
  // The NT internals will handle specifics behind exception handling execution
  // and remove race conditions. To avoid maintaining any locks and state for
  // exception handling internally, this function will call the
  // ShadowExceptionHandler before any invocation of the user's exception
  // handler. If the ShadowExceptionHandler returns a status code indicating it
  // didn't handle the exception, then the user's exception handler will be
  // called.
  PVECTORED_EXCEPTION_HANDLER CreateVectoredExceptionHandler(
      PVECTORED_EXCEPTION_HANDLER Handler) {
    SpinMutexLock lock(&Mutex);

    // If we will cross a page boundary, or there is no active page, create a
    // new page and update position in memory for newly created functions
    if (AtPageBoundary(lock) || UNLIKELY(!PagePtr)) {
      AllocateNewPage(lock);
    }

    return CreateNewExceptionHandler(lock, Handler);
  }

 private:
  struct CombinedFunctionStub {
    CombinedFunctionStub(PVECTORED_EXCEPTION_HANDLER UserHandler) {
      static_assert(sizeof(CombinedFunctionStub) % 16 == 0,
                    "Must have 2 byte alignment");
      static void *first = static_cast<void *>(&ShadowExceptionHandler);
      auto userFunction = static_cast<void *>(UserHandler);
      internal_memcpy(Instructions, &first, sizeof(void *));
      internal_memcpy(Instructions + sizeof(void *), &userFunction,
                      sizeof(void *));
    }

    // Instruction set for properly calling a combination of a custom
    // VectoredExceptionHandler preceded by the ShadowExceptionHandler on amd64
    // clang-format off
    unsigned char Instructions[96] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // first addr, will be ShadowExceptionHandler
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // second addr, will be user's VectoredExceptionHandler
      // StartOfInstructions:
      0x55, 0x53,                                     // push rbp, push rbx
      0x48, 0x89, 0x4C, 0x24, 0x08,                   // mov         qword ptr [rsp+8],rcx
      0x48, 0x83, 0xEC, 0x38,                         // sub         rsp,38h
      0x48, 0x8B, 0x4C, 0x24, 0x40,                   // mov         rcx,qword ptr [rsp+40h]
      0x48, 0x8b, 0x05,       0xd9, 0xff, 0xff, 0xff, // mov rax first (via offset) -41 (this is ShadowExceptionHandler addr)
      0xff, 0xd0,                                     // call ShadowExceptionHandler
      0x89, 0x44, 0x24, 0x20,                         // mov         dword ptr [rsp+20h],eax
      0x83, 0x7C, 0x24, 0x20, 0x00,                   // cmp         dword ptr [rsp+20h],0
      0x74, 0x06,                                     // je          rsp,38h (jump to CallUserCode)
      0x8B, 0x44, 0x24, 0x20,                         // mov         eax,dword ptr [rsp+20h]
      0xEB, 0x14,                                     // jmp         jump to Return
      // CallUserCode:
      0x48, 0x8B, 0x4C, 0x24, 0x40,                   // mov         rcx,qword ptr [rsp+40h]
      0x48, 0x8b, 0x05,       0xC2, 0xff, 0xff, 0xff, // mov rax second (via offset) -64 (this is user's VectoredExceptionHandler addr)
      0x48, 0x83, 0xC4, 0x38,                         // add         rsp,38h
      0x5b, 0x5d,                                     // pop rbp, pop rbx
      0xff, 0xe0,                                     // jmp rax     (compiler likes tail call better to maintain call stack)
      // Return:
      0x48, 0x83, 0xC4, 0x38,                         // add         rsp,38h
      0x5b, 0x5d,                                     // pop rbp, pop rbx
      0xc3,                                           // ret
      0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // int 3
      0xcc, 0xcc, 0xcc                                // int 3
    };
    // clang-format on
  };

  void AllocateNewPage(const SpinMutexLock &Lock) {
    DWORD oldProtection;
    PagePtr = static_cast<unsigned char *>(
        MmapOrDie(GetPageSizeCached(), "ASANVectoredExceptionHandler"));
    CHECK(__sanitizer_virtual_protect(PagePtr, GetPageSizeCached(),
                                      PAGE_EXECUTE_READWRITE, &oldProtection));
    NextHandlerPosition = 0;
  }

  bool AtPageBoundary(const SpinMutexLock &Lock) {
    return NextHandlerPosition + FunctionSize > GetPageSizeCached();
  }

  PVECTORED_EXCEPTION_HANDLER CreateNewExceptionHandler(
      const SpinMutexLock &Lock, PVECTORED_EXCEPTION_HANDLER Handler) {
    unsigned char *newHandler;
    auto combinedExceptionHandler = CombinedFunctionStub(Handler);

    // Copy the newly created exception handler into executable memory
    internal_memcpy(PagePtr + NextHandlerPosition,
                    combinedExceptionHandler.Instructions, FunctionSize);
    newHandler = PagePtr + NextHandlerPosition;
    NextHandlerPosition += FunctionSize;

    // Return the address of StartOfInstructions label from newly created
    // exception handler to add
    return reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(newHandler +
                                                         (2 * sizeof(void *)));
  }

  StaticSpinMutex Mutex = {};
  unsigned char *PagePtr = nullptr;  // Current page of memory being used
  size_t NextHandlerPosition = 0;    // Position of next function allocation
  static constexpr size_t FunctionSize = sizeof(CombinedFunctionStub);
};

ASANVectoredExceptionHandler *GetASANVectoredExceptionHandler() {
  return &immortalize<ASANVectoredExceptionHandler>();
}

INTERCEPTOR_WINAPI(PVOID, AddVectoredExceptionHandler, ULONG First,
                   PVECTORED_EXCEPTION_HANDLER Handler) {
  CHECK(REAL(AddVectoredExceptionHandler));

  auto exceptionHandler =
      GetASANVectoredExceptionHandler()->CreateVectoredExceptionHandler(
          Handler);

  return REAL(AddVectoredExceptionHandler)(First, exceptionHandler);
}

INTERCEPTOR_WINAPI(ULONG, RemoveVectoredExceptionHandler, PVOID Handler) {
  CHECK(REAL(RemoveVectoredExceptionHandler));
  // TODO: Safely manage removal of combined exception handler functions here to
  // avoid leaking memory.
  return REAL(RemoveVectoredExceptionHandler)(Handler);
}

#endif

namespace __asan {

void InitializePlatformInterceptors() {
  // The interceptors were not designed to be removable, so we have to keep this
  // module alive for the life of the process.
  HMODULE pinned;
  CHECK(GetModuleHandleExW(
      GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
      (LPCWSTR)&InitializePlatformInterceptors, &pinned));

  ASAN_INTERCEPT_FUNC(CreateThread);
  ASAN_INTERCEPT_FUNC(SetUnhandledExceptionFilter);

#ifdef _WIN64
  ASAN_INTERCEPT_FUNC(__C_specific_handler);
#else
  ASAN_INTERCEPT_FUNC(_except_handler3);
  ASAN_INTERCEPT_FUNC(_except_handler4);
#endif

  // Try to intercept kernel32!RaiseException, and if that fails, intercept
  // ntdll!RtlRaiseException instead.
  if (!::__interception::OverrideFunction("RaiseException",
                                          (uptr)WRAP(RaiseException),
                                          (uptr *)&REAL(RaiseException))) {
    CHECK(::__interception::OverrideFunction("RtlRaiseException",
                                             (uptr)WRAP(RtlRaiseException),
                                             (uptr *)&REAL(RtlRaiseException)));
  }

#if SANITIZER_WINDOWS64
  ::__interception::OverrideFunction(
      "AddVectoredExceptionHandler", (uptr)WRAP(AddVectoredExceptionHandler),
      (uptr *)&REAL(AddVectoredExceptionHandler));

  ::__interception::OverrideFunction(
      "RemoveVectoredExceptionHandler",
      (uptr)WRAP(RemoveVectoredExceptionHandler),
      (uptr *)&REAL(RemoveVectoredExceptionHandler));
#endif
}

// This mocks an internal CRT data structure which is subject to change.
// _CrtMemBlockHeader
struct AllocationDebugHeader {
  void *a, *b, *c;
  int d;
  int block_use;
  size_t data_size;
  long g;
  unsigned char h[4];

  AllocationDebugHeader() = delete;
  ~AllocationDebugHeader() = delete;
};

// A hash map of allocations which occured before ASAN initialization
// that can be used to determine if the CRT (or user in some cases) allocated
// memory prior to ASAN.
using SystemAllocationMap = __sanitizer::AddrHashMap<PROCESS_HEAP_ENTRY, 1031>;
alignas(SystemAllocationMap) unsigned char system_allocation_storage[sizeof(
    SystemAllocationMap)];
SystemAllocationMap *system_allocations;

// TODO: Should investigate all versions of msvcr to make sure that the process
// heap is used Only allocations that happen on the process heap prior to asan
// initialization are tracked
// This currently only tracks allocations that originated through call stacks
// containing malloc from the process heap in order to correctly report back
// asan errors to the consumer
void CaptureSystemHeapAllocations() {
  new (system_allocation_storage) SystemAllocationMap();
  system_allocations =
      reinterpret_cast<SystemAllocationMap *>(system_allocation_storage);

  PROCESS_HEAP_ENTRY lpEntry;

  HANDLE heap = ::GetProcessHeap();
  lpEntry.lpData = NULL;
  while (::HeapWalk(heap, &lpEntry)) {
    if (lpEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
      // Allocations are stored agnostic of debug/release information and based
      // on the runtime mode will call the correct functions to inspect the
      // allocation
      SystemAllocationMap::Handle h(system_allocations,
                                    reinterpret_cast<uptr>(lpEntry.lpData),
                                    false, true);
      *h = lpEntry;
    }
  }
  ::HeapUnlock(heap);
}

void RemoveFromSystemHeapAllocationsMap(void *oldPtr) {
  SystemAllocationMap::Handle h(system_allocations,
                                reinterpret_cast<uptr>(oldPtr), true, false);
}

void AsanApplyToGlobals(globals_op_fptr op, const void *needle) {
  UNIMPLEMENTED();
}

// Since asan's mapping is compacting, the shadow chunk may be
// not page-aligned, so we only flush the page-aligned portion.
void FlushUnneededASanShadowMemory(uptr p, uptr size) {
// On Windows we should avoid the overhead of a call to ReleaseMemoryPagesToOS
// which attempts to MEM_RELEASE a reserved region if possible. We know that
// the shadow memory should never get MEM_RELEASEd so just MEM_DECOMMIT it.
#if SANITIZER_WINDOWS64
  uptr page_size = GetPageSizeCached();
  uptr beg_aligned = RoundUpTo(p, page_size);
  uptr end_aligned = RoundDownTo(p + size, page_size);

  if (end_aligned > beg_aligned) {
    uptr shadow_beg = MEM_TO_SHADOW(beg_aligned);
    uptr shadow_end = MEM_TO_SHADOW(end_aligned - ASAN_SHADOW_GRANULARITY) - 1;

    ::VirtualFree(reinterpret_cast<LPVOID>(shadow_beg),
                  static_cast<size_t>(shadow_end - shadow_beg), MEM_DECOMMIT);
  }
#elif SANITIZER_WINDOWS
// No-op on 32-bit windows since full shadow memory is always committed.
#else
  ReleaseMemoryPagesToOS(MemToShadow(p), MemToShadow(p + size));
#endif
}

// ---------------------- TSD ---------------- {{{
static bool tsd_key_inited = false;

static __declspec(thread) void *fake_tsd = 0;

// https://docs.microsoft.com/en-us/windows/desktop/api/winternl/ns-winternl-_teb
// "[This structure may be altered in future versions of Windows. Applications
// should use the alternate functions listed in this topic.]"
typedef struct _TEB {
  PVOID Reserved1[12];
  // PVOID ThreadLocalStoragePointer; is here, at the last field in Reserved1.
  PVOID ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;

constexpr size_t TEB_RESERVED_FIELDS_THREAD_LOCAL_STORAGE_OFFSET = 11;
BOOL IsTlsInitialized() {
  PTEB teb = (PTEB)NtCurrentTeb();
  return teb->Reserved1[TEB_RESERVED_FIELDS_THREAD_LOCAL_STORAGE_OFFSET] !=
         nullptr;
}

void AsanTSDInit(void (*destructor)(void *tsd)) {
  // FIXME: we're ignoring the destructor for now.
  tsd_key_inited = true;
}

void *AsanTSDGet() {
  CHECK(tsd_key_inited);
  return IsTlsInitialized() ? fake_tsd : nullptr;
}

void AsanTSDSet(void *tsd) {
  CHECK(tsd_key_inited);
  fake_tsd = tsd;
}

void PlatformTSDDtor(void *tsd) { AsanThread::TSDDtor(tsd); }
// }}}

// ---------------------- Various stuff ---------------- {{{
void *AsanDoesNotSupportStaticLinkage() { return 0; }

uptr FindDynamicShadowStart() {
  return MapDynamicShadow(MemToShadowSize(kHighMemEnd), ASAN_SHADOW_SCALE,
                          /*min_shadow_base_alignment*/ 0, kHighMemEnd);
}

void AsanCheckDynamicRTPrereqs() {}

void AsanCheckIncompatibleRT() {}

void ReadContextStack(void *context, uptr *stack, uptr *ssize) {
  UNIMPLEMENTED();
}

void AsanOnDeadlySignal(int, void *siginfo, void *context) { UNIMPLEMENTED(); }

bool PlatformUnpoisonStacks() { return false; }

void InitializePlatformExceptionHandlers() {
#if SANITIZER_WINDOWS64
  EnlightenVSDebugger();
  // On Win64, we map memory on demand with access violation handler.
  // Install our exception handler.
  CHECK(AddVectoredExceptionHandler(TRUE, &ShadowExceptionHandler));
#endif
}

// Debug and release versions of the allocation header are different
static uptr GetAlignedAllocationHeader(void *addr) {
  static constexpr auto ptrSize = sizeof(void*);
  uintptr_t ptr = reinterpret_cast<uintptr_t>(addr);
  ptr = (ptr & ~(ptrSize - 1)) - ptrSize;
  ptr = *(reinterpret_cast<uintptr_t *>(ptr));
  return ptr;
}

// Returns the debug header information for a potential debug allocation
static AllocationDebugHeader *const GetAllocationDebugHeader(void *addr) {
  return static_cast<AllocationDebugHeader *>(addr) - 1;
}

bool AllocatedPriorToAsanInit(void *addr) {
  auto found = false;
  if (!addr) {
    return found;
  }

  // First attempt to look up the address passed in from the system allocations
  // map
  SystemAllocationMap::Handle h(system_allocations,
                                reinterpret_cast<uptr>(addr), false, false);
  found = h.exists();

#if _DEBUG
  // In debug, some non-debug CRT functions will call their debug counterparts
  // (e.g. free calls free_dbg) In the event that a debug allocation is passed
  // to a non-debug function, we want to attempt to pass through to the debug
  // call if we have not found the allocation in the map yet. This means we need
  // to attempt to look up the debug allocation address.
  if (!found) {
    found = DbgAllocatedPriorToAsanInit(addr);
  }
#endif

  return found;
}

bool AlignedAllocatedPriorToAsanInit(void *addr) {
  auto found = false;
  if (!addr) {
    return found;
  }

  SystemAllocationMap::Handle alignedHandle(
      system_allocations, GetAlignedAllocationHeader(addr), false, false);
  found = alignedHandle.exists();
  // TODO: May need to update checks after asan respects aligned offset

#if _DEBUG
  if (!found) {
    found = DbgAlignedAllocatedPriorToAsanInit(addr);
  }
#endif

  return found;
}

#if _DEBUG
// This mocks an internal CRT data structure which is subject to change.
// _AlignMemBlockHdr
struct AlignedAllocationDebugHeader {
  void *head;
  unsigned char gap[sizeof(void *)];

  AlignedAllocationDebugHeader() = delete;
  ~AlignedAllocationDebugHeader() = delete;
};

// Returns debug aligned allocation header information for a potential debug
// allocation
static AlignedAllocationDebugHeader *const GetAlignedAllocationDebugHeader(
    void *addr) {
  return reinterpret_cast<AlignedAllocationDebugHeader *>(
             reinterpret_cast<uptr>(addr) & ~(sizeof(uptr) - 1)) -
         1;
}

// Checks to see whether or not the address was a valid allocation from the
// debug heap or not
static bool IsValidDebugAllocation(uptr addr, PROCESS_HEAP_ENTRY &heapEntry) {
  // We need to ensure proper access before inspection
  // First need to make sure that the address matches a debug allocation header,
  // then that the allocation is big enough to be a debug allocation before
  // reading debug header members
  return reinterpret_cast<uptr>(heapEntry.lpData) +
                 sizeof(AllocationDebugHeader) ==
             addr &&
         heapEntry.cbData >= sizeof(AllocationDebugHeader) &&
         reinterpret_cast<AllocationDebugHeader *>(heapEntry.lpData)
             ->block_use &&
         reinterpret_cast<AllocationDebugHeader *>(heapEntry.lpData)
                 ->data_size < heapEntry.cbData;
}

// Checks whether or not an address is present in the system allocations map
// captured prior to asan initialization. The lookupAddr should be the address
// needed to look up from the map, which will vary depending on allocation types
// that add headers to allocations (debug, aligned_debug, etc.). For normal
// debug allocations lookupAddr will be the debug header starting address. It is
// the same for aligned debug allocations, however that address can only be
// found by first inspecting the aligned allocation header. The checkAddr should
// be the address that the debug block was actually allocated at. For normal
// debug allocations, that will be the starting address after the debug header.
// It is the same for aligned debug allocations, but again the aligned
// allocation header must first be inspected to determine that address
static bool AllocationPresentAndValid(void *lookupAddr, void *checkAddr) {
  SystemAllocationMap::Handle h(
      system_allocations, reinterpret_cast<uptr>(lookupAddr), false, false);
  if (h.exists()){
    return IsValidDebugAllocation(reinterpret_cast<uptr>(checkAddr), *h);
  }

  return false;
}

bool DbgAllocatedPriorToAsanInit(void *addr) {
  auto found = false;
  if (!addr) {
    return found;
  }

  // If the debug header address is in the map, there is a chance it could be a
  // debug allocation. We need to check the process heap entry fields after the
  // validating the ability to read them
  found = AllocationPresentAndValid(GetAllocationDebugHeader(addr), addr);

  return found;
}

bool DbgAlignedAllocatedPriorToAsanInit(void *addr) {
  auto found = false;
  if (!addr) {
    return found;
  }

  auto alignedAllocationHeaderStartingAddr =
      GetAlignedAllocationDebugHeader(addr);

  if (alignedAllocationHeaderStartingAddr &&
      alignedAllocationHeaderStartingAddr->head) {
    auto debugAllocatedBlock = alignedAllocationHeaderStartingAddr->head;
    found = AllocationPresentAndValid(
        GetAllocationDebugHeader(debugAllocatedBlock), debugAllocatedBlock);
    // TODO: May need to update checks after asan respects aligned offset
  }

  return found;
}

#endif

// We need to check if this address belongs to any of the heaps in the process.
bool IsSystemHeapAddress(uptr addr, void *heap) {
  HANDLE heaps[128];
  PROCESS_HEAP_ENTRY lpEntry;

  void **curr, **end;
  if (heap == nullptr) {
    curr = heaps;
    DWORD num_heaps = ::GetProcessHeaps(sizeof(heaps) / sizeof(HANDLE), heaps);
    CHECK(num_heaps <= sizeof(heaps) / sizeof(HANDLE) &&
          "You have exceeded the maximum number of supported heaps.");
    end = curr + num_heaps;
  } else {
    curr = &heap;
    end = curr + 1;
  }

  while (curr != end) {
    ::HeapLock(*curr);
    lpEntry.lpData = NULL;

    while (::HeapWalk(*curr, &lpEntry)) {
      if (lpEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
        if (reinterpret_cast<uptr>(lpEntry.lpData) == addr) {
          ::HeapUnlock(*curr);
          return true;
        }

// The CRT adds extra space in front of an allocation in debug mode so we do
// our best detecting such allocations.
#ifdef _DEBUG
        if (IsValidDebugAllocation(addr, lpEntry)) {
          ::HeapUnlock(*curr);
          return true;
        }
#endif  // _DEBUG
      }
    }

    ::HeapUnlock(*curr);
    ++curr;
  }

  return false;
}

// We want to install our own exception handler (EH) to print helpful reports
// on access violations and whatnot.  Unfortunately, the CRT initializers assume
// they are run before any user code and drop any previously-installed EHs on
// the floor, so we can't install our handler inside __asan_init.
// (See crt0dat.c in the CRT sources for the details)
//
// Things get even more complicated with the dynamic runtime, as it finishes its
// initialization before the .exe module CRT begins to initialize.
//
// For the static runtime (-MT), it's enough to put a callback to
// __asan_set_seh_filter in the last section for C initializers.
//
// For the dynamic runtime (-MD), we want link the same
// asan_dynamic_runtime_thunk.lib to all the modules, thus __asan_set_seh_filter
// will be called for each instrumented module.  This ensures that at least one
// __asan_set_seh_filter call happens after the .exe module CRT is initialized.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE int __asan_set_seh_filter() {
  // We should only store the previous handler if it's not our own handler in
  // order to avoid loops in the EH chain.
  auto prev_seh_handler = SetUnhandledExceptionFilter(SEHHandler);
  if (prev_seh_handler != &SEHHandler)
    default_seh_handler = prev_seh_handler;
  return 0;
}

bool HandleDlopenInit() {
  // Not supported on this platform.
  static_assert(!SANITIZER_SUPPORTS_INIT_FOR_DLOPEN,
                "Expected SANITIZER_SUPPORTS_INIT_FOR_DLOPEN to be false");
  return false;
}

#if !ASAN_DYNAMIC
// The CRT runs initializers in this order:
// - C initializers, from XIA to XIZ
// - C++ initializers, from XCA to XCZ
// Prior to 2015, the CRT set the unhandled exception filter at priority XIY,
// near the end of C initialization. Starting in 2015, it was moved to the
// beginning of C++ initialization. We set our priority to XCAB to run
// immediately after the CRT runs. This way, our exception filter is called
// first and we can delegate to their filter if appropriate.
#pragma section(".CRT$XCAB", long, read)
__declspec(allocate(".CRT$XCAB")) int (*__intercept_seh)() =
    __asan_set_seh_filter;

// Piggyback on the TLS initialization callback directory to initialize asan as
// early as possible. Initializers in .CRT$XL* are called directly by ntdll,
// which run before the CRT. Users also add code to .CRT$XLC, so it's important
// to run our initializers first.
static void NTAPI asan_thread_init(void *module, DWORD reason, void *reserved) {
  if (reason == DLL_PROCESS_ATTACH)
    __asan_init();
}

#pragma section(".CRT$XLAB", long, read)
__declspec(allocate(".CRT$XLAB")) void(NTAPI *__asan_tls_init)(
    void *, unsigned long, void *) = asan_thread_init;
#endif

static void NTAPI asan_thread_exit(void *module, DWORD reason, void *reserved) {
  if (reason == DLL_THREAD_DETACH) {
    // Unpoison the thread's stack because the memory may be re-used.
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    uptr stackSize = (uptr)tib->StackBase - (uptr)tib->StackLimit;
    __asan_unpoison_memory_region(tib->StackLimit, stackSize);
  }
}

#pragma section(".CRT$XLY", long, read)
__declspec(allocate(".CRT$XLY")) void(NTAPI *__asan_tls_exit)(
    void *, unsigned long, void *) = asan_thread_exit;

WIN_FORCE_LINK(__asan_dso_reg_hook)

}  // namespace __asan

#endif  // SANITIZER_WINDOWS
