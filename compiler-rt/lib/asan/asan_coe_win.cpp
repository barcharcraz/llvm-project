
//===-- asan_coe_win.cpp ------------------------------------------------------===//
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
#include <eh.h>

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

#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_win.h"
#include "sanitizer_common/sanitizer_win_defs.h"
#include "sanitizer_common/sanitizer_win_immortalize.h"

// Continue on Error (COE)
// -----------------------
//
// We report only the unique errors diagnosed at runtime, and then provide a
// summary upon program exit(), which is source oriented. It's organizd around
// line, function, file which gives a prioritized global source perspective.
// 
// Heap allocations are initialized to blocks of 0xbebebebe. This flushes out
// the program errors that "got luck" becuase uninitialized values were zer0.
// 
// Direct use of undefined data will stop the program regardless of COE. 
// Consider these two examples:
// 
//  Undeined pointer
//   1.)  int *p = 0xbebebebe;
//        printf("What p points to 0x%x\n", *p); // Boom!
// 
//  Undefined malloc operand
//   2.)  int* foo = (int*)malloc(0xbebebf42); // Boom!
//
// The default mode of halt-on-first-error was never engineered for BAD mutating
// writes that erroneously altered Asan meta-data for the heap and the stack. So we 
// had to make the meta-data "safer"  as the Asan runtime would AV from continueing 
// after a simple underflow (e.g. A[-1] = 3.14159;). That underflow would clobber
// meta-data for "A" and then subsequent reporting of errors involving "A" would AV 
// in the Address Sanitizer runtime while processing an error.
//
// Also the mechanism for symbolizing a call stack was not robust and involved a
// different binary: llvm_symbolizer.exe. The runtime used a custom text command
// language over sockets to make requests from the symbolizer.exe The space and
// time for symboizing each set of call stacks was prohibitive for
// continue-on-error. We want COE to replace checked compilers after some tuing.
// 
// Now we only use Rtl... and K32... functions to walk the stack
// get a context, and load modules. Then each frame is [symbolized in process]. 
// 
// We checkpoint the quarantine state, [symbolize in process] and then restore 
// the quarantine state. This prevents the "polution" of the state of the user's 
// quarantine space for the primary_ and secondary_ allocators in the combined allocator.
//
// GOALS:
// 
//  If a program completed without -fsanitize=address, it should "complete"
//  with continue-on-error (COE), IFF it contains NO undefined behaviour. If there's
//  undefined behavior, the system may or may not return %errorlevel%  == 0 and we do
//  our best to continue all the way to exit()
// 
//  Two big differences involving data:
// 
//  1.) There's a different layout for ALL data, the program might produce
//  incorrect results not seen with "normal" or optimized data layouts. Specifically
//  there is no stack packing when we compile for Asan and additionally the compiler
//  will artifically align variables 0 mod 8 at a minimum.
// 
//  2.) Heap allocations are initialized to 32-bit words of 0xbebebebe (not zer0)
//      This will pop the use of uninitialized heap data.
//
// SCENARIOS:
// 
//   Scenario #1
//       We run a word.exe binary for an hour and we dump unique errors upon
//       termination Unique errors are determined by a hash of the hex call site
//       addresses. If an environment variable COE_LOG_FILE is null and is NOT set to 
//       "some.name.log", then we print to stderr or stdout based upon: 
//           setenv ASAN_OPTIONS=continue_on_error=1
//           setenv ASAN_OPTIONS=continue_on_error=2
// 
//       NOTE : if you just setenv COE_LOG_FILE = "some.name.log" and do NOT
//              setenv ASAN_OPTIONS=continue_on_error=(1 or 2) then ALL output
//              will got to the log file (not interfering with test diffing)
// 
//   Scenario #2
//       We run 200,000 unit tests and get the expected test resuls for diffing.
//       Plus, we get all the hidden memory safety errors, in a seperate LOG.FILE.
//       The cost of initial adoption is not prohibative. Your test suites did 
//       not blow up.
//
//  CONSTRAINTS:
// 
//     1.) The error messages can not diverge from the current Asan format
//         becuase of third party diffing tools.
//     2.) We take as little memory as possible to avoid
//         impacting the user's binary and we NEVER use the STL or VirtualALloc, 
//         new or malloc.
// 
//         NOTE: VirtualAlloc is not space efficient so the internal containers
//               are negatively impacted by the 64K granularity of VirtualAlloc
//               https://devblogs.microsoft.com/oldnewthing/20031008-00/?p=42223
//
// Interface implementation for "asan_continue_on_error.h"
// -----------------------------------------------------
//
// namespace __coe_win {
// 
//   // State
//   bool ContinueOnError()
//   bool ModulesLoading()
//   bool CrtTearingDown()
// 
//   // Error object
//   void OpenError()
//   void CloseError(ErrorDescription &e)
//   bool ErrorIsHashed(const char *category)
//
//   // Call stacks
//   void StackInsert(const __sanitizer::StackTrace *stk_trace)
//   void PrintStack(__sanitizer::StackTrace const *stk)
// 
//   // Reporting
//   void ReportError(ErrorDescription &e)
//   void ReportErrorSummary(const char *bug_descr,
//                           const __sanitizer::StackTrace *stack)
//   void RawWrite(const char *buffer)
//  }
// 
// This plugs intop a platform independent API to the rest of the 
// runtime. Clients see this simple API of a sealed object that uses
// no virtual calls.
// 
//   #include "asan_continue_on_error.h"
//
//   CoePlatformDependent coe;
//
// New engineering
// ---------------
//
//    1.) Create "safe" meta-data for caching information associated with errors
//        Two heap managers:
//          - (primary_) SizeClassAllocator for small to medium objects
//          - (secondary_) MMap Allocator for large or unaligned objects
//        The safe meta data is placed in a postion unique to each allocator.
//    2.) Eliminate use of llvm\symbolizer.exe
//          - implement internal stack symbolizer with minium use of dbghelp.dll
//          - Eliminate inter-process communication with streams and custom text
//            commands to a symbolizer.exe
//          - Eliminate the use of StackWalk64() to walk a possibly bogus stack
//          - checkpoint the quarentine space around new symbolizing
//    3.) Hash and cache new vectors of return PC's.
//    4.) New code to symbolized stacks [in process] for allocation, free, point 
//        of error with re-directed error messages to stdout, stderr or a log file.
//    5.) Hash all errors to ensure uniqueness
//         (e.g., we may execute the same memory safety issue in a loop or on
//         different call paths to a leaf). This is hashed by call stacks. Then
//         we post proces and present all errors at line,function,file level of
//         granularity
//    6.) Match all the existing error formats for 17 categories of errors with
//        current product. (in support of common post processing tools for logs
//        .. e.g.,Dassualt)
//    7.) Print source oriented (func,file,line, call path) summary information
//        upon program termination of user's program.
//
//    NOTE: COE should simply be under a new compiler flag: /Od+ when I get
//          to tune the performance of the AddressSanitizer runtime.
//

#include <Psapi.h>
#include <handleapi.h>
#include <signal.h>

#include "asan_errors.h"
#pragma pack(push, before_imagehlp, 8)
// Urban myth - Some versions of imagehlp.dll lack
// the proper 0 mod 8 packing directives themselves.
#include <imagehlp.h>
#pragma pack(pop, before_imagehlp)
#include <windows.h>

// Before we invoke the in process symbolizer we
// make sure there's enough stack space remaining.
// spec2k6\perlbench has a deep recursive stress test.
// In an error, capture the current stack and do not
// call into dbghlp in this process at this point.
static const u32 kMaxDepthForLookAhead = 512;

// Two pages (8K) for an internal sprintf() and 
// then output to a stream. See varargs Write().
static const u32 kSprintfFormatBufferLen = 1 << 13;

// When printing the function:line if it's lager 
// than this len. then start tabbed, on next line
static const u32 kMaxFuncFileLineLen = 60;

// Used for indexing the accumulated parts
// of an errror that will be hashed. Invarient
// is that the point of catchin an error goes to:
// 
// current_error_stacks[kFirstCapturedStackIndex].size;
static const u32 kFirstCapturedStackIndex = 0;

// Second limit if we were able to determine we
// could call dbghlp in process. See the constant 
// kMaxDepthForLookAhead for capture and filter
// of current in process stack depth.
static const u32 kPrintStackDepthLimit = 64;

// We can format func,file,line for 128 frames
static const u32 kMaxStackDepthForFormat = 128;

// Clipping limit when formatting a function of file name
static const u32 kMaxFuncOrFileNmaeLen = 512;

// Traditional size that's prime for hashing 'errors'.
static const u32 kHashTablePrimeSize = 1033;

// Traditional size that's prime for hashing 'strings'.
static const u32 kStringTablePrimeSize = 1999;

// Used for optimization. If we are printingsymbolizing in process
// there is no need to update meta-data from safe meta data in the
// allocators. We assume the in process symboizer does not trash 
// memory.
static bool modules_loading = false;

// All output goes to this file handle
static HANDLE coe_res_file_handle = nullptr;

// Upon exit when printing summay into, if we are in
// a really clobbered state, optimize out some actions in
// asan_allocator.cpp
bool crt_state_tearing_down = false;

static int coe_total_error_cnt = 0;
static wchar_t coe_wcs_log_file_name[] = L"COE_LOG_FILE";

// This is a very complex but concise way to pass "..." which is varargs
// in a printf() extern declaration. This is how COE hijaks output(s)
//
// class... Args is `template parameter pack',
// Args... args is `function parameter pack',
// and args... is a `function parameter pack expansion'.

template <class... Args>
static void Write(const char* format, Args... args) {
  char tmp[kSprintfFormatBufferLen];
  DWORD cbWritten = 0;

  __sanitizer::internal_snprintf(tmp, kSprintfFormatBufferLen, format, args...);

  bool fSuccess =
      WriteFile(coe_res_file_handle,      // handle for file,stderr,or stdout
                tmp,                      // message
                strlen(tmp),              // message length
                &cbWritten,               // bytes written
                (LPOVERLAPPED) nullptr);  // not overlapped

  CHECK(fSuccess);
}

namespace __asan {

HMODULE hmDbgHelp;

static SpinMutex fallback_mutex;

bool COE() {
  if (flags()->continue_on_error)
    return true;
  return false;
}

struct CoeError {
  ErrorKind kind;
  u16 file_name_hash;   // hash of file name string
  u16 func_name_hash;   // hash of function name string
  u16 error_desc_hash;  // hash of error string
  u16 error_category;
  u32 hit_count, line_no, displacement;
  uptr addr, pc, bp, sp;

  CoeError(ErrorKind error_kind) : hit_count(0) {
    kind = error_kind;
  }
};

// Accumulated errors with their variable number of call stacks, used for
// hashing. Placing in .data to avoid use of VirtualAlloc() which has a 64KB
// granularity.

static char*
    coe_accumulated_errors_backing[kHashTablePrimeSize * sizeof(CoeError)];

static CoeError* coe_accumulated_errors =
    reinterpret_cast<CoeError*>(coe_accumulated_errors_backing);

bool CoeErrors(uptr xhash) {
  CoeError* e = &coe_accumulated_errors[xhash];
  if (e->kind != kErrorKindInvalid) {
    return true;
  }
  return false;
}

struct SourceErrors {
  void SortErrors();
  void PrintSummary();
  void ReportOneErrorSummary(const char* bug_descr,
                             const __sanitizer::StackTrace* stack);
  void ReportOneUnhashedErrorSummary(const char* bug_descr,
                                const __sanitizer::StackTrace* stack);
  struct H1Element {
    u16 file;
    u32 count;
  };

  struct H2Element {
    u16 file;
    u16 func;
    u32 count;
  };

  struct H3Element {
    u16 file;
    u16 func;
    u32 line;
    DWORD64 line_displacement;
    u16 bug_descr;
    u32 count;
  };

  char* StringTable[kStringTablePrimeSize] = {};

 private:
  // Source oriented summay information
  //    - FilesWithHitCounts[file][highest] to FilesWithHitCounts[file][lowest]
  //    - FuncsInEachFile[file][func1...funcn]
  //    - LinesInEachFunc[file][func][line1 .. linen]
  //    - OffsetsInEachLine[file][func][line1] [offset1 ... offsetN]

  H1Element FilesWithHitCount[kStringTablePrimeSize] = {0};

  // Given an int x = H2(file,func), use x as a row index to find a function's
  // containing file table. Build this first with hashes and linear probe, then
  // sort based on file hit count. Then we can iterate over funcs in the same
  // file. We can then sort the hit counts of each function within the same
  // file. Hash on 2 then sort on 1
  // https://stackoverflow.com/questions/664014/what-integer-hash-function-are-good-that-accepts-an-integer-hash-key

  u16 H2(u16 file, u16 func) {
    unsigned int x = (file << 16) | func;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x % kStringTablePrimeSize;
  }

  H2Element FuncsInEachFile[kStringTablePrimeSize] = {0};

  // Given an int x = H3(file,function,line) use x as a row index to find a
  // line's containing function. Build first with hashes and linear proble, then
  // sort based on {file,func} as a primary key. This sorted order supports the
  // two outer loops iterating over files and ranges of functions in those
  // files. Hash on 3 then sort on 2

  u16 H3(u16 file, u16 func, u32 line) {
    unsigned int x = ((file << 16) | func) + line;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x % kStringTablePrimeSize;
  }

  H3Element LinesInEachFunc[kStringTablePrimeSize] = {0};
};

SourceErrors source_errors;

decltype(::SymCleanup)* SymCleanup;
decltype(::SymGetLineFromAddr64)* SymGetLineFromAddr64;
decltype(::SymGetOptions)* SymGetOptions;
decltype(::SymGetSearchPathW)* SymGetSearchPathW;
decltype(::SymGetSymFromAddr64)* SymGetSymFromAddr64;
decltype(::SymInitialize)* SymInitialize;
decltype(::SymLoadModuleExW)* SymLoadModuleExW;;
decltype(::SymSetOptions)* SymSetOptions;
decltype(::SymSetScopeFromAddr)* SymSetScopeFromAddr;
decltype(::SymSetSearchPathW)* SymSetSearchPathW;

static const size_t kAsanWindowsSymMaxLen = 2 * 1024;

static char symbol_memory[sizeof(IMAGEHLP_SYMBOL64) + kAsanWindowsSymMaxLen];

class Symbol {
 public:
  Symbol(HANDLE process, DWORD64 address)
      : sym((SymbolType*)&symbol_memory[0]) {
    internal_memset(sym, '\0', sizeof(*sym));
    sym->SizeOfStruct = sizeof(*sym);
    sym->MaxNameLength = kAsanWindowsSymMaxLen;
    DWORD64 displacement;
    if (!SymGetSymFromAddr64(process, address, &displacement, sym)) {
      internal_memcpy(sym->Name, "NoFuncSymbol()", 8);
    }
  }

  char* Name() { return sym->Name; }

 private:
  typedef IMAGEHLP_SYMBOL64 SymbolType;
  SymbolType* sym;
};

// We can't new or malloc, we can not use the STL and
// VirtualAlloc is really inefficient.
struct CallStacks {
  void ResetToZeros() {
    for (int i = 0; i < 4; i++) {
      current_error_stacks[i].trace = nullptr;
      current_error_stacks[i].size = 0;
      current_error_stacks[i].tag = 0;
    }
    current_error_stk_cnt = 0;
  }

  void Accumulate(const __sanitizer::StackTrace* stk_trace) {
    for (u32 i = 0; i < stk_trace->size; i++) {
      current_traces[current_error_stk_cnt][i] = stk_trace->trace[i];
    }

    current_error_stacks[current_error_stk_cnt].trace =
        &current_traces[current_error_stk_cnt][0];
    current_error_stacks[current_error_stk_cnt].size = stk_trace->size;
    current_error_stacks[current_error_stk_cnt].tag = stk_trace->tag;
    current_error_stk_cnt++;
  }

  void SetEmpty() { current_error_stk_cnt = 0; }
  int CurrenCnt() { return current_error_stk_cnt; }

  StackTrace* StackTrace(int i) { return &current_error_stacks[i]; }
  u32 StackTraceSize(int i) { return current_error_stacks[i].size; }

 private:
  int current_error_stk_cnt = 0;
  __sanitizer::StackTrace current_error_stacks[4] = {};
  uptr current_traces[3][kStackTraceMax] = {};
};

static CallStacks stacks;

struct ErrorHashing {
  // Compilers - Aho,Ullman - Dragon book Fig. 7.35
  u16 CoeStringHash(const char* name) {
    size_t h = 0, g = 0;
    char elem = 0;
    for (size_t i = 0; i < strlen(name); i++) {
      elem = name[i];
      h = (h << 4) + elem;
      g = h & 0xF0000000;
      if (g) {
        h = h ^ (g >> 24);
        h = h ^ g;
      }
    }
    h = h % kStringTablePrimeSize;
    return (u16)h;
  }

  uptr CoeHash(const char* category) {
    u16 h = CoeStringHash(category);

    // Capture point of error call stack first and then push the others
    uptr seed = stacks.StackTraceSize(kFirstCapturedStackIndex);
    int num_stacks = stacks.CurrenCnt();
    CHECK(num_stacks >= 0 && num_stacks <= 3);

    for (int i = 0; i < num_stacks; i++) {
      StackTrace* stk_trace = stacks.StackTrace(i);

      for (u32 j = 0; j < stk_trace->size; j++) {
        const uptr ret_pc = stk_trace->trace[j];
        // Constant is fractional part of golden ratio. Good random bit distribution.
        // Extra shifts would be over kill.This hash function discerns all 14 "unique" 
        // new-delete-mismatch errors in spec2k6\povray with call paths leading to the same delete
        seed ^= (ret_pc + 0x9e3779b9);  //+ ((seed << 6) + (seed >> 2));
      }
    }

    // Combine effect of text description from error object
    // https://www.boost.org/doc/libs/1_64_0/boost/functional/hash/hash.hpp
    uptr category_hash = h % kHashTablePrimeSize;
    seed ^= category_hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    seed = seed % kHashTablePrimeSize;

    return seed;
  }

  uptr CurrentError() {
    CHECK(coe_current_error_hash_index >= 0 &&
          coe_current_error_hash_index<  kHashTablePrimeSize);
    return (uptr)coe_current_error_hash_index;
  }

  bool CurrentErrorWasNotHashed() {
    return coe_current_error_hash_index == -1;
  }

  void CoeClearCurrentErrorHash() { coe_current_error_hash_index= -1; }

  bool CoeErrorIsHashed(const char* category) {
    uptr xhash = CoeHash(category);
    SetCurrentError(xhash);
    if (CoeErrors(xhash)) {
      return true;
    }
    return false;
  }

 private:
  void SetCurrentError(uptr xhash) {
    CHECK(coe_current_error_hash_index== -1);
    coe_current_error_hash_index= (int)xhash;
  }

  int coe_current_error_hash_index= -1;
};

static ErrorHashing hash;

// While printing the summary, fill in these tables to support a
// quick iteration upon termination (of a possibly insane number of errors)
//
//    - FilesWithHitCounts[file][highest] to FilesWithHitCounts[file][lowest]
//    - FuncsInEachFile[file][func1...funcn]
//    - LinesInEachFunc[file][func][line1 .. linen]
//    - OffsetsInEachLine[file][func][line1] [offset1 ... offsetN]

u16 CoeStringFindOrIntern(const char* name);

void SourceErrors::ReportOneUnhashedErrorSummary(
    const char* bug_descr,
    const __sanitizer::StackTrace* stack) {

  // #1 description
  u16 bug_descr_xhash = CoeStringFindOrIntern(bug_descr);
  char* unique_string = StringTable[bug_descr_xhash];
  
  Printf("SUMMARY: AddressSanitizer: %s ", unique_string);

  HANDLE hProcess = ::GetCurrentProcess();
  uptr pc = StackTrace::GetPreviousInstructionPc(stack->trace[1]);
  SymSetScopeFromAddr(hProcess, (DWORD64)pc);

  IMAGEHLP_LINE64 line;  // source line number
  DWORD displacement;    // byte offset from start of line number

  if (SymGetLineFromAddr64(hProcess, (DWORD64)pc, &displacement, &line)) {
    // #2 File and line number
    u16 file_name_xhash = CoeStringFindOrIntern(line.FileName);
    unique_string = StringTable[file_name_xhash];

    Printf("%s:%d at offset %x", unique_string, line.LineNumber);

    // #3 Function name - using class symbol definition
    Symbol func(hProcess, (DWORD64)pc);
    u16 func_name_xhash = CoeStringFindOrIntern(func.Name());
    unique_string = StringTable[func_name_xhash];

    Printf("in %s() \n", unique_string);
  } else {
    Printf("\n");
  }
}

void SourceErrors::ReportOneErrorSummary(const char* bug_descr,
                                         const __sanitizer::StackTrace* stack) {
  if (hash.CurrentErrorWasNotHashed()) {
    ReportOneUnhashedErrorSummary(bug_descr, stack);
    return;
  }
  // #1 description
  u16 bug_descr_xhash = CoeStringFindOrIntern(bug_descr);
  char* unique_string = StringTable[bug_descr_xhash];
  uptr current_error_xhash = hash.CurrentError();

  // The current index was hashed in the IsCahed() method on each error type
  CoeError* e = &coe_accumulated_errors[current_error_xhash];

  Printf("SUMMARY: AddressSanitizer: %s ", unique_string);

  HANDLE hProcess = ::GetCurrentProcess();
  uptr pc = StackTrace::GetPreviousInstructionPc(stack->trace[0]);
  SymSetScopeFromAddr(hProcess, (DWORD64)pc);

  IMAGEHLP_LINE64 line;  // source line number
  DWORD displacement;    // byte offset from start of line number

  if (SymGetLineFromAddr64(hProcess, (DWORD64)pc, &displacement, &line)) {
    // #2 File and line number
    u16 file_name_xhash = CoeStringFindOrIntern(line.FileName);
    unique_string = StringTable[file_name_xhash];
    e->file_name_hash = file_name_xhash;
    e->line_no = line.LineNumber;
    e->displacement = displacement;

    Printf("%s:%d at offset %x", unique_string, line.LineNumber);

    // #3 Function name - using class symbol definition
    Symbol func(hProcess, (DWORD64)pc);
    u16 func_name_xhash = CoeStringFindOrIntern(func.Name());
    unique_string = StringTable[func_name_xhash];
    e->func_name_hash = func_name_xhash;

    // To be sorted by decending hit count frequency.
    H1Element* elem1 = &FilesWithHitCount[file_name_xhash];
    elem1->file = file_name_xhash;
    elem1->count += 1;

    // To be sorted (upon terminate) by file_name_hash (in priority order)
    // Then secondary sort by func_name_hash hit counts per functions
    // qualified by file. Note that 79 = 43 + 23 + 13
    //
    // File: MyFile.cpp (79)
    //     Func1(43)
    //       Line 1200
    //         Offset 0x16 "heap-buffer-overflow"
    //     Func2(23)
    //       Line 86
    //         Offset 0x8 "new-delete-type-mismatch"
    //     Func3(13)
    //       . . .

    // To be sorted by function hit-count within the same file.
    H2Element* elem2 = &FuncsInEachFile[H2(file_name_xhash, func_name_xhash)];
    elem2->file = file_name_xhash;
    elem2->func = func_name_xhash;
    elem2->count += 1;

    // To be sorted within the same file::func
    H3Element* elem3 =
        &LinesInEachFunc[H3(file_name_xhash, func_name_xhash, line.LineNumber)];
    elem3->file = file_name_xhash;
    elem3->func = func_name_xhash;
    elem3->line = line.LineNumber;
    elem3->line_displacement = displacement;
    elem3->bug_descr = bug_descr_xhash;
    elem3->count += 1;

    Printf("in %s() \n", unique_string);
  } else {
    Printf("\n");
  }
}

// We make two passed over the accumulated "raw" unique errors.
// These are theoretically unique but we need to raise the level
// of abstraction for the user. We print the following example
// ordered by higheset to lowest hit counts.
//
//    File-1  (hit count)
//        Function-1 (hit count)
//            Line-1
//                Offset-1 error-descr (hit count)
//                Offset-2 error-descr (hit count)
//            Line-2
//                Offset-1 error-descr (hit count)
//        Function-2 (hit count)
//            Line-1
//                Offset-1 error-descr (hit count)
//    File-2  (hit count)
//        Function-1 (hit count)
//            Line-1
//                Offset-1 error-descr (hit count)
//            Line-2
//                Offset-1 error-descr (hit count)
//                Offset-2 error-descr (hit count)
//
//      NOTE: We take care of multiple memory references at the same sournce
//      line
//
//    Pass 1
//
//    Create the direct mapped caching while reporting each error summary
//
//    - FilesWithHitCounts[file][hits]
//    - FuncsInEachFIle[file][func]
//    - LinesInEachFunc[file][func][line]
//    - OffsetsInEachLine[file][func][line1][offset]
//
//    Pass 2
//
//    Sort the arrays used for the linear probes so that we can iterate over
//    ranges of a primary search key, abstractly represented as follows:
//
//    - FilesWithHitCounts[file][highest] to FilesWithHitCounts[file][lowest]
//    - FuncsInEachFIle[file][func1...funcn]
//    - LinesInEachFunc[file][func][line1 .. linen]
//    - OffsetsInEachLine[file][func][line1] [offset1 ... offsetN]
//
//    for (auto file : FilesWithHitCounts) {
//
//      Printf("File: %s\n", StringTable[elem.file_hash]);
//      auto range_of_funcs = FunctToFile(file)
//
//      for (auto func : range_of_funcs) {
//
//        Printf("Func: %s\n, StringTable(func);
//        auto range_of_lines = FunctToFile(file,func);
//
//        for (auto line: range_of_lines) {
//
//          Printf("line %d\n", line);
//          auto range_of_offsets = FunctToFile(file,func,line)
//
//          for (auto offset : range_of_offsets) {
//
//            Printf("Offset %x Error %s Hits %d\n",offset->number,
//            offset->err_descr, offset->cnt);
//          }
//        }
//      }
//    }

void SourceErrors::SortErrors() {
  // Descending frequency - from most broken file to least

  for (int i = 1; i < kStringTablePrimeSize; i++) {
    if (!FilesWithHitCount[i].file)
      continue;
    for (int j = i;
         j > 0 && (FilesWithHitCount[j - 1].count < FilesWithHitCount[j].count);
         j--) {
      H1Element tmp;
      tmp.file = FilesWithHitCount[j - 1].file;
      tmp.count = FilesWithHitCount[j - 1].count;
      FilesWithHitCount[j - 1].file = FilesWithHitCount[j].file;
      FilesWithHitCount[j - 1].count = FilesWithHitCount[j].count;
      FilesWithHitCount[j].file = tmp.file;
      FilesWithHitCount[j].count = tmp.count;
    }
  }

  Printf("\n=== Files in priority order ===\n\n");

  for (int i = 0; i < kHashTablePrimeSize; i++) {
    if (FilesWithHitCount[i].file == 0)
      break;
    Printf("File: %s Unique call stacks: %d\n",
           StringTable[FilesWithHitCount[i].file], FilesWithHitCount[i].count);
  }

  // Produce "file::function()" sorted by frequency
  for (int i = 1; i < kStringTablePrimeSize; i++) {
    if (!FuncsInEachFile[i].file)
      continue;
    for (int j = i;
         j > 0 && (FuncsInEachFile[j - 1].count < FuncsInEachFile[j].count);
         j--) {
      H2Element tmp;
      tmp.file = FuncsInEachFile[j - 1].file;
      tmp.func = FuncsInEachFile[j - 1].func;
      tmp.count = FuncsInEachFile[j - 1].count;

      FuncsInEachFile[j - 1].file = FuncsInEachFile[j].file;
      FuncsInEachFile[j - 1].func = FuncsInEachFile[j].func;
      FuncsInEachFile[j - 1].count = FuncsInEachFile[j].count;

      FuncsInEachFile[j].file = tmp.file;
      FuncsInEachFile[j].func = tmp.func;
      FuncsInEachFile[j].count = tmp.count;
    }
  }

  // Sorting File::Func

  // Insertion sort is adaptive - it's performance improves on semi-sorted
  // data. Next group/sort functions within the same file in priority order

  int current = -1;

  for (int i = 0; i < kHashTablePrimeSize; i++) {
    if (FilesWithHitCount[i].file == 0)
      break;

    // Insertion sort ordered by files[i]
    for (int j = current + 1; j < kStringTablePrimeSize; j++) {
      if (!FuncsInEachFile[j].file)
        break;
      if (FuncsInEachFile[j].file != FilesWithHitCount[i].file) {
        continue;
      }

      // swap(A[++current], A[j])

      H2Element tmp;
      tmp.file = FuncsInEachFile[current + 1].file;
      tmp.func = FuncsInEachFile[current + 1].func;
      tmp.count = FuncsInEachFile[current + 1].count;

      ++current;

      FuncsInEachFile[current].file = FuncsInEachFile[j].file;
      FuncsInEachFile[current].func = FuncsInEachFile[j].func;
      FuncsInEachFile[current].count = FuncsInEachFile[j].count;

      FuncsInEachFile[j].file = tmp.file;
      FuncsInEachFile[j].func = tmp.func;
      FuncsInEachFile[j].count = tmp.count;
    }
  }

  // To be sorted by line hit-count per line, within the same file::func

  for (int i = 1; i < kStringTablePrimeSize; i++) {
    if (!LinesInEachFunc[i].file)
      continue;
    for (int j = i;
         j > 0 && (LinesInEachFunc[j - 1].count < LinesInEachFunc[j].count);
         j--) {
      H3Element tmp;

      tmp.file = LinesInEachFunc[j - 1].file;
      tmp.func = LinesInEachFunc[j - 1].func;
      tmp.line = LinesInEachFunc[j - 1].line;
      tmp.count = LinesInEachFunc[j - 1].count;
      tmp.line_displacement = LinesInEachFunc[j - 1].line_displacement;
      tmp.bug_descr = LinesInEachFunc[j - 1].bug_descr;

      LinesInEachFunc[j - 1].file = LinesInEachFunc[j].file;
      LinesInEachFunc[j - 1].func = LinesInEachFunc[j].func;
      LinesInEachFunc[j - 1].line = LinesInEachFunc[j].line;
      LinesInEachFunc[j - 1].count = LinesInEachFunc[j].count;
      LinesInEachFunc[j - 1].line_displacement =
          LinesInEachFunc[j].line_displacement;
      LinesInEachFunc[j - 1].bug_descr = LinesInEachFunc[j].bug_descr;

      LinesInEachFunc[j].file = tmp.file;
      LinesInEachFunc[j].func = tmp.func;
      LinesInEachFunc[j].line = tmp.line;
      LinesInEachFunc[j].count = tmp.count;
      LinesInEachFunc[j].line_displacement = tmp.line_displacement;
      LinesInEachFunc[j].bug_descr = tmp.bug_descr;
    }
  }

  // Now group lines within prioritized file::function ordering

  current = -1;

  for (int i = 0; i < kHashTablePrimeSize; i++) {
    if (FuncsInEachFile[i].file == 0)
      break;
    // Insertion sort ordered by file::func
    for (int j = current + 1; j < kStringTablePrimeSize; j++) {
      if (!LinesInEachFunc[j].file)
        break;
      if (!((LinesInEachFunc[j].file == FuncsInEachFile[i].file) &&
            (LinesInEachFunc[j].func == FuncsInEachFile[i].func))) {
        continue;
      }

      // swap( A[++current], A[j] )

      H3Element tmp;

      tmp.file = LinesInEachFunc[current + 1].file;
      tmp.func = LinesInEachFunc[current + 1].func;
      tmp.line = LinesInEachFunc[current + 1].line;
      tmp.count = LinesInEachFunc[current + 1].count;

      tmp.line_displacement = LinesInEachFunc[current + 1].line_displacement;
      tmp.bug_descr = LinesInEachFunc[current + 1].bug_descr;

      ++current;

      LinesInEachFunc[current].file = LinesInEachFunc[j].file;
      LinesInEachFunc[current].func = LinesInEachFunc[j].func;
      LinesInEachFunc[current].line = LinesInEachFunc[j].line;
      LinesInEachFunc[current].count = LinesInEachFunc[j].count;

      LinesInEachFunc[current].line_displacement =
          LinesInEachFunc[j].line_displacement;
      LinesInEachFunc[current].bug_descr = LinesInEachFunc[j].bug_descr;

      LinesInEachFunc[j].file = tmp.file;
      LinesInEachFunc[j].func = tmp.func;
      LinesInEachFunc[j].line = tmp.line;
      LinesInEachFunc[j].count = tmp.count;

      LinesInEachFunc[j].line_displacement =
          LinesInEachFunc[j].line_displacement;
      LinesInEachFunc[j].bug_descr = LinesInEachFunc[j].bug_descr;
    }
  }
}

void PrintCallStack(HANDLE hProcess, StackTrace* trace_pcs);

void SourceErrors::PrintSummary() {
  Printf(
      "\n=== Source Code Details: Unique errors caught at instruction "
      "offset fron source line number, in functions, in the same "
      "file. === \n\n");

  int current_file = 0;
  int current_func = 0;

  for (int i = 0; i < kHashTablePrimeSize; i++) {
    if (LinesInEachFunc[i].file == 0)
      break;
    if (LinesInEachFunc[i].file != current_file) {
      Printf("File: %s \n", StringTable[LinesInEachFunc[i].file]);
      current_file = LinesInEachFunc[i].file;
    }
    if (LinesInEachFunc[i].func != current_func) {
      Printf("\tFunc: %s()\n", StringTable[LinesInEachFunc[i].func]);
      current_func = LinesInEachFunc[i].func;
    }
    Printf(
        "\t\tLine: %d Unique call stacks (paths) leading to error at line "
        "%d "
        ": "
        "%d\n",
        LinesInEachFunc[i].line, LinesInEachFunc[i].line,
        LinesInEachFunc[i].count);

    Printf("\t\t\tBug: %s at instr %d bytes from start of line\n",
           StringTable[LinesInEachFunc[i].bug_descr],
           LinesInEachFunc[i].line_displacement);
  }
}

void CoeOpenError() {
  if (!flags()->continue_on_error)
    return;
  stacks.ResetToZeros();
}

void CoeCloseError(ErrorDescription& edesc) {
  if (!flags()->continue_on_error)
    return;

  if (hash.CurrentErrorWasNotHashed()) {
    stacks.SetEmpty();
    return;
  }
  CoeError* row = &coe_accumulated_errors[hash.CurrentError()];
  row->hit_count += 1;
  stacks.SetEmpty();
  hash.CoeClearCurrentErrorHash();
}

void CoeRawWrite(const char* buffer) {
  DWORD cbWritten = 0;
  bool fSuccess =
      WriteFile(coe_res_file_handle,     // handle for file,stderr,or stdout
                buffer,                   // message
                strlen(buffer),           // message length
                &cbWritten,               // bytes written
                (LPOVERLAPPED) nullptr);  // not overlapped

  RAW_CHECK_MSG(fSuccess,"Internal error duing continue on error: Fail on write()\n");
}

// API called in  void StackTrace::Print() const { }
// defined in sanitizer_common\sanitizer_stacktrace_libcdep.cpp

void CoePrintStack(__sanitizer::StackTrace const* stk_trace) {
  SpinMutexLock l(&fallback_mutex);
  HANDLE hProcess = ::GetCurrentProcess();
  try {
    PrintCallStack(hProcess, (__sanitizer::StackTrace*)stk_trace);
  } catch (char* msg) {
    Write("CoePrintStack(FAIL printing): %s\n", msg);
    UNREACHABLE("Internal error: CoePrintStack");
  }
}

// These two API's save/restore the allocators' quarantine space around
// in proc symbolization, if/when that ever fires due to finding an error.
extern void asan_quarantine_checkpoint();
extern void asan_quarantine_restore_checkpoint();

// We use this class to take a "temp space" in the allocators which we give back
// immediately with quarantine_checkpoint/quarantine_restore_checkpoint.
// https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-syminitialize

class SymHandler {
  HANDLE p;

 public:
  SymHandler(HANDLE process, char const* path = nullptr,
                                  bool intrude = false)
      : p(process) {
    asan_quarantine_checkpoint();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    modules_loading = true;

    if (!SymInitialize(p, path, intrude)) {
      DWORD error = GetLastError();
      Printf("Call to SymInitialize() returned error : %d\n", error);
      RAW_CHECK_MSG(false, "Unexpected failure: Unable to start dbghelp.dll");
    }
  }

  ~SymHandler() {
    if (SymCleanup(p)) {
      // SymCleanup returned success
    } else {
      DWORD error = GetLastError();
      Printf("SymCleanup() returned error : %d\n", error);
      RAW_CHECK_MSG(false, "Unexpected failure: Unable to shutown dbghelp.dll");
    }
    // Recycle everything in quarantine. Effectively garbage collect all 
    // the symbol/module storage from symbolizing an error in proc. Then
    // restore the quarantine space [here] to the check point of user's space 
    // (restore cache and base object).
    asan_quarantine_restore_checkpoint();
    modules_loading = false;
  }
};

void CoeSetSymOptions(DWORD add, DWORD remove = 0) {
  DWORD symOptions = SymGetOptions();
  symOptions |= add;
  symOptions &= ~remove;
  SymSetOptions(symOptions);
}

// The top two OS frames don't get all the symbol
// information because SymHandler *path==nullptr

struct ModuleData {
  wchar_t image_name[MAX_PATH];
  wchar_t module_name[MAX_PATH];
  void* base_address;
  DWORD load_size;
};

// TODO - PR bug filed - create internal_strncpy_s and internal_wcscpy
static const int kMaxPdbs = 1024 * 4;

class GetModuleInfo {
  HANDLE process;

 public:
  GetModuleInfo(HANDLE h) : process(h) {}

  ModuleData operator()(HMODULE module) {
    ModuleData ret;
    MODULEINFO mi;
    wchar_t temp[MAX_PATH];

    GetModuleInformation(process, module, &mi, sizeof(mi));
    ret.base_address = mi.lpBaseOfDll;
    ret.load_size = mi.SizeOfImage;
    GetModuleFileNameEx(process, module, temp, MAX_PATH);
    wcscpy(ret.image_name, temp);
    GetModuleBaseName(process, module, temp, MAX_PATH);
    wcscpy(ret.module_name, temp);

    CHECK(SymLoadModuleExW(process, 0, ret.image_name, ret.module_name,
                           (DWORD64)ret.base_address, ret.load_size, 0, 0));
    return ret;
  }
};

// 4K maximum number of DLL's.
//
// NOTE: for someone to debug applications this large they must
// set HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session
// Manager\DebuggerMaxModuleMsgs The default is 500.
//
// We have tested with up to 4,000 DLL's at a top ISV so far.
// I do *not* want to dynamically reallocate here becuse we don't 
// have the proper stress testing in place.

static ModuleData static_module_info_array[kMaxPdbs];
static HMODULE static_module_handles_array[kMaxPdbs];

void CoeLoadModulesSymbols(HANDLE process, DWORD pid) {
  DWORD cbNeeded = 0;
  if (!EnumProcessModules(process, &static_module_handles_array[0],
                          kMaxPdbs * sizeof(HMODULE), &cbNeeded)) {
    if (cbNeeded > sizeof(static_module_handles_array)) {
      RAW_CHECK_MSG(false,
                    "Internal Asan RT Error: Loading more than 4K modules is "
                    "not supported "
                    "under continue_on_error.");
    }
    RAW_CHECK_MSG(false,
                  "Internal ASan RT Error: Failed to enumerate all the modules "
                  "in process.");
  }
  int module_cnt = (cbNeeded / sizeof(HMODULE));
  GetModuleInfo gmi(process);
  for (int i = 0; i < module_cnt; i++) {
    static_module_info_array[i] = gmi(static_module_handles_array[i]);
  }
}

struct CoeShutDown {
  static const size_t kErrorLines = 512;
  static const size_t kBytesPerLine = 1024;

  char* end;
  char* last;
  size_t last_len;
  size_t line_cnt;
  char* start_next;

  char summary_strings[kErrorLines * kBytesPerLine];

  char* AllocateSummaryString(size_t char_cnt) {
    if (start_next + char_cnt >= end) {
      // Go silent after 100's of errors.
      // You are well and truly hosed.
      return nullptr;
    }
    last = start_next;
    last_len = char_cnt;
    start_next += char_cnt;
    line_cnt += 1;
    return last;
  }

  CoeShutDown() {
    start_next = last = summary_strings;
    // A cache line "64-bytes" margin of error
    end = summary_strings + ((kErrorLines * kBytesPerLine) - 64);
    last_len = 0;
    line_cnt = 0;
  }

  ~CoeShutDown() {
    crt_state_tearing_down = true;

    if (coe_total_error_cnt == 0)
      return;
    
    // First, create an error report prioritized on
    // File,Func,Line hit counts. Provides global
    // overview of all the bugs found.
    source_errors.SortErrors();
    source_errors.PrintSummary();

    // Second, this is a "raw hash table dump" based only on uniqueness
    // of call stacks. Hashing on call stacks cuts out duplicates of
    // full error report spew and provides deep context for each bug.
    // Here we dump that table
    Write(
        "\n>>>Total: %u Unique Memory Safety Issues (based on call "
        "stacks "
        "not source position) <<<\n\n",
        coe_total_error_cnt);
    FlushFileBuffers(coe_res_file_handle);
    int error_ordinal = 0;
    for (int i = 0; i < kHashTablePrimeSize; i++) {
      CoeError* e = &coe_accumulated_errors[i];

      if (e->kind != kErrorKindInvalid) {
        Write("#%d %s Function: %s(Line:%d) \n", error_ordinal++,
              source_errors.StringTable[e->file_name_hash],
              source_errors.StringTable[e->func_name_hash], e->line_no);

        Write("\tRaw HitCnt: %d  ", e->hit_count);

        if (e->kind == kErrorKindGeneric) {
          Write("On Reference: %s \n",
                source_errors.StringTable[e->error_desc_hash]);
        } else {
          Write("\n");
        }
        FlushFileBuffers(coe_res_file_handle);
      }
    }
  }
};

CoeShutDown coe_global_lifetime;

u16 CoeStringFindOrIntern(const char* name) {
  CHECK(name);
  u16 xhash = hash.CoeStringHash(name);
  if (source_errors.StringTable[xhash]) {
    if (!internal_strcmp(name, source_errors.StringTable[xhash])) {
      return xhash;
    } else {
      // Linear probe, don't cons up collision chains
      int i = (xhash + 1) % kStringTablePrimeSize;
      CHECK(i != xhash);
      while (source_errors.StringTable[i] && (i < xhash)) {
        if (!internal_strcmp(name, source_errors.StringTable[i])) {
          return i;
        }
        i += 1;
      }
      CHECK(i != xhash);  // realloc
      xhash = i;
    }
  }

  size_t length = internal_strlen(name);
  CHECK(length);

  // Allocate from, and copy to static .data segmment

  char* unique_string = coe_global_lifetime.AllocateSummaryString(length + 4);
  internal_memcpy(unique_string, name, length);
  source_errors.StringTable[xhash] = unique_string;
  return xhash;
}

// Per error: accumulation of symbolized call stack information.
// {file,function,line} in each frame on the stack at an "event".
// Events like point of allocation, point of free and point of 
// error detection.

class CoeStack {
 public:
  CoeStack() : current_frame_(0) {}
  char* CurrentFunctionNamePtr() {
    return &(function_names_[current_frame_][0]);
  }
  void IncCurrentFrame() { current_frame_++; }
  void DecCurrentFrame() { current_frame_++; }
  void ReSetCurrentFrame() { current_frame_ = 0; }
  int GetCurrentFrame() { return current_frame_; }
  char* CurrentFileNamePtr() { return &(file_names_[current_frame_][0]); }
  int* CurrentLineNumberPtr() { return &(line_numbers_[current_frame_]); }

 private:
  // tmep. memory only used, as a stack local instantiation,
  // and only when there's a memory safety error.
  char function_names_[kMaxStackDepthForFormat][kMaxFuncOrFileNmaeLen];
  char file_names_[kMaxStackDepthForFormat][kMaxFuncOrFileNmaeLen];
  int line_numbers_[kMaxStackDepthForFormat];
  int current_frame_;
};

void FormatStackFrameStrings(CoeStack* stk, HANDLE hProcess,
                             const uptr trace_return_pc) {
  IMAGEHLP_LINE64 line = {0};
  line.SizeOfStruct = sizeof line;
  DWORD offset_from_symbol = 0;

  uptr pc = StackTrace::GetPreviousInstructionPc(
      (uptr)trace_return_pc);

  Symbol func_sym(hProcess, (DWORD64)pc);

  strncpy_s(stk->CurrentFunctionNamePtr(), kMaxFuncOrFileNmaeLen,
            func_sym.Name(), kMaxFuncOrFileNmaeLen - 2);

  // entered a critical section in the caller thus
  // creating a sequentialized access to dbghelp.dll

  SymSetScopeFromAddr(hProcess, (DWORD64)pc);

  if (SymGetLineFromAddr64(hProcess, (DWORD64)pc, &offset_from_symbol, &line)) {
    // Cache the file an line number
    size_t file_name_len = strnlen_s(line.FileName, kMaxFuncOrFileNmaeLen);
    CHECK(file_name_len + 2 < kMaxFuncOrFileNmaeLen);
    strncpy_s(stk->CurrentFileNamePtr(), kMaxFuncOrFileNmaeLen, line.FileName,
              file_name_len);
    *(stk->CurrentLineNumberPtr()) = line.LineNumber;

  } else {
    strncpy_s(stk->CurrentFileNamePtr(), kMaxFuncOrFileNmaeLen, "Windows",
              strlen("Windows"));
    *(stk->CurrentLineNumberPtr()) = 0;
  }
}

void PrintCallStack(HANDLE hProcess, StackTrace* trace_pcs) {
  CHECK(trace_pcs->size > 0);

  CoeStack stk;
  CHECK(stk.GetCurrentFrame() == 0);

  if (trace_pcs->size > kPrintStackDepthLimit) {
    Write("Call stack output is too deep \n");
    // TODO - do we put linker flag /STACKSIZE:20000 in the objs for ASan
    return;
  }
  // We use the skip and size factors Google used to get the stack
  for (u32 i = 0; i < trace_pcs->size - 1; i++) {
    if (trace_pcs->trace[i]) {
      FormatStackFrameStrings(&stk, hProcess, trace_pcs->trace[i]);
    }
    stk.IncCurrentFrame();
  }

  CHECK(trace_pcs->size - 1 == stk.GetCurrentFrame());

  size_t size_max_name = 0;
  size_t stack_frame_cnt = stk.GetCurrentFrame();

  stk.ReSetCurrentFrame();

  for (size_t index = 0; index < stack_frame_cnt; index++) {
    size_t len = strnlen(stk.CurrentFunctionNamePtr(), kMaxFuncOrFileNmaeLen);
    stk.IncCurrentFrame();
    if (len > size_max_name) {
      size_max_name = len;
    }
  }

  stk.ReSetCurrentFrame();
  if (size_max_name > kMaxFuncFileLineLen) {
    for (size_t index = 0; index < stack_frame_cnt; index++) {
      Write("\t #%d  %s \n", index, stk.CurrentFunctionNamePtr());
      Write("\t\t %s", stk.CurrentFileNamePtr());
      if (*(stk.CurrentLineNumberPtr())) {
        Write("(%d)\n", *(stk.CurrentLineNumberPtr()));
      } else {
        Write("\n");
      }
      stk.IncCurrentFrame();
    }
  } else {
    for (size_t index = 0; index < stack_frame_cnt; index++) {
      Write("\t #%d  %s  ", index, stk.CurrentFunctionNamePtr());
      for (size_t i = 0;
           i <= size_max_name - strlen(stk.CurrentFunctionNamePtr()); i++) {
        Write(" ");
      }
      Write(" %s", stk.CurrentFileNamePtr());
      if (*(stk.CurrentLineNumberPtr())) {
        Write("(%d)\n", *(stk.CurrentLineNumberPtr()));
      } else {
        Write("\n");
      }
      stk.IncCurrentFrame();
    }
  }
  Write(" \n");
}

// Called when we "report" a unique error, in terms of hashed, call-stacks.
// This creates a row in a table, backed by storage in the .data section.
// Using .data becuase VirtualAlloc() is a 64K granularity on Windows

void ASanLiteCacheError(const ErrorDescription& error) {
  
  if (hash.CurrentErrorWasNotHashed()) {
    return;
  }
  //  Placement new - a typed row in the table of cached errors.
  CoeError* cached_error =
      new (&coe_accumulated_errors[hash.CurrentError()])
          CoeError(error.kind);
  if (error.kind == kErrorKindGeneric) {
    cached_error->error_desc_hash =
        CoeStringFindOrIntern(error.Base.scariness.GetDescription());
  }

  // CloseError will increment, indicating a dynamic
  // hit count regardless of duplication
  cached_error->hit_count = 0;
  coe_total_error_cnt++;
  if (error.kind == kErrorKindGeneric) {
    // Report("ERROR:AddressSanitizer: %s on address %p at pc %p bp %p sp")
    cached_error->addr = error.Generic.addr_description.Address();
    cached_error->pc = error.Generic.pc;
    cached_error->bp = error.Generic.bp;
    cached_error->sp = error.Generic.sp;
  }
}

void CoeInitializeDbgHelp() {
  HANDLE hProcess = ::GetCurrentProcess();
  // When an executable is run from a location different from the one where it
  // was originally built, we may not see the nearby PDB files.
  // To work around this, I append the directory of the main module
  // to the symbol search path.  All the failures below are not fatal.
  const size_t kSymPathSize = 2048;
  static wchar_t path_buffer[kSymPathSize + 1 + MAX_PATH];

  if (!SymGetSearchPathW(GetCurrentProcess(), path_buffer, kSymPathSize)) {
    Report("*** WARNING: Failed to SymGetSearchPathW ***\n");
    return;
  }
  size_t sz = internal_wcslen(path_buffer);
  if (sz) {
    CHECK_EQ(0, wcscat_s(path_buffer, L";"));
    sz++;
  }
  DWORD res = GetModuleFileNameW(NULL, path_buffer + sz, MAX_PATH);
  if (res == 0 || res == MAX_PATH) {
    Report("*** WARNING: Failed on getting the EXE directory ***\n");
    return;
  }
  // Write the zero character in place of the last backslash to get the
  // directory of the main module at the end of path_buffer.
  wchar_t* last_bslash = wcsrchr(path_buffer + sz, L'\\');
  CHECK_NE(last_bslash, 0);
  *last_bslash = L'\0';
  if (!SymSetSearchPathW(GetCurrentProcess(), path_buffer)) {
    Report("*** WARNING: Failed to SymSetSearchPathW()\n");
    return;
  }

  // Set magic dbghelp incantations
  CoeSetSymOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME |
                        SYMOPT_DEFERRED_LOADS);
  // Load the symbols for symbolizing call stacks
  CoeLoadModulesSymbols(hProcess, GetCurrentProcessId());
}

// API - to override AsanReportErrror() which is defined
// in the symbolizer (gone for COE) and called in
// asan_errors.cpp

static void* trace_lookahead_buffer[kMaxDepthForLookAhead];

void CoeReportError(ErrorDescription& current_error) {
  // Look ahead for stack size
  u32 size = CaptureStackBackTrace(1, kStackTraceMax,
                                   (void**)&trace_lookahead_buffer[0], 0);
  CHECK(size > 0);
  // If the stack will possibly overflow becuase the application
  // is super-recursive (e.g., spec2k6\perlbmk op_pat.t) AND we
  // have turned on -fsanitize, then we can't call into dbghlp
  // and add 20+ more frames with locals.
  if (size > (kStackTraceMax - 4)) {
    Printf("Stack too deep for symbolized stack reporting.\n");
    Printf(
        "See MSDN: link /STACK:reserve[,commit] ...to increase the stack "
        "size.\n");
    Report("%s\n", "NOT ABORTING");
    return;
  }

  Printf(
      "================================================================="
      "\n");

  // Allocate space in the table[hash], copy e and set hit count.
  ASanLiteCacheError(current_error);

  // Prepare for in process symbolize and report
  HANDLE hProcess = ::GetCurrentProcess();
  SymHandler handler(hProcess);
  CoeInitializeDbgHelp();

  current_error.Print();
}

static const u32 kMaxLogFileStringSize = 4 * 1024;
static wchar_t logfile_name[kMaxLogFileStringSize];
static const u32 kMaxLogFileWChars = kMaxLogFileStringSize / sizeof(short);

static wchar_t* GetEnvironmentVariableValue(LPCWSTR wszName) {
  DWORD cntNeeded = GetEnvironmentVariableW(wszName, nullptr, 0);
  if (!cntNeeded)
    return nullptr;

  if (cntNeeded >= (kMaxLogFileWChars - sizeof(wchar_t))) {
    Printf("Log file name is large than %d characters.\n",
           kMaxLogFileStringSize / 2);
    Printf("No logfile created for environment variable COE_LOG_FILE\n");
    return nullptr;
  }
  size_t character_cnt_written =
      GetEnvironmentVariableW(wszName, logfile_name, cntNeeded);
  if (character_cnt_written != cntNeeded - 1) {
    RAW_CHECK_MSG(
        false,
        "Unexpected failure: get COE_LOG_FILE environment variable value");
  }

  return logfile_name;
}

static void CoeDynamicallyLoadDbghelp() {
  // Flags were parsed becuase of calls ordered
  // previously in AsanInitInternal()
  if (flags()->continue_on_error) {
    hmDbgHelp = LoadLibraryA("dbghelp.dll");
    if (nullptr == hmDbgHelp) {
      UNREACHABLE("Unable to load the DbgHelp DLL");
    }

#define DBGHELP_IMPORT(name)                      \
    do {                                          \
      name = reinterpret_cast<decltype(::name)*>( \
          GetProcAddress(hmDbgHelp, #name));      \
      CHECK(name != nullptr);                     \
    } while (0)

    DBGHELP_IMPORT(SymCleanup);
    DBGHELP_IMPORT(SymGetLineFromAddr64);
    DBGHELP_IMPORT(SymGetOptions);
    DBGHELP_IMPORT(SymGetSearchPathW);
    DBGHELP_IMPORT(SymGetSymFromAddr64);
    DBGHELP_IMPORT(SymInitialize);
    DBGHELP_IMPORT(SymLoadModuleExW);
    DBGHELP_IMPORT(SymSetOptions);
    DBGHELP_IMPORT(SymSetScopeFromAddr);
    DBGHELP_IMPORT(SymSetSearchPathW);
#undef DBGHELP_IMPORT
  }
}

HANDLE CoeCreateLogFile(const wchar_t* wszResultsFilePath) {
  CHECK(wszResultsFilePath);
  auto coe_res_file_handle =
      ::CreateFileW(wszResultsFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);

  if (coe_res_file_handle != INVALID_HANDLE_VALUE) {
    return coe_res_file_handle;
  }

  LPWSTR coe_temp_file_path = (LPWSTR)wszResultsFilePath;
  u32 dwError = GetLastError();
  Write(
      "\nFailed to open file %ws. Internal error %x.\nTrying to default to "
      "a newly created temp file.",
      wszResultsFilePath, dwError);
  // ...otherwise, create a tmp file in the %TMP% then %TEMP% directories
  // Windwos specifies 14 on MSDN
  auto tmp_path_wchar_cnt = GetTempPathW(MAX_PATH - 14, coe_temp_file_path);
  if (0 == tmp_path_wchar_cnt) {
    Write("\nFailed to get temp directory. No log file. Internal error %x\n",
          GetLastError());
    return nullptr;
  }

  if (!GetTempFileNameW(coe_temp_file_path, L"Asan_COE", 0,
                        &coe_temp_file_path[tmp_path_wchar_cnt])) {
    Write("\nFailed to get temp file name. Internal error %x\n", GetLastError());
    return nullptr;
  }

  auto h_coe_tmp_file = CreateFileW(coe_temp_file_path, GENERIC_WRITE, 0, NULL,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if (h_coe_tmp_file == INVALID_HANDLE_VALUE) {
    Write("\nFailed to open temp file %ws with error %x\n", coe_temp_file_path,
          GetLastError());
    // failed...but not from a lack of effort
    return nullptr;
  }

  return h_coe_tmp_file;
}


void InitializeCOE() {
  // Called from AsanInitInternal() in asan\asan_rtl.cpp 
  const wchar_t* wszResultsFilePath =
      GetEnvironmentVariableValue(coe_wcs_log_file_name);
  if (wszResultsFilePath) {
    if (!(coe_res_file_handle = CoeCreateLogFile(wszResultsFilePath))) {
      RAW_CHECK_MSG(
          false,
          "Internal error duing continue on error: Failed log file creation.\n");
    }
    // Ensure down stream functionaly if user only specified a log file name
    flags()->continue_on_error = true;
  }
  else if (0 != flags()->continue_on_error) {
    // No log file specified. Provide a choice of stdout or stderr.
    coe_res_file_handle = GetStdHandle(
        flags()->continue_on_error == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
  }
  // This must take place after InitializeFlags() in AsanInitInteral()
  // Global constructor ordering is link line dependent.
  // Calling what follows, in a construcor, caused race conditions with parsing flags.
  CoeDynamicallyLoadDbghelp();
}

}  // namespace __asan

// Windows platform dependant implementation of a COE Class interface

namespace __coe_win {

bool ModulesLoading() { return modules_loading; }

bool ContinueOnError() { return __asan::COE(); }

bool CrtTearingDown() { return crt_state_tearing_down; }

void OpenError() {
  CHECK(__asan::COE());
  __asan::CoeOpenError();
}

void CloseError(__asan::ErrorDescription& e) {
  CHECK(__asan::COE());
  __asan::CoeCloseError(e);
}

void ReportError(__asan::ErrorDescription& e) {
  if (__asan::COE())
    __asan::CoeReportError(e);
}

bool ErrorIsHashed(const char* category) {
  CHECK(__asan::COE());
  return __asan::hash.CoeErrorIsHashed(category);
}

void ReportErrorSummary(const char* bug_descr,
                        const __sanitizer::StackTrace* stack) {
  if (__asan::COE())
    __asan::source_errors.ReportOneErrorSummary(bug_descr, stack);
}

void RawWrite(const char* buffer) {
  if (__asan::COE())
    __asan::CoeRawWrite(buffer);
}

void StackInsert(const __sanitizer::StackTrace* stk_trace) {
  if (__asan::COE())
    __asan::stacks.Accumulate(stk_trace);
}

void PrintStack(__sanitizer::StackTrace const* stk) {
  if (__asan::COE())
    __asan::CoePrintStack(stk);
}

}  // namespace __coe_win


#include "asan_continue_on_error.h"
CoePlatformDependent coe;

#endif  // SANITIZER_WINDOWS
