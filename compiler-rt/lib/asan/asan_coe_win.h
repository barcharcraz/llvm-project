//===-- asan_coe_win.h ----------------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// ASan-private header for asan_allocator.cpp.
//===----------------------------------------------------------------------===//
#pragma once

#if SANITIZER_WINDOWS
#include "asan_errors.h"
#include "sanitizer_common\sanitizer_stacktrace.h"

namespace __asan {
  void InitializeCOE();
}

// Platform abstract declaration used for instatiation 
// in a sealed class with no use of virtual. 
// TODO provide a convenince macro using ## so this 
// just becomes namespace __coe_foo { PLATFORM_DECL }
namespace __coe_win {

bool ContinueOnError();
bool ModulesLoading();
bool CrtTearingDown();
void OpenError();
void CloseError(__asan::ErrorDescription &e);
bool ErrorIsHashed(const char *category);
void ReportError(__asan::ErrorDescription &e);
void ReportErrorSummary(const char *bug_descr,
                        const __sanitizer::StackTrace *stack);
void StackInsert(const __sanitizer::StackTrace *stk_trace);
void PrintStack(__sanitizer::StackTrace const *stk);
void RawWrite(const char *buffer);
} 

// Platform instantiation
struct COE_Windows {
  // State
  bool ContinueOnError() { return __coe_win::ContinueOnError(); }
  bool ModulesLoading() { return __coe_win::ModulesLoading(); }
  bool CrtTearingDown() { return __coe_win::CrtTearingDown(); }

  // Hashing 
  void OpenError() { __coe_win::OpenError(); }
  void CloseError(__asan::ErrorDescription &e) { __coe_win::CloseError(e); }
  bool ErrorIsHashed(const char *category) {
    return __coe_win::ErrorIsHashed(category);
  }

  // Reporting
  void ReportError(__asan::ErrorDescription &e) { __coe_win::ReportError(e); }
  void ReportErrorSummary(const char *bug_descr,
                          const __sanitizer::StackTrace *stack) {
    __coe_win::ReportErrorSummary(bug_descr, stack);
  }

  // Call Stacks
  void StackInsert(const __sanitizer::StackTrace *stk_trace) {
    __coe_win::StackInsert(stk_trace);
  }
  void PrintStack(__sanitizer::StackTrace const *stk) {
    __coe_win::PrintStack(stk);
  }

  // Override sanitizer_printf TODO: move to sanitizer_common
  void RawWrite(const char *buffer) { __coe_win::RawWrite(buffer); }
};
#endif