//===-- asan_coe_default.h ----------------------------------------*- C++
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
#ifndef ASAN_COE_DEFAULT_H
#define ASAN_COE_DEFAULT_H


#include "asan_errors.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "sanitizer_common/sanitizer_common.h"

// Defualt to null implementation

struct COE_Default {
  // State
  bool ContinueOnError() { return false; }
  bool ModulesLoading() { return false; }
  bool CrtTearingDown() { return false; }

  // Hashing errors
  void OpenError() {}
  void CloseError(__asan::ErrorDescription &e) {}
  bool ErrorIsHashed(const char *category) { return false; }

  // Reporting in process
  void ReportError(__asan::ErrorDescription &e) {}
  void ReportErrorSummary(const char *bug_descr,
                          const __sanitizer::StackTrace *stack) {}
  // Call stacks
  void StackInsert(const __sanitizer::StackTrace *stk_trace) {}
  void PrintStack(__sanitizer::StackTrace const *stk,
                  __sanitizer::InternalScopedString *out) {}

  // Raw output to presected COE resource handle
  void RawWrite(const char *buffer) {}
};

#endif ASAN_COE_DEFAULT_H