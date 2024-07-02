//===-- asan_continue_on_error.h ----------------------------------------*- C++ -*-===//
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
#ifndef ASAN_CONTINUE_ON_ERROR_H
#define ASAN_CONTINUE_ON_ERROR_H


#if SANITIZER_WINDOWS
#include <asan\asan_coe_win.h>
#else
#include <asan\asan_coe_default.h>
#endif

namespace CoeInterface {
    template <class Target>
    class COEClass {
     public:

      // State

      bool ContinueOnError() { return platform.ContinueOnError(); }
      bool CrtTearingDown() { return platform.CrtTearingDown(); }
      bool ModulesLoading() { return platform.ModulesLoading(); }

      // Errors

      void OpenError() { platform.OpenError(); }
      void CloseError(__asan::ErrorDescription& e) { platform.CloseError(e); }
      bool ErrorIsHashed(const char* category) {
        return platform.ErrorIsHashed(category);
      }

      // Report

      void ReportError(__asan::ErrorDescription& e) { platform.ReportError(e); }
      void ReportErrorSummary(const char* bug_descr,
                              const __sanitizer::StackTrace* stack) {
        platform.ReportErrorSummary(bug_descr, stack);
      }

      // Call Stack

      void StackInsert(const __sanitizer::StackTrace* stk_trace) {
        platform.StackInsert(stk_trace);
      }
      void PrintStack(__sanitizer::StackTrace const* stk,
                      __sanitizer::InternalScopedString *out) {
        platform.PrintStack(stk,out);
      }
      void RawWrite(const char* buffer) { platform.RawWrite(buffer); }

      COEClass() : platform(){};
     private:
      Target platform;
    };
}  // namespace CoeInterface

#if SANITIZER_WINDOWS
using CoePlatformDependent = CoeInterface::COEClass<COE_Windows>;
#else
using CoePlatformDependent = CoeInterface::COEClass<COE_Default>;
#endif

// Sealed instance that's platform dependent without virtual

extern CoePlatformDependent coe;


#endif  // ASAN_CONTINUE_ON_ERROR_H
