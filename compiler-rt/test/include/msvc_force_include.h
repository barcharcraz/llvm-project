//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#pragma once

#ifndef NO_TEST_ENVIRONMENT_PREPARER

#include <crtdbg.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

void __prepare_test_environment() {
    // avoid assertion dialog boxes
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _CALL_REPORTFAULT);

    // set stdout to be unbuffered
    setvbuf(stdout, 0, _IONBF, 0);
}

#pragma section(".CRT$XCU", long, read)
__declspec(allocate(".CRT$XCU")) void (*__pte)() = __prepare_test_environment;

#ifdef __cplusplus
}
#endif

#endif // NO_TEST_ENVIRONMENT_PREPARER
