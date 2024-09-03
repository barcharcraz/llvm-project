#include "Windows.h"
#include <iostream>
#include <sanitizer/asan_interface.h>

extern "C" void __asan_on_error() { std::cerr << "__asan_on_error called\n"; }

void Callback(const char *c) { std::cerr << "SetCallback called\n"; }

extern "C" __declspec(dllexport) void SetErrorReportCallback() {
  __asan_set_error_report_callback(Callback);
}