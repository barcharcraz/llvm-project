// MSVC-DISABLED: Flaky due to permissions on Windows CI

// RUN: %clang_cl_asan /D_DISABLE_VECTOR_ANNOTATION /D_DISABLE_STRING_ANNOTATION -Od %s -Fe%t
// RUN: %clang_cl_asan /D_DISABLE_VECTOR_ANNOTATION /D_DISABLE_STRING_ANNOTATION /DTEST_DRIVER -Od %s -Fe%t_driver.exe
// RUN: not %run %t_driver.exe %t 2>&1 | FileCheck %s

// Annotations disabled due to libconcrt.lib compilation mismatch

#if TEST_DRIVER
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <system_error>
#include <windows.h>

struct CommandAndMessage {
  LPSTR Command;
  const char *Message;

  CommandAndMessage(std::string command, const char *message)
      : Message(message) {
    Command = strdup(command.c_str());
  }
};

int main(int argc, const char *argv[]) {

  // Name and path to test command
  std::string testName = argv[1];
  std::string processHeapTest = "cmd.exe /C " + testName;
  std::string userHeapTest = processHeapTest + " \"UserHeap\"";

  static const CommandAndMessage tests[] = {
      {processHeapTest, "Process Heap Test failure"},
      {userHeapTest, "User Heap Test failure"}};

  // start the deadlock exe 5 times for both process and user heap manipulations to try and see if any deadlock on shutdown
  for (const auto &test : tests) {
    for (auto i = 0; i < 5; ++i) {
      STARTUPINFO si{};
      PROCESS_INFORMATION pi{};
      if (!CreateProcess(nullptr, test.Command, nullptr, nullptr, FALSE, 0,
                         nullptr, nullptr, &si, &pi)) {
        std::cerr << test.Message << std::endl;
        std::cerr << std::system_category().message(GetLastError())
                  << std::endl;
        return EXIT_FAILURE;
      }

      // Wait until child process exits, wait time in milliseconds
      auto processExitStatus = WaitForSingleObject(pi.hProcess, 500);

      // Close process and thread handles
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);

      if (processExitStatus == WAIT_ABANDONED ||
          processExitStatus == WAIT_TIMEOUT ||
          processExitStatus == WAIT_FAILED) {
        std::cerr << test.Message << std::endl;
        std::cerr << "Process wait failed" << std::endl;
        return EXIT_FAILURE;
      }
    }
  }

  fputs("Success.\n", stderr);

  return EXIT_SUCCESS;
}
#else
#include <iostream>
#include <ppl.h>
#include <windows.h>

using namespace concurrency;

void UserHeapManipulations() {
  // Create user heap and do some operations on it
  HANDLE heap = HeapCreate(0, 0, 0);
  void *ptr = HeapAlloc(heap, 0, 4);
  void *ptr2 = HeapReAlloc(heap, 0, ptr, 0);
  HeapFree(heap, 0, ptr2);
  HeapDestroy(heap);
}

int main(int argc, char *argv[]) {
  concurrency::parallel_for(0, 100, [argc, &argv](int) {
    // Arguments are passed from deadlock_on_process_shutdown_driver.cpp
    if (argc >= 2) {
      UserHeapManipulations();
    }
  });

  // Message is printed from deadlock_on_process_shutdown_driver.cpp success
  // CHECK: Success.
}
#endif