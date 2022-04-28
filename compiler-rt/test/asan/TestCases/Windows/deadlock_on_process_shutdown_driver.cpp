#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <system_error>
#include <vector>
#include <windows.h>

struct CommandAndMessage {
  LPSTR Command;
  const char *Message;

  CommandAndMessage(LPSTR command, const char *message) : Command(command), Message(message) {}
};

int main(int argc, const char *argv[]) {

  static const CommandAndMessage tests[] = {{"cmd.exe /C deadlock_on_process_shutdown.exe", "Process Heap Test failure"}, {"cmd.exe /C deadlock_on_process_shutdown.exe \"UserHeap\"", "User Heap Test failure"}};

  // start the deadlock exe 50 times for both process and user heap manipulations to try and see if any deadlock on shutdown
  for (const auto &test : tests) {
    for (auto i = 0; i < 50; ++i) {
      STARTUPINFO si{};
      PROCESS_INFORMATION pi{};
      if (!CreateProcess(nullptr, test.Command, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << test.Message << std::endl;
        std::cerr << std::system_category().message(GetLastError()) << std::endl;
        return EXIT_FAILURE;
      }

      // Wait until child process exits, wait time in milliseconds
      auto processExitStatus = WaitForSingleObject(pi.hProcess, 500);

      // Close process and thread handles
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);

      if (processExitStatus == WAIT_ABANDONED || processExitStatus == WAIT_TIMEOUT || processExitStatus == WAIT_FAILED) {
        std::cerr << test.Message << std::endl;
        std::cerr << "Process wait failed" << std::endl;
        return EXIT_FAILURE;
      }
    }
  }

  return EXIT_SUCCESS;
}