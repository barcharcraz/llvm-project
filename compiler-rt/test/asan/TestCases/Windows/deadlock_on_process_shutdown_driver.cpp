#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <system_error>
#include <windows.h>

struct CommandAndMessage {
  LPSTR Command;
  const char *Message;

  CommandAndMessage(std::string command, const char *message) : Message(message) {
    Command = strdup(command.c_str());
  }
};

int main(int argc, const char *argv[]) {

  // Name and path to test command
  std::string testName = argv[1];
  std::string processHeapTest = "cmd.exe /C " + testName;
  std::string userHeapTest = processHeapTest + " \"UserHeap\"";

  static const CommandAndMessage tests[] = {{processHeapTest, "Process Heap Test failure"}, {userHeapTest, "User Heap Test failure"}};

  // start the deadlock exe 5 times for both process and user heap manipulations to try and see if any deadlock on shutdown
  for (const auto &test : tests) {
    for (auto i = 0; i < 5; ++i) {
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

  fputs("Success.\n", stderr);

  return EXIT_SUCCESS;
}