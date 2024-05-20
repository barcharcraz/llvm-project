
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t_sub.exe
// RUN: %clang_asan /std:c++17 /DMAIN_PROCESS /EHsc -Od %s -Fe%t
// RUN: env COE_LOG_FILE=coe_subprocess.log %run %t %t_sub.exe 2>&1 | FileCheck %s --check-prefix=CHECK-NORMAL
// RUN: %clang_asan /std:c++17 /DMAIN_PROCESS /DPROGRAMMATIC_OPTION /EHsc -Od %s -Fe%t
// RUN: env COE_LOG_FILE= %run %t %t_sub.exe 2>&1 | FileCheck %s --check-prefix=CHECK-PROGRAMMATIC

#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

#ifdef MAIN_PROCESS
char *exeName;
std::vector<DWORD> pids;
constexpr int numSubprocesses = 5;
std::mutex vectorMutex;

void launchSubprocess() {
  HANDLE hRead, hWrite;

  SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  sa.lpSecurityDescriptor = NULL;
  sa.bInheritHandle = TRUE;

  if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
    std::cerr << "CreatePipe failed\n";
    return;
  }

  STARTUPINFO si;
  ZeroMemory(&si, sizeof(STARTUPINFO));
  si.cb = sizeof(STARTUPINFO);
  si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
  si.hStdOutput = hWrite;
  si.hStdError = hWrite;
  si.wShowWindow = SW_HIDE;

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

  if (!CreateProcess(NULL, exeName, NULL, NULL, TRUE, 0, NULL, NULL, &si,
                     &pi)) {
    std::cerr << "CreateProcess failed\n";
    return;
  }
  WaitForSingleObject(pi.hProcess, 30000);

  {
    std::lock_guard lock(vectorMutex);
    pids.emplace_back(pi.dwProcessId);
  }

  CloseHandle(hWrite);

  DWORD bytesRead;
  char buffer[4096];
  std::string result;
  while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
    if (bytesRead == 0)
      break;
    buffer[bytesRead] = '\0';
    result += buffer;
  }

  std::cerr << result;

  CloseHandle(hRead);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
}
#endif

double x[5];

#ifdef PROGRAMMATIC_OPTION
extern "C" const char *__asan_default_options() {
  SetEnvironmentVariableA("COE_LOG_FILE", "coe_subprocess_programmatic.log");
  return "";
}
#endif

int main(int argc, char **argv) {
#ifdef MAIN_PROCESS
  std::vector<std::thread> threads;
  exeName = argv[1];
#endif
  auto returnCode = (int)x[5];

#ifdef MAIN_PROCESS
  pids.reserve(numSubprocesses);
  for (int i = 0; i < numSubprocesses; ++i) {
    threads.push_back(std::thread(launchSubprocess));
  }

  for (auto &thread : threads) {
    thread.join();
  }
  std::string baseFileName = "coe_subprocess.log";
#endif

#ifdef PROGRAMMATIC_OPTION
  baseFileName = "coe_subprocess_programmatic.log";
#endif

  std::cerr << "Success\n";

#ifdef MAIN_PROCESS
  // should be 6 log files present, one named coe_subprocess.log and the
  // others coe_subprocess.log.<pid>
  auto fileCount = 0;
  if (std::filesystem::exists(baseFileName)) {
    std::cerr << baseFileName << "\n";
    ++fileCount;
  } else {
    std::cerr << "File " << baseFileName << " does not exist\n";
  }
  for (const auto pid : pids) {
    std::string expectedFileName = baseFileName + "." + std::to_string(pid);
    if (!std::filesystem::exists(expectedFileName)) {
      std::cerr << "File with PID " << expectedFileName << " does not exist\n";
      break;
    } else {
      std::cerr << expectedFileName << "\n";
      ++fileCount;
    }
  }

  if (fileCount != numSubprocesses + 1) {
    std::cerr << "Failed\n";
  }
#endif
  // CHECK-COUNT-6: Success
  // CHECK-NORMAL-COUNT-6: {{coe_subprocess.log.*}}
  // CHECK-PROGRAMMATIC-COUNT-6: {{coe_subprocess_programmatic.log.*}}
  // CHECK-NOT: Failed
  // CHECK-NOT: File {{.*}} does not exist
  // CHECK-NOT: CreateProcess failed
  // CHECK-NOT: CreatePipe failed
  return returnCode;
}