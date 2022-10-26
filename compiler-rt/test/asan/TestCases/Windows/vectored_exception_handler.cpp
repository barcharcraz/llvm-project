// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t AsanReportTest 2>&1 | FileCheck %s --check-prefix=CHECK1
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t UserHandlerTest 2>&1 | FileCheck %s --check-prefix=CHECK2
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t ManyHandlersTest 2>&1 | FileCheck %s --check-prefix=CHECK3
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t MultipleExceptionTest 2>&1 | FileCheck %s --check-prefix=CHECK4
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t NestedShadowExceptionTest 2>&1 | FileCheck %s --check-prefix=CHECK5
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t RemovalTest 2>&1 | FileCheck %s --check-prefix=CHECK6
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t RemoveOneTest 2>&1 | FileCheck %s --check-prefix=CHECK7
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t RemoveAfterFirstExceptionTest 2>&1 | FileCheck %s --check-prefix=CHECK8
// RUN: %clang_asan /std:c++17 /EHsc -Od %s -Fe%t && not %run %t VeryManyHandlers 2>&1 | FileCheck %s --check-prefix=CHECK9

// ASAN only adds VEH on amd64
// REQUIRES: asan-64-bits
#include <algorithm>
#include <iostream>
#include <sanitizer/asan_interface.h>
#include <string>
#include <vector>
#include <windows.h>

#include <Psapi.h>
#include <dbghelp.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp")

extern "C" void __asan_set_shadow_f2(size_t addr, size_t size);

struct SymbolAndFrameNumber {
  std::string symbol;
  int frameNumber;

  bool operator!=(const SymbolAndFrameNumber &rhs) {
    return !(symbol == rhs.symbol && frameNumber == rhs.frameNumber);
  }
};

enum class ThrowType {
  None,
  Regular,
  Shadow
};

char *problematicMemory;
int order = 0;
constexpr int maxFrames = 20;
constexpr int callFirst = 1;
constexpr int callLast = 0;
constexpr int maxNameLength = 1024;
ThrowType exceptionToThrow = ThrowType::None;
std::vector<PVOID> handlers;
std::vector<SymbolAndFrameNumber> sequence;
std::vector<SymbolAndFrameNumber> expected;
std::vector<SymbolAndFrameNumber> recordedStackTrace;

// Forces shadow bytes to have stack-buffer-overflow for asan report
void PopulateShadowMemoryWithIssue() {
  size_t shadowOffset;
  size_t shadowScale;
  __asan_get_shadow_mapping(&shadowScale, &shadowOffset);
  size_t addr = (((size_t)problematicMemory) >> shadowScale) + shadowOffset;
  __asan_set_shadow_f2(addr, 1);
}

std::string GetSymbol(HANDLE process, DWORD64 address) {
  IMAGEHLP_SYMBOL64 *sym((IMAGEHLP_SYMBOL64 *)::operator new(sizeof(IMAGEHLP_SYMBOL64) + maxNameLength));
  memset(sym, '\0', sizeof(*sym) + maxNameLength);
  sym->SizeOfStruct = sizeof(*sym);
  sym->MaxNameLength = maxNameLength;
  DWORD64 displacement;

  SymGetSymFromAddr64(process, address, &displacement, sym);
  if (*sym->Name == '\0') {
    return "couldn't symbolize";
  }
  std::vector<char> undecoratedName(maxNameLength);
  UnDecorateSymbolName(sym->Name, &undecoratedName[0], maxNameLength, UNDNAME_COMPLETE);
  return std::string(&undecoratedName[0], strlen(&undecoratedName[0]));
}

void RecordStackTrace(EXCEPTION_POINTERS *ep) {
  HANDLE process = GetCurrentProcess();
  HANDLE hThread = GetCurrentThread();

  if (!SymInitialize(process, NULL, TRUE)) {
    std::cerr << "SymInitialize returned error : " << GetLastError() << std::endl;
    return;
  }

  DWORD symOptions = SymGetOptions();
  symOptions |= SYMOPT_LOAD_LINES | SYMOPT_UNDNAME;
  SymSetOptions(symOptions);

  CONTEXT *context = ep->ContextRecord;
  CONTEXT copyContext = *context;
  RtlCaptureContext(context);

  STACKFRAME64 frame;
  frame.AddrPC.Offset = context->Rip;
  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrStack.Offset = context->Rsp;
  frame.AddrStack.Mode = AddrModeFlat;
  frame.AddrFrame.Offset = context->Rbp;
  frame.AddrFrame.Mode = AddrModeFlat;

  auto imgType = IMAGE_FILE_MACHINE_AMD64;
  int frameNumber = 0;

  while (StackWalk64(imgType, process, hThread, &frame, context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL) && frameNumber++ < maxFrames) {
    if (frame.AddrPC.Offset != 0) {
      std::string fnName = GetSymbol(process, frame.AddrPC.Offset);
      if (fnName.find("Rtl") == std::string::npos) // don't record rtl functions to make test easier
      {
        recordedStackTrace.push_back({fnName, frameNumber});
      }
    } else {
      recordedStackTrace.push_back({"No Symbols", frameNumber});
    }
  }

  SymCleanup(process);
  *context = copyContext;
  return;
}

static const char *asanReportTest = "AsanReportTest";
void AsanReportTest() {
  // Cause an asan report to check and make sure user exception handler
  // didn't get in front
  problematicMemory = (char *)malloc(8);
  PopulateShadowMemoryWithIssue();
  *problematicMemory = 1;
  // CHECK1: AddressSanitizer: stack-buffer-overflow
}

static const char *userHandler1 = "UserExceptionHandler1";
LONG WINAPI
UserExceptionHandler1(
    struct _EXCEPTION_POINTERS *ExceptionInfo) {
  UNREFERENCED_PARAMETER(ExceptionInfo);
  std::cerr << userHandler1 << " called." << std::endl;

  // If this exception handler gets invoked first,
  // the asan report will end up being incomplete.
  // CHECK1-NOT: AddressSanitizer: nested bug in the same thread, aborting.
  // CHECK1-NOT: UserExceptionHandler1 called.
  sequence.push_back({userHandler1, order++});
  return EXCEPTION_ACCESS_VIOLATION;
}

static const char *userHandler2 = "UserExceptionHandler2";
LONG WINAPI
UserExceptionHandler2(
    struct _EXCEPTION_POINTERS *ExceptionInfo) {
  UNREFERENCED_PARAMETER(ExceptionInfo);
  sequence.push_back({userHandler2, order++});
  std::cerr << userHandler2 << " called." << std::endl;
  return EXCEPTION_CONTINUE_SEARCH;
}

static const char *userHandler3 = "UserExceptionHandler3";
LONG WINAPI
UserExceptionHandler3(
    struct _EXCEPTION_POINTERS *ExceptionInfo) {
  sequence.push_back({userHandler3, order++});
  std::cerr << userHandler3 << " called." << std::endl;
  switch (exceptionToThrow) {
  case ThrowType::Regular:
    exceptionToThrow = ThrowType::None;
    RaiseException(1, 0, 0, nullptr);
    break;
  case ThrowType::Shadow:
    exceptionToThrow = ThrowType::None;
    AsanReportTest();
    break;
  case ThrowType::None:
  default:
    break;
  }
  RecordStackTrace(ExceptionInfo);
  return EXCEPTION_CONTINUE_SEARCH;
}

bool CheckOrder() {
  if (order <= 1) { // order doesn't matter for given test
    return true;
  }
  for (auto i = 0; i < sequence.size(); ++i) {
    if (sequence[i] != expected[i]) {
      std::cerr << "Failed. Ordering of " << sequence[i].symbol << " is: " << sequence[i].frameNumber << " instead of: " << expected[i].symbol << " " << expected[i].frameNumber << std::endl;
      return false;
    }
  }
  return true;
}

void RemoveHandlers() {
  for (auto &h : handlers) {
    if (!RemoveVectoredExceptionHandler(h)) {
      std::cerr << "Failed. Removing exception handlers returned false." << std::endl;
      return;
    }
  }
  CheckOrder();
}

template <typename Before, typename Except, typename After>
void TryExceptTest(Before before, Except duringExcept, After after) {
  before();
  _try {
    std::cerr << "Raising exception." << std::endl;
    RaiseException(1, 0, 0, nullptr);
  }
  __except (EXCEPTION_EXECUTE_HANDLER) {
    duringExcept();
  }
  after();
}

PVOID AddHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
  auto handle = AddVectoredExceptionHandler(first, handler);
  if (!handle) {
    std::cerr << "Failed. Adding exception handlers returned nullptr." << std::endl;
    return nullptr;
  }
  handlers.push_back(handle);
  return handle;
}

// for testing puposes always 2,1,3
void AddExpectedOrder() {
  static int pos = 0;
  expected.push_back({userHandler2, pos++});
  expected.push_back({userHandler1, pos++});
  expected.push_back({userHandler3, pos++});
}

static const char *manyHandlersTest = "ManyHandlersTest";
void ManyHandlersTest() {
  // add more exception handlers in front and behind to make sure order is maintained
  AddHandler(callFirst, UserExceptionHandler2);
  AddHandler(callLast, UserExceptionHandler3);
  AddExpectedOrder();
}

static const char *multipleExceptionTest = "MultipleExceptionTest";
void MultipleExceptionTest() {
  // throw 2 exceptions
  exceptionToThrow = ThrowType::Regular;
  ManyHandlersTest();

  // should cycle through each exception handler twice
  AddExpectedOrder();
}

static const char *nestedShadowExceptionTest = "NestedShadowExceptionTest";
void NestedShadowExceptionTest() {
  exceptionToThrow = ThrowType::Shadow;
  ManyHandlersTest();
}

static const char *removalTest = "RemovalTest";
void RemovalTest() {
  ManyHandlersTest();
  RemoveHandlers();
}

static const char *removeOneTest = "RemoveOneTest";
void RemoveOneTest() {
  // Remove first veh
  if (!RemoveVectoredExceptionHandler(handlers[0])) {
    std::cerr << "Failed. Removing exception handlers returned false." << std::endl;
    return;
  }
}

static const char *veryManyHandlers = "VeryManyHandlers";
void VeryManyHandlers() {
  for (auto i = 0; i < 32; ++i) { // for 4 KB pages, this will force at least one internal reallocation
    AddHandler(callFirst, UserExceptionHandler2);
    AddHandler(callLast, UserExceptionHandler3);
  }
  expected.clear(); // Only testing for AVs during paging
}

static const char *userHandlerTest = "UserHandlerTest";
static const char *removeAfterFirstExceptionTest = "RemoveAfterFirstExceptionTest";

void PrintRecordedStackTrace() {
  for (const auto &[symbol, frameNumber] : recordedStackTrace) {
    std::cerr << symbol << ": " << frameNumber << std::endl;
  }
}

int main(int argc, char **argv) {
  AddHandler(callFirst, UserExceptionHandler1);
  auto noop = []() {};

  if (!strcmp(argv[1], asanReportTest)) {
    AsanReportTest();
  }
  if (!strcmp(argv[1], userHandlerTest)) {
    TryExceptTest(noop, noop, RemoveHandlers);
    // CHECK2: UserExceptionHandler1 called.
  }
  if (!strcmp(argv[1], manyHandlersTest)) {
    TryExceptTest(ManyHandlersTest, PrintRecordedStackTrace, RemoveHandlers);
    // CHECK3: UserExceptionHandler2 called.
    // CHECK3-NEXT: UserExceptionHandler1 called.
    // CHECK3-NEXT: UserExceptionHandler3 called.

    // CHECK3: {{UserExceptionHandler3:*}}
    // CHECK3-NEXT: {{RaiseException*}}
    // CHECK3-NEXT: {{TryExceptTest*}}
    // CHECK3-NEXT: {{main*}}
    // CHECK3-NOT: couldn't symbolize
  }
  if (!strcmp(argv[1], multipleExceptionTest)) {
    // raise 2 exceptions check stack
    TryExceptTest(MultipleExceptionTest, PrintRecordedStackTrace, RemoveHandlers);
    // CHECK4: UserExceptionHandler2 called.
    // CHECK4-NEXT: UserExceptionHandler1 called.
    // CHECK4-NEXT: UserExceptionHandler3 called.
    // CHECK4-NEXT: UserExceptionHandler2 called.
    // CHECK4-NEXT: UserExceptionHandler1 called.
    // CHECK4-NEXT: UserExceptionHandler3 called.

    // CHECK4: {{UserExceptionHandler3:*}}
    // CHECK4-NEXT: {{RaiseException*}}
    // CHECK4-NEXT: {{UserExceptionHandler3:*}}
    // CHECK4-NEXT: {{RaiseException*}}
    // CHECK4-NEXT: {{TryExceptTest*}}
    // CHECK4-NEXT: {{main*}}
    // CHECK4-NOT: couldn't symbolize
  }
  if (!strcmp(argv[1], nestedShadowExceptionTest)) {
    // raise shadow exception from inside eh
    TryExceptTest(NestedShadowExceptionTest, noop, RemoveHandlers);
    // CHECK5: UserExceptionHandler2 called.
    // CHECK5-NEXT: UserExceptionHandler1 called.
    // CHECK5-NEXT: UserExceptionHandler3 called.

    // CHECK5: {{AddressSanitizer: stack-buffer-overflow:*}}
    // CHECK5-NEXT: {{WRITE of size 1*}}
    // CHECK5-NEXT: #0 0x{{[0-9a-f]+}} in AsanReportTest
    // CHECK5-NEXT: #1 0x{{[0-9a-f]+}} in UserExceptionHandler3

    // CHECK5: #6 0x{{[0-9a-f]+}} in TryExceptTest
    // CHECK5-NEXT: #7 0x{{[0-9a-f]+}} in main
  }
  if (!strcmp(argv[1], removalTest)) {
    // Add then remove should call no handlers
    TryExceptTest(RemovalTest, noop, noop);
    // CHECK6-NOT: UserExceptionHandler2 called.
    // CHECK6-NOT: UserExceptionHandler1 called.
    // CHECK6-NOT: UserExceptionHandler3 called.
  }
  if (!strcmp(argv[1], removeOneTest)) {
    // Removing after first exception and raising again should call no handlers
    TryExceptTest(ManyHandlersTest, PrintRecordedStackTrace, RemoveOneTest);
    TryExceptTest(noop, noop, noop);
    // CHECK7: UserExceptionHandler2 called.
    // CHECK7-NEXT: UserExceptionHandler1 called.
    // CHECK7-NEXT: UserExceptionHandler3 called.

    // CHECK7: {{UserExceptionHandler3:*}}
    // CHECK7-NEXT: {{RaiseException*}}
    // CHECK7-NEXT: {{TryExceptTest*}}
    // CHECK7-NEXT: {{main*}}
    // CHECK7-NOT: couldn't symbolize

    // CHECK7: Raising exception.
    // CHECK7: UserExceptionHandler2 called.
    // CHECK7-NEXT: UserExceptionHandler3 called.
    // CHECK7-NOT: UserExceptionHandler1 called.
  }
  if (!strcmp(argv[1], removeAfterFirstExceptionTest)) {
    // Removing after first exception and raising again should call no handlers
    TryExceptTest(ManyHandlersTest, PrintRecordedStackTrace, RemoveHandlers);
    TryExceptTest(noop, noop, noop);
    // CHECK8: UserExceptionHandler2 called.
    // CHECK8-NEXT: UserExceptionHandler1 called.
    // CHECK8-NEXT: UserExceptionHandler3 called.

    // CHECK8: {{UserExceptionHandler3:*}}
    // CHECK8-NEXT: {{RaiseException*}}
    // CHECK8-NEXT: {{TryExceptTest*}}
    // CHECK8-NEXT: {{main*}}
    // CHECK8-NOT: couldn't symbolize

    // CHECK8: Raising exception.
    // CHECK8-NOT: UserExceptionHandler2 called.
    // CHECK8-NOT: UserExceptionHandler1 called.
    // CHECK8-NOT: UserExceptionHandler3 called.
  }
  if (!strcmp(argv[1], veryManyHandlers)) {
    // Add a very large amount of EHs to test paging
    TryExceptTest(VeryManyHandlers, noop, noop);
    // CHECK9-COUNT-32: UserExceptionHandler2 called.
    // CHECK9-NEXT: UserExceptionHandler1 called.
    // CHECK9-COUNT-32: UserExceptionHandler3 called.
  }

  // CHECK-NOT: {{Failed.*}}
}