#pragma once
#include <Windows.h>
#include <assert.h>
#include <dbghelp.h>
#include <iostream>
#include <malloc.h>
#include <stdio.h>

[[noreturn]] void fail(const char *message = "") {
  // WriteFile must be used instead of std::cerr and fprintf
  // because of deadlocks with streams and asan reporting
  DWORD bytesWritten;
  HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
  WriteFile(err, message, strlen(message), &bytesWritten, NULL);
  TerminateProcess(GetCurrentProcess(), -1);
}

PIMAGE_IMPORT_DESCRIPTOR FindImportDescriptor(HMODULE mod, const char *targetModuleName) {
  ULONG sizeUnused{};
  const PIMAGE_IMPORT_DESCRIPTOR importDescriptorList = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ImageDirectoryEntryToDataEx(mod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &sizeUnused, NULL));

  for (PIMAGE_IMPORT_DESCRIPTOR imp = importDescriptorList; imp->Characteristics && imp->Name; ++imp) {
    const char *importModuleName = reinterpret_cast<char *>(mod) + imp->Name;
    if (_stricmp(importModuleName, targetModuleName) == 0) {
      return imp;
    }
  }
  return nullptr;
}

void **FindImportAddress(HMODULE mod, const PIMAGE_IMPORT_DESCRIPTOR importDescriptor, void *targetExport) {
  const PIMAGE_THUNK_DATA thunkList = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<char *>(mod) + importDescriptor->FirstThunk);

  for (PIMAGE_THUNK_DATA thunk = thunkList; thunk->u1.Function; ++thunk) {
    void **importAddress = reinterpret_cast<void **>(&thunk->u1.Function);
    if (*importAddress == targetExport) {
      return importAddress;
    }
  }
  return nullptr;
}

template <typename ProtectFunc>
void OverwriteIATOrFail(const char *moduleName, const char *targetModuleName, const char *targetExportName, void *newTargetFP, ProtectFunc virtualProtect) {

  HMODULE mod = GetModuleHandleA(moduleName);
  if (mod == nullptr) {
    std::cerr << "Failure to find " << moduleName << std::endl;
    fail();
  }

  HMODULE targetModule = GetModuleHandleA(targetModuleName);
  if (targetModule == nullptr) {
    std::cerr << "Failure to find " << targetModuleName << std::endl;
    fail();
  }

  void *targetExport = reinterpret_cast<void *>(GetProcAddress(targetModule, targetExportName));
  if (targetExport == nullptr) {
    std::cerr << "Could not find export " << targetExportName << " in module " << targetModuleName << std::endl;
    fail();
  }

  PIMAGE_IMPORT_DESCRIPTOR targetImportDescriptor = FindImportDescriptor(mod, targetModuleName);
  if (targetImportDescriptor == nullptr) {
    std::cerr << "Could not locate import descriptor for " << targetModuleName << "!" << targetExportName << " in " << moduleName << std::endl;
    fail();
  }

  void **importAddress = FindImportAddress(mod, targetImportDescriptor, targetExport);
  if (importAddress == nullptr) {
    std::cerr << "Could not find import address table entry for " << targetModuleName << "!" << targetExportName << " in " << moduleName << std::endl;
    fail();
  }

  MEMORY_BASIC_INFORMATION mbi{};
  VirtualQuery(importAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

  if (!virtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect)) {
    std::cerr << "Could not unprotect memory (0x" << importAddress << ") in " << moduleName << " import address table for " << targetModuleName << "!" << targetExportName << std::endl;
    fail();
  }

  *importAddress = newTargetFP;

  DWORD protectUnused{};
  virtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &protectUnused);
}