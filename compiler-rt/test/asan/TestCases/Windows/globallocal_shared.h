#pragma once
#include <Windows.h>

#if defined(TEST_GLOBAL)
#define ALLOC GlobalAlloc
#define REALLOC GlobalReAlloc
#define FREE GlobalFree
#define LOCK GlobalLock
#define UNLOCK GlobalUnlock
#define SIZE GlobalSize
#define HANDLE_FUNC GlobalHandle
static constexpr auto ZEROINIT = GMEM_ZEROINIT;
static constexpr auto FixedType = GMEM_FIXED;
static constexpr auto MOVEABLE = GMEM_MOVEABLE;
static constexpr auto MODIFY = GMEM_MODIFY;
static constexpr const char *const TEST_TYPE = "Global";
#else
#define ALLOC LocalAlloc
#define REALLOC LocalReAlloc
#define FREE LocalFree
#define LOCK LocalLock
#define UNLOCK LocalUnlock
#define SIZE LocalSize
#define HANDLE_FUNC LocalHandle
static constexpr auto ZEROINIT = LMEM_ZEROINIT;
static constexpr auto FixedType = LMEM_FIXED;
static constexpr auto MOVEABLE = LMEM_MOVEABLE;
static constexpr auto MODIFY = LMEM_MODIFY;
static constexpr const char *const TEST_TYPE = "Local";
#endif

