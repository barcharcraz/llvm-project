#pragma once

#if defined(TEST_GLOBAL)
#define ALLOC GlobalAlloc
#define REALLOC GlobalReAlloc
#define FREE GlobalFree
#define LOCK GlobalLock
#define UNLOCK GlobalUnlock
#define SIZE GlobalSize
#else
#define ALLOC LocalAlloc
#define REALLOC LocalReAlloc
#define FREE LocalFree
#define LOCK LocalLock
#define UNLOCK LocalUnlock
#define SIZE LocalSize
#endif

