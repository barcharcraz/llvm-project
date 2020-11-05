#pragma once

#if defined(TEST_GLOBAL)
#define ALLOC GlobalAlloc
#define REALLOC GlobalReAlloc
#define FREE GlobalFree
#define LOCK GlobalLock
#define UNLOCK GlobalUnlock
#define SIZE GlobalSize
#define ZEROINIT GMEM_ZEROINIT
#define FIXED GMEM_FIXED
#define MOVEABLE GMEM_MOVEABLE
#define MODIFY GMEM_MODIFY
#else
#define ALLOC LocalAlloc
#define REALLOC LocalReAlloc
#define FREE LocalFree
#define LOCK LocalLock
#define UNLOCK LocalUnlock
#define SIZE LocalSize
#define ZEROINIT LMEM_ZEROINIT
#define FIXED LMEM_FIXED
#define MOVEABLE LMEM_MOVEABLE
#define MODIFY LMEM_MODIFY
#endif

