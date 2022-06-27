// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: not %run %t 2>&1 | FileCheck %s

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>

#define SIZE 7
extern void nothing();
int x=13,*aa,*bb,y=0;
int fail = 0;
int tmp;

// Testing output for example in
// https://docs.microsoft.com/en-us/cpp/sanitizers/error-dynamic-stack-buffer-overflow
void main()
{
  int *cc;
  int i;
  int k = 17;
__try{
  tmp = k;
  aa = (int*)_alloca(SIZE*sizeof(int));
  if (((int)aa) & 0x3)
    fail = 1;
  for (i=0;i<SIZE;i++){
    aa[i] = x+1+i;
  }
  bb = (int*)_alloca(x*sizeof(int));
  if (((int)bb) & 0x3)
    fail = 1;

  for (i=0;i<x;i++){
    bb[i] = 7;
    bb[i] = bb[i]+i;
  }
  {
    int s = 112728283;
    int ar[8];
    for (i = 0; i<8;i++)
      ar[i] = s * 17*i;
  }

  cc = (int*)_alloca(x);
  if (((int)cc) & 0x3)
    fail = 1;

  cc[0] = 0;
  cc[1] = 1;
  cc[2] = 2;
  cc[3] = 3;             // <--- Boom!
  // CHECK:ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address [[ADDR:0x[0-9a-f]+]] at pc {{0x[0-9a-f]+}} bp {{0x[0-9a-f]+}} sp {{0x[0-9a-f]+}}
  // CHECK: WRITE of size {{[0-9]+}} at [[ADDR]] thread T0
  // CHECK: Address [[ADDR]] is located in stack of thread T0
  // CHECK: SUMMARY: AddressSanitizer: dynamic-stack-buffer-overflow
  // CHECK: Shadow bytes around the buggy address:
  // CHECK: Shadow byte legend (one shadow byte represents 8 application bytes):
  // CHECK-NEXT: Addressable:           00
  // CHECK-NEXT: Partially addressable: 01 02 03 04 05 06 07 
  // CHECK-NEXT: Heap left redzone:       fa
  // CHECK-NEXT: Freed heap region:       fd
  // CHECK-NEXT: Stack left redzone:      f1
  // CHECK-NEXT: Stack mid redzone:       f2
  // CHECK-NEXT: Stack right redzone:     f3
  // CHECK-NEXT: Stack after return:      f5
  // CHECK-NEXT: Stack use after scope:   f8
  // CHECK-NEXT: Global redzone:          f9
  // CHECK-NEXT: Global init order:       f6
  // CHECK-NEXT: Poisoned by user:        f7
  // CHECK-NEXT: Container overflow:      fc
  // CHECK-NEXT: Array cookie:            ac
  // CHECK-NEXT: Intra object redzone:    bb
  // CHECK-NEXT: ASan internal:           fe
  // CHECK-NEXT: Left alloca redzone:     ca
  // CHECK-NEXT: Right alloca redzone:    cb
  for (i=0;i<x;i++)
    if (bb[i] != (7+i))
      fail = 1;
  if (tmp != k)
    fail = 1;
  if (fail){
    printf("fail\n");
    exit(7);
  }
  printf("%d\n",(*cc)/y);
  printf("fail\n");
  exit(7);
} __except (1)
            
  {
    
   for (i=0;i<SIZE;i++)
     if (aa[i] != (x+i+1))
      fail = 1;
  if (fail){
    printf("fail\n");
    exit(7);
  }
  printf("pass\n");
  exit(0);
  }  
}