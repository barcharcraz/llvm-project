// RUN: %clang_cl_asan -Od %s -Fe%t
// RUN: %run %t

#include "Windows.h"
#include "malloc.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

int main() 
{
    _setmaxstdio(64);
    _setmaxstdio(4);
    _setmaxstdio(2064);
   return 0;
}