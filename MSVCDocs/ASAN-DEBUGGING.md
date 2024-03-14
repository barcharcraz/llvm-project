# Debugging the Address Sanitizer runtime

## General Debugging tips

* ReSearch
    * https://www.osgwiki.com/wiki/Research
    * This is a useful plugin that allows searching the OS source files
* Using `-SaveOutputs 1` as an argument to `SetupAndRunLocalTests-Msvc.ps1` will cache the created binaries and results from a test run and print the saved location

## Using [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)

### Useful breakpoints

Preface each of these commands with `bp` or `bm` 

* Break on x64 shadow memory exception handler? &emsp; `clang_rt_asan_dynamic_x86_64!ShadowExceptionHandler`

* Find out what's being sent to `llvm-symbolizer`? &emsp;`clang_rt_asan_dynamic_x86_64!__sanitizer::SymbolizerProcess::SendCommand`

* Find out what's being sent to `WinSymbolizer`? &emsp;`clang_rt_asan_dynamic_x86_64!__sanitizer::WinSymbolizerTool::SymbolizePC`

### General tips

* `sxd av` turns off stopping on access violation first-chance exceptions, and will allow you to ignore the x64 exception handling that occurs when the shadow memory is paged in

* `.call clang_rt_asan_dynamic_x86_64!__asan::MemToShadow(addr)` will be useful for checking the shadow memory of an address
    * Generally a good starting point for debugging
    * Adding `addr` and the corresponding shadow address to the watch window shortcuts this

* `ba <type><size> <address>` can be used to understand when memory is touched, both for user allocated memory and shadow memory
    * https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ba--break-on-access-
    * Ex: `ba w4 my_ptr`
    * This helps short circuit scenarios where there is where too much clutter between user code and ASan memory modification

* `.childdbg 1` will allow debugging of child processes spawned
    * After, `sxi epr` will make it so where a breakpoint isn't hit when the child process exits
    * `sxi ibp` will make it so where a breakpoint isn't hit when **any** child process spanws, but you will still be able to break by changing the active process 

* `.dmp /ma <DmpName>.dmp` will create a mini dump of the current executable in the current working directory and name it `DmpName.dmp`