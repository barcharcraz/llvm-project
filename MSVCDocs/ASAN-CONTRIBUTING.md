# Contributing to the MSVC Address Sanitizer

## Introduction

The MSVC Address Sanitizer (ASan) project is an essential part of our development environment. Below are guidelines for contributing to ASan, including development conventions, building steps, testing procedures, continuous integration, and updating public documentation.

> NOTE: The Address Sanitizer will be (and is generally) referred to as ASan for brevity.

## Getting Started

A great place to start is the Microsoft Docs for [ASan](https://learn.microsoft.com/en-us/cpp/sanitizers/asan?view=msvc-170). Another great resource is the [google ASan wiki](https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm).

If you are brand new to the project and development team, there are some helpful tips for onboarding and development in the [OneNote](https://microsoft.sharepoint.com/teams/DD_VC/_layouts/15/Doc.aspx?sourcedoc={b72456de-7699-4e28-958c-16cc62b8cf45}&action=edit&wd=target%28BE%20Team%2FSecurity%2FCompiler%20Security%20V-Team.one%7Cf620fd11-0e2d-43af-84c6-a52ace6459ad%2FASAN%20Onboarding%20Notes%7C8fa37345-1332-4eac-8b3b-052a60f7c78c%2F%29&wdorigin=703), some of which may be repeated here.

This project is a fork of LLVM. Contributions will (eventually) be upstreamed to the [LLVM GitHub repo](https://github.com/llvm/llvm-project).

> NOTE: At the time of this commit, this fork is based on LLVM 14. Our main branch for development is [`ms/llvm14/main`](https://devdiv.visualstudio.com/DevDiv/_git/AddressSanitizer?version=GBms%2Fllvm14%2Fmain), and all <b>new</b> changes should be made branched off there.

## Development Conventions
* Branching convention is `dev/alias/whatever` example: `dev/zajohnson/runtime-bug-fix`
* The ASan source is a submodule of the msvc repo, which means there are two corresponding pull requests (PRs) per ASan source change. The msvc branch to target is [`prod/be`](https://devdiv.visualstudio.com/DevDiv/_git/msvc?version=GBprod%2Fbe).
* The Standard Template Library (STL) is currently not usable in the runtime due to dependency issues
* Regression tests are preferred with all changes
* Changes that outdate documentation (including the repo's markdown) should update documentation accordingly

## Getting the Source Code

#### <b>Please reference the [MSVC readme](https://devdiv.visualstudio.com/DevDiv/_git/msvc?anchor=msvc-repo) before continuing here.</B> You must fetch the submodules in that repo as well.

> NOTE: <b>All commands are relative to your MSVC enlistment root. Any command that needs the fully qualified path will contain this reference as \<msvc_root\>.</b>

### <u>First steps for new environments:</u>

```
profile.cmd -add CoreXT SanitizerUnitTests
init.cmd

# use updatedrop to get a baseline
updatedrop.cmd x86 amd64 chk latest_be 

# From this point, you can build the individual projects
```

## Build Steps

There are 4 projects you might care about under `src/vctools/asan/mt`:
1. `libasan.vcxproj` &mdash; The ASan runtime, which is where most of development takes place
2. `libasand.vcxproj` &mdash; The ASan runtime (debug pieces), which also adds `DCHECK`s
3. `libomp.vcxproj` &mdash; OpenMP, please reference [the relevant contributing.md](..\CONTRIBUTING.md) and the [LLVM readme](..\README.md)
4. `llvm-symbolizer.vcxproj` &mdash; The llvm-symbolizer, which is used in ASan reporting
<br></br>


Currently, `x86` and `x64` are the active development platforms. `MSBuild` is used for building the project. You can specify `chk` or `ret` for the different types of builds.

For the rest of the examples, we will use `x64` and `chk` as the `Platform` and `Configuration` for `MSBuild`.

### Example of building the ASan runtime:
```
call infra\msvc\MSBuild.cmd /m /p:Platform=x64 /p:Configuration=chk <msvc_root>\src\vctools\asan\mt\libasan.vcxproj
```

Congratulations! The project is built. Binaries will be produced at `<msvc_root>\binaries\<Platform><Configuration>\bin\<Platform>\sanitizers` and `<msvc_root>\binaries\<Platform><Configuration>\lib\<Platform>\sanitizers`. The artifacts here are shipped to customers by means of:

1. <b>_VisualCppTools_</b>
    * This is a nuget package that is released with each version of the toolset
    * You can find references [here](https://devdiv.visualstudio.com/DevDiv/_artifacts/feed/VisualCppTools)
2. <b>_Visual Studio_</b>
    * This is the normal Visual Studio distribution, which the bins and libs ship alongside
3. <b>_Last Known Good_</b> (LKG, an OS thing) 
    * This is explained in further detail [here](https://www.osgwiki.com/wiki/Compiler_toolset_used_in_WDG)

There is also the option of a private binary drop for internal customers. This is generally straightforward, as in some cases only `clang_rt.asan_dynamic-x86_64.dll` or `clang_rt.asan_dynamic-i386.dll` is needed to be replaced in the customer's environment. However, if they need all bins/libs:

```
cd binaries\<Platform><Configuration>\bin\<Platform>\sanitizers

dir /s clang_rt* # Copy everything output here, includes *.pdb

cd ..\..\lib\<Platform>\sanitizers

dir /s clang_rt* # Copy everything output here, includes *.pdb
```

If a full toolset is needed, such as compiler, linker, and associated libs, it's best to just grab the built toolset from a PR or `prod/be` to give rather than building on a local machine.

## Testing

There are several different ways to test changes to the ASan runtime.

1. Using the powershell script `SetupAndRunLocalTests-Msvc.ps` (located at `src\qa\sanitizers\asan\SetupAndRunLocalTests-Msvc.ps1`).
    * This will likely be used most of the time for regular development, and does not require `setenv` from the development environment
    * It utilizes the [`LLVM Integrated Tester` AKA lit](https://llvm.org/docs/CommandGuide/lit.html#lit-llvm-integrated-tester)
    * The script can test whole suites (e.g. `Asan`, `AsanWindows`, or `Fuzzer`) or individual tests
        * Whole suite example: `powershell src\qa\sanitizers\asan\SetupAndRunLocalTests-Msvc.ps1 -MsvcHostArch amd64 -TestSuite AsanWindows`
        * Individual test example: `powershell src\qa\sanitizers\asan\SetupAndRunLocalTests-Msvc.ps1 -MsvcHostArch x86 -TestSuite AsanWindows -RunTest hello_world.cpp`
    * This is the script used by CI, and runs each suite under all different configuration types
    * For more info, try running the script with no arguments to better understand the different options
2. Compiling and running executables manually
    * Requires `setenv` to be run in your environment
    * `/fsanitize=address` compiler option, along with any other necessary compiler/linker flag that needs to be tested
    * The lit test runner above will produce a full command line output for each test. If you need to discover an existing test's verbatim command line, you can run the powershell script above with that individual test to determine the exact command line used


When creating a pull request, option 1 will be used during automated testing.

Most unit tests live under `src\vctools\asan\llvm\compiler-rt\test\asan\TestCases`. Windows specific tests should be added under the `TestCases\Windows` folder. Other tests live under the msvc repo for testing the compiler, integration, or other libraries using ASan. These tests can be found `src\qa`.

There are also Real World Code (RWC) tests that should be run as a part of changes to ASan to prevent regressions. These are mentioned in the Continuous Integration and Workflows section.

### Continuous Integration and Workflows

> NOTE: These links may become outdated, but the names of the pipelines should generally stay the same and can be found searching [here](https://devdiv.visualstudio.com/DevDiv/_build?pipelineNameFilter=ASAN). The list below is not complete, but is a minimum set of required passing runs for each ASan change.

1.	<b>MSVC-ASAN-UnitTests-Private</b> &mdash; [MSVC-ASAN-UnitTests-Private](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=13061&_a=summary)
    *	This is required to pass for all changes, and is a run of all configurations possible for `SetupAndRunLocalTests-Msvc.ps`
    *	Has a dependency on up-to-date toolset, build, and symbols
    *	Symbols are required as the tests have explicit `CHECK`s for call frames
    * There is an associated rolling pipeline <b>MSVC-ASAN-UnitTests-Rolling</b> [Runs for MSVC-ASAN-UnitTests-Rolling](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=13945)
        *	This is the exact same, except it happens nightly on `prod/be`
        *	Potential code integration issues are caught here, usually from FI/RI or if someone failed to run the above during PR
2.	<b>MSVC-ASAN-Private</b> &mdash; [MSVC-ASAN-Private](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=12199)
    *	This is the regress pipeline, which runs rlexe with `/fsanitize=address` on everything that’s not marked as `ASanIncompatible`
    *	Generally healthy, however if there are issues plaguing normal regress we see them here too.
    * There is an associated rolling pipeline <b>MSVC-ASAN-Stress-Rolling</b> [Runs for MSVC-ASAN-Stress-Rolling](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=12291&_a=summary)
        *	This combines ASan stress tests with all the other backend stress tests
3.	<b>MSVC-OSS-\<Platform>\-ASAN Pipelines</b> &mdash; [MSVC-OSS-x64-All-Private-ASan](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=13624&_a=summary) and [MSVC-OSS-x86-All-Private-ASan](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=13623)
    *	RWC runs, which are currently optional for us, but <b>should</b> be treated as <b>required</b>
    * If there are any failing with your run, consult either the "Prod/be Open Source Test Report" email sent weekly to the asan alias, or the [BE dashboard](https://devdiv.visualstudio.com/DevDiv/_dashboards/dashboard/cc8b8f5c-9a86-4aa6-aa86-37a5bd53a21f)
4. <b>MSVC-ASan-InsiderTest</b> &mdash; [MSVC-ASan-InsiderTest](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=19433)
    * Triggered nightly on `prod/be`, and tests the ASan build and runtime on the latest published prerelease of Windows
    * This is necessary to catch Windows specific issues as early as possible
    * The most common current issue is surrounding interception and the addition of instructions that confuse the interception machinery
5. <b>Libs-ASan-\<Platform\></b> &mdash; [Libs-ASan-amd64](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=20660) and [Libs-ASan-x86](https://devdiv.visualstudio.com/DevDiv/_build?definitionId=20661)
    * Used to instrument the STL and VCRuntime's tests with ASan
    * Manually triggered currently, but eventually will run as a required check for ASan changes
 

## Updating Public Documentation

Follow the steps listed [here](https://review.learn.microsoft.com/en-us/help/get-started/setup-github?branch=main) to get started. Afterwards, the documentation can be found under the [AddressSanitizer space](https://learn.microsoft.com/en-us/cpp/sanitizers/asan?view=msvc-170).

Any changes that outdate this documentation should be updated before the associated GA release.

## FAQ

> _Why is there always an exception breakpoint hit during x64 ASan startup?_

&emsp; The x64 implementation of the shadow memory mapping currently requires the runtime to handle an exception that is thrown using a registered vector exception handler that pages in the relevant memory. You can safely ignore these exceptions. 

&emsp; For specific debugging tips, check out [the debugging page](ASAN-DEBUGGING.md).

> _I'm having strange compiler errors with the project. What should I do?!_

&emsp; The first thing to do is make sure your environment is properly set up and up to date. This issue can _almost always_ be resolved by making sure you are in sync with the latest bits. If the errors don't go away after that, try checking out a different branch and building. If errors persist, feel free to post in the [ASan Development Discussions teams channel](https://teams.microsoft.com/l/channel/19%3A09aa1f0afc114fc6a703d60f52b93012%40thread.skype/ASAN%20Development%20Discussions?groupId=96a8d54f-46ca-4f05-b330-d489906bc109&tenantId=72f988bf-86f1-41af-91ab-2d7cd011db47) or email asan@microsoft.com

> _I can't see locals or line numbers from the debugger. Why?_
 
&emsp; The easiest way to remedy this is to add `#pragma optimize("", off)` in the file that you care about viewing that information from. If you want to get really fancy, you can always use the sanitizer's hand rolled `Printf` to print debugging statements! =)

&emsp; For more specific debugging tips, check out [the debugging page](ASAN-DEBUGGING.md).

