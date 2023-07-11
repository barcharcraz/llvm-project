#!/usr/bin/env python

import os
import platform
import random
import re
import sys
import time
import argparse
import tempfile
import shutil
import copy
from xml.sax.saxutils import quoteattr

import lit.ProgressBar
import lit.LitConfig
import lit.TestingConfig
import lit.Test
import lit.run
import lit.util
import lit.discovery
import lit.TestRunner
import threading

class TestingProgressDisplay(object):
    def __init__(self, opts, numTests, progressBar=None):
        self.opts = opts
        self.numTests = numTests
        self.progressBar = progressBar
        self.completed = 0

    def finish(self):
        if self.progressBar:
            self.progressBar.clear()
        elif self.opts.quiet:
            pass
        elif self.opts.succinct:
            sys.stdout.write('\n')

    def update(self, test):
        self.completed += 1

        if self.opts.incremental:
            update_incremental_cache(test)

        if self.progressBar:
            self.progressBar.update(float(self.completed)/self.numTests,
                                    test.getFullName())

        shouldShow = test.result.code.isFailure or \
            self.opts.showAllOutput or \
            (not self.opts.quiet and not self.opts.succinct)
        if not shouldShow:
            return

        if self.progressBar:
            self.progressBar.clear()

        # Show the test result line.
        test_name = test.getFullName()
        print(('%s: %s (%d of %d)' % (test.result.code.name, test_name,
                                     self.completed, self.numTests)))

        # Show the test failure output, if requested.
        if (test.result.code.isFailure and self.opts.showOutput) or \
           self.opts.showAllOutput:
            if test.result.code.isFailure:
                print(("%s TEST '%s' FAILED %s" % ('*'*20, test.getFullName(),
                                                  '*'*20)))
            print((test.result.output))
            print(("*" * 20))

        # Report test metrics, if present.
        if test.result.metrics:
            print(("%s TEST '%s' RESULTS %s" % ('*'*10, test.getFullName(),
                                               '*'*10)))
            items = sorted(test.result.metrics.items())
            for metric_name, value in items:
                print(('%s: %s ' % (metric_name, value.format())))
            print(("*" * 10))

        # Report micro-tests, if present
        if test.result.microResults:
            items = sorted(test.result.microResults.items())
            for micro_test_name, micro_test in items:
                print(("%s MICRO-TEST: %s" %
                         ('*'*3, micro_test_name)))

                if micro_test.metrics:
                    sorted_metrics = sorted(micro_test.metrics.items())
                    for metric_name, value in sorted_metrics:
                        print(('    %s:  %s ' % (metric_name, value.format())))

        # Ensure the output is flushed.
        sys.stdout.flush()
def slashsan(stri):
    return stri.replace("\\","\\\\")

print("""
    Run LLVM/Clang/ASAN unit tests on MSVC/ASAN
    usage:
    a) run vcvarsall or setenv from the compiler path you want to use to add include libs etc.
    b) set TEST_C_COMPILER=c:\\the\compiler\path\\to\\use.exe
    c) set TEST_OUTPUT_DIR=c:\\the\output\directory\\
    d) set ASAN_RT_LIB_DIR=c:\\path\\to\\runtime\\libs
    e) set ASAN_RT_SRC_ROOT=e:\\path\\to\\compiler\\rt\\src
    f) set ASAN_RT_BIN_DIR=e:\\path\\to\\x86-or-x64\\build\\bin
    g) set UNIX_BIN_DIR=[some path to a /bin dir with sed,awk,and grep]
    h) python msvc.py <path_to_tests> <target_arch>

        where path to tests is something like:
            llvm\\projects\\compiler-rt\\test\\asan\\TestCases\\Windows

        where arch is either x86 || x86_64


    optionally:
    add  ` --run_test testfile.cpp  `
    to run a specific test rather than the whole suite
""")
parser = argparse.ArgumentParser()
parser.add_argument('test_paths',
                    nargs='*',
                    help='Files or paths to include in the test suite')

parser.add_argument("--version", dest="show_version",
                    help="Show version and exit",
                    action="store_true", default=False)
parser.add_argument("-j", "--threads", dest="numThreads", metavar="N",
                    help="Number of testing threads",
                    type=int, default=None)
parser.add_argument("--config-prefix", dest="configPrefix",
                    metavar="NAME", help="Prefix for 'lit' config files",
                    action="store", default=None)
parser.add_argument("-D", "--param", dest="userParameters",
                    metavar="NAME=VAL",
                    help="Add 'NAME' = 'VAL' to the user defined parameters",
                    type=str, action="append", default=[])
parser.add_argument("--use-debug-runtimes", dest="debug_runtimes",
                    help="Enable MTd and MDd runtimes for tests",
                    action="store_true", default=False)


format_group = parser.add_argument_group("Output Format")
# FIXME: I find these names very confusing, although I like the
# functionality.
format_group.add_argument("-q", "--quiet",
                    help="Suppress no error output",
                    action="store_true", default=False)
format_group.add_argument("-s", "--succinct",
                    help="Reduce amount of output",
                    action="store_true", default=False)
format_group.add_argument("-v", "--verbose", dest="showOutput",
                    help="Show test output for failures",
                    action="store_true", default=False)
format_group.add_argument("-vv", "--echo-all-commands",
                    dest="echoAllCommands",
                    action="store_true", default=False,
                    help="Echo all commands as they are executed to stdout.\
                    In case of failure, last command shown will be the\
                    failing one.")
format_group.add_argument("-a", "--show-all", dest="showAllOutput",
                    help="Display all commandlines and output",
                    action="store_true", default=False)
format_group.add_argument("-o", "--output", dest="output_path",
                    help="Write test results to the provided path",
                    action="store", metavar="PATH")
format_group.add_argument("--no-progress-bar", dest="useProgressBar",
                    help="Do not use curses based progress bar",
                    action="store_false", default=True)
format_group.add_argument("--show-unsupported",
                    help="Show unsupported tests",
                    action="store_true", default=False)
format_group.add_argument("--show-xfail",
                    help="Show tests that were expected to fail",
                    action="store_true", default=False)

execution_group = parser.add_argument_group("Test Execution")
execution_group.add_argument("--path",
                    help="Additional paths to add to testing environment",
                    action="append", type=str, default=[])
execution_group.add_argument("--vg", dest="useValgrind",
                    help="Run tests under valgrind",
                    action="store_true", default=False)
execution_group.add_argument("--vg-leak", dest="valgrindLeakCheck",
                    help="Check for memory leaks under valgrind",
                    action="store_true", default=False)
execution_group.add_argument("--vg-arg", dest="valgrindArgs", metavar="ARG",
                    help="Specify an extra argument for valgrind",
                    type=str, action="append", default=[])
execution_group.add_argument("--time-tests", dest="timeTests",
                    help="Track elapsed wall time for each test",
                    action="store_true", default=False)
execution_group.add_argument("--no-execute", dest="noExecute",
                    help="Don't execute any tests (assume PASS)",
                    action="store_true", default=False)
execution_group.add_argument("--xunit-xml-output", dest="xunit_output_file",
                    help=("Write XUnit-compatible XML test reports to the"
                        " specified file"), default=None)
execution_group.add_argument("--timeout", dest="maxIndividualTestTime",
                    help="Maximum time to spend running a single test (in seconds)."
                    "0 means no time limit. [Default: 0]",
                type=int, default=None)
execution_group.add_argument("--test-target-arch", dest="testTargetArch",
    help="Select runtime library extension (i386,amd64,etc)",
    action="store", type=str, default="i386")

selection_group = parser.add_argument_group("Test Selection")
selection_group.add_argument("--max-tests", dest="maxTests", metavar="N",
                    help="Maximum number of tests to run",
                    action="store", type=int, default=None)
selection_group.add_argument("--max-time", dest="maxTime", metavar="N",
                    help="Maximum time to spend testing (in seconds)",
                    action="store", type=float, default=None)
selection_group.add_argument("--shuffle",
                    help="Run tests in random order",
                    action="store_true", default=False)
selection_group.add_argument("-i", "--incremental",
                    help="Run modified and failing tests first (updates "
                    "mtimes)",
                    action="store_true", default=False)
selection_group.add_argument("--filter", metavar="REGEX",
                    help=("Only run tests with paths matching the given "
                        "regular expression"),
                    action="store",
                    default=os.environ.get("LIT_FILTER"))
selection_group.add_argument("--num-shards", dest="numShards", metavar="M",
                    help="Split testsuite into M pieces and only run one",
                    action="store", type=int,
                    default=os.environ.get("LIT_NUM_SHARDS"))
selection_group.add_argument("--run-shard", dest="runShard", metavar="N",
                    help="Run shard #N of the testsuite",
                    action="store", type=int,
                    default=os.environ.get("LIT_RUN_SHARD"))

debug_group = parser.add_argument_group("Debug and Experimental Options")
debug_group.add_argument("--debug",
                    help="Enable debugging (for 'lit' development)",
                    action="store_true", default=False)
debug_group.add_argument("--show-suites", dest="showSuites",
                    help="Show discovered test suites",
                    action="store_true", default=False)
debug_group.add_argument("--show-tests", dest="showTests",
                    help="Show all discovered tests",
                    action="store_true", default=False)
debug_group.add_argument("--single-process", dest="singleProcess",
                    help="Don't run tests in parallel.  Intended for debugging "
                    "single test failures",
                    action="store_true", default=False)

debug_group.add_argument("--run-test", dest="runTest",
                    help="run a specific test rather than the whole suite",
                    action="store", type=str, default="")

debug_group.add_argument("--force-dynamic", dest="force_dynamic",
                    help="link the dynamic libs instead of the static libs",
                    action="store_true", default=False)
debug_group.add_argument("--print-env", dest="print_env",
                    help="print the environment",
                    action="store_true", default=False)

debug_group.add_argument("--disable-optimizations", dest="disable_opt",
                    help="disable optimization",
                    action="store_true", default=False)

opts = parser.parse_args()
args = opts.test_paths



if opts.show_version:
    print(("lit %s" % (lit.__version__,)))


if not args:
    parser.error('No inputs specified')

if opts.numThreads is None:
    opts.numThreads = lit.util.usable_core_count()

if opts.echoAllCommands:
    opts.showOutput = True

inputs = args

STATIC_RT_FLAG = None
DYNAMIC_RT_FLAG = None
if opts.debug_runtimes:
    STATIC_RT_FLAG = " /MTd "
    DYNAMIC_RT_FLAG = " /MDd "
else:
    STATIC_RT_FLAG = " /MT "
    DYNAMIC_RT_FLAG = " /MD "

# Decide what the requested maximum indvidual test time should be
if opts.maxIndividualTestTime is not None:
    maxIndividualTestTime = opts.maxIndividualTestTime
else:
    # Default is zero
    maxIndividualTestTime = 0

isWindows = platform.system() == 'Windows'


litConfig = lit.LitConfig.LitConfig(
        progname = os.path.basename(sys.argv[0]),
        path = opts.path,
        quiet = opts.quiet,
        useValgrind = opts.useValgrind,
        valgrindLeakCheck = opts.valgrindLeakCheck,
        valgrindArgs = opts.valgrindArgs,
        noExecute = opts.noExecute,
        #singleProcess = opts.singleProcess,
        debug = opts.debug,
        isWindows = isWindows,
        params = [],
        config_prefix = opts.configPrefix,
        maxIndividualTestTime = maxIndividualTestTime,
        parallelism_groups = {},
        echo_all_commands = opts.echoAllCommands)

litConfig.windows = True
litConfig.host_os = "Windows"
litConfig.host_arch = platform.machine()
litConfig.target_arch = sys.argv[2]
litConfig.compiler_id = "MSVC"
litConfig.cxx_mode_flags = []
litConfig.debug_info_flags = []
litConfig.asan_dynamic = False
litConfig.clang = os.environ['TEST_C_COMPILER'] # "ex .\\binaries\\bin\i386\cl.exe"
setattr(litConfig,"target_cflags","")
litConfig.target_suffix = litConfig.target_arch
litConfig.compiler_rt_libdir = os.environ['ASAN_RT_LIB_DIR']
litConfig.compiler_rt_src_root = os.environ['ASAN_RT_SRC_ROOT']
litConfig.python_executable = sys.executable
litConfig.android = False
litConfig.pipefail = True
litConfig.bashPath = ""

litConfig.limit_to_features = False
litConfig.unsupported = False
default_flags = " /EHs /DMSVC /D_WIN32 /Zi /GS- /FI" + litConfig.compiler_rt_src_root + "\\test\\include\\msvc_force_include.h "
selected_runtime = None
test_target_arch = opts.testTargetArch

testConfig = lit.TestingConfig.TestingConfig.fromdefaults(litConfig)
testConfig.environment = os.environ

arch_specific_features = []
if opts.testTargetArch == "x86_64":
    litConfig.bits = "64"
    arch_specific_features = ['asan-64-bits', 'x86_64-target-arch', 'msvc-host-x86_64']
    ml_exe = "ml64.exe"
elif opts.testTargetArch == "i386":
    litConfig.bits = "32"
    arch_specific_features =  ['asan-32-bits', 'x86-target-arch', 'msvc-host-i386']
    ml_exe = "ml.exe"
else:
    assert 0 and "Error: unsupported ASan runtime architecture."

if opts.force_dynamic:
    testConfig.available_features = [ 'clang-dynamic-runtime',
    'asan-dynamic-runtime','stable-runtime',
    'shadow-scale-3', 'msvc-host', 'win32', 'windows', 'windows-msvc', 'win32-dynamic-asan',
    'compiler-rt-optimized']
else:
    testConfig.available_features = ['clang-static-runtime',
    'asan-static-runtime','stable-runtime',
    'shadow-scale-3', 'msvc-host', 'win32', 'windows', 'windows-msvc' , 'win32-static-asan',
    'compiler-rt-optimized']

if opts.debug_runtimes:
    testConfig.available_features += ['asan-debug-runtime']
else:
    testConfig.available_features += ['asan-release-runtime']


testConfig.available_features += arch_specific_features

#setup arch specific lib names for reference later
arch = test_target_arch
if opts.debug_runtimes:
    d = "d"
    dbg_ ="dbg_"
else:
    d = ""
    dbg_ = ""

import_lib                 = f"clang_rt.asan_{dbg_}dynamic-{arch}.lib"
dynamic_runtime_thunk      = f"clang_rt.asan_{dbg_}dynamic_runtime_thunk-{arch}.lib"
static_runtime_thunk       = f"clang_rt.asan_{dbg_}static_runtime_thunk-{arch}.lib"
runtime_dll                = f"clang_rt.asan_{dbg_}dynamic-{arch}.dll"
fuzzer_dynamic_lib         = f"clang_rt.fuzzer_MD{d}-{arch}.lib"
fuzzer_no_main_dynamic_lib = f"clang_rt.fuzzer_MD{d}_no_main-{arch}.lib"
fuzzer_static_lib          = f"clang_rt.fuzzer_MT{d}-{arch}.lib"
fuzzer_no_main_static_lib  = f"clang_rt.fuzzer_MT{d}_no_main-{arch}.lib"
profile_lib                = f"clang_rt.profile-{arch}.lib"

del arch, d, dbg_

if opts.force_dynamic:
    runtime_thunk = dynamic_runtime_thunk
else:
    runtime_thunk = static_runtime_thunk

runtime_flags = ""
testConfig.environment['_CL_'] = ""
if opts.force_dynamic:
    testConfig.environment['_LINK_'] ="/debug /incremental:no "
    selected_runtime = DYNAMIC_RT_FLAG
    runtime_flags += " /Od "
    runtime_flags += DYNAMIC_RT_FLAG
else:
    testConfig.environment['_LINK_'] ="/debug  /incremental:no  "
    selected_runtime = STATIC_RT_FLAG
    runtime_flags += STATIC_RT_FLAG

out_to_exe_tuple = ("(?<! (-|/)c )-o %t( |)", lit.TestingConfig.SubstituteCaptures("/Fe:%t\g<2>"))
out_to_obj_tuple = ("(-|/)c -o %t( |)", lit.TestingConfig.SubstituteCaptures("/c /Fo:%t\g<2>"))

#set of optimization substitutions
optimization_subs = {
       ("-O0", "/Od"),
        ("/O0", "/Od"),
        ("-O1","/O1i-"),
        ("-O2","/O2i-"),
        ("-O3", "/O2i-"),
          ("-Od", "/Od"),
          (" -O ", " /O2 "),
}
if opts.disable_opt:
    optimization_subs = {
         ("-O0", "/Od"),
         ("/O0", "/Od"),
        ("-O1","/Od"),
        ("-O2","/Od"),
        ("-O3", "/Od"),
        ("-Od", "/Od"),
        (" -O ", " /Od "),
    }

#general set of substitutions for Lit to use when processing compile/run lines.
# these are a base that will be modified later for some sets of tests,
# some for individual tests, too
testConfig.substitutions = {
                            ("FileCheck ", "FileCheck --dump-input=fail "),
                            ("-fsanitize-coverage=func ", lit.TestingConfig.SubstituteCaptures("/d2Sancov " )),
                            ("%if_not_i386", 'if "' + opts.testTargetArch + '" neq "i386" '),
                            ("%if_i386", 'if "' + opts.testTargetArch + '" == "i386" '),
                            ("%sancov", "sancov.exe"),
                            ("%clangxx_asan ", litConfig.clang +  default_flags + runtime_flags + " /fsanitize=address /Oy- " ),
                            ("%clang_cl_asan ", litConfig.clang + default_flags + runtime_flags + " /fsanitize=address " ),
                            ("%clang_asan ", litConfig.clang +  default_flags + runtime_flags + " /fsanitize=address /Oy- "),
                            ("%clang_asan_no_rt ", litConfig.clang +  default_flags + " /fsanitize=address /Oy- "),
                            ("%clang_cl ", litConfig.clang + default_flags + runtime_flags),
                            ("%clang_cl_no_rt ", litConfig.clang + default_flags),
                            ("%clang ", litConfig.clang + default_flags + runtime_flags),
                            ("%cpp_compiler ", litConfig.clang + default_flags + runtime_flags + " /fsanitize=address /fsanitize=fuzzer "),
                            ("%no_fuzzer_cpp_compiler ", litConfig.clang + default_flags + runtime_flags),
                            ("%no_fuzzer_c_compiler ", litConfig.clang + default_flags + runtime_flags),
                            ("%libfuzzer_src", litConfig.compiler_rt_src_root + "\\lib\\fuzzer"),
                            ("%ml", ml_exe),
                            ("%env_asan_opts=", "env ASAN_OPTIONS=" ),
                            ("-Fe","/Fe:"),
                            ("%run"," cmd /v /c "),
                            ("-fomit-frame-pointer","/Oy"),
                            ("-fno-omit-frame-pointer","/Oy-"),
                            ("-fstack-protector"," /GS "),
                            ("%stdcxx11","/std:c++14"), # Apparently we don't have a c++11 flag :(
                            ("-std=","/std:"),
                            ("%clang_cfi", litConfig.clang + " /guard:cf "),
                            ("-link","/link /incremental:no"),
                            ("sed ",os.environ["UNIX_BIN_DIR"]+"\\sed.exe "),
                            ("mv ",os.environ["UNIX_BIN_DIR"]+"\\mv.exe "),
                            ("mkdir ",os.environ["UNIX_BIN_DIR"]+"\\mkdir.exe "),
                            ("grep ", os.environ["UNIX_BIN_DIR"]+"\\grep.exe "),
                            ("awk ", os.environ["UNIX_BIN_DIR"]+"\\awk.exe "),
                            ("rm ", os.environ["UNIX_BIN_DIR"]+"\\rm.exe "),
                            ("python ", sys.executable + " "),
                            ("-LD","/LD"),
                            (" -D"," /D"),
                            ("-x c "," /Tc%s "),
                            ("-x c\+\+ "," /Tp%s "),
                            ("-pie", ""),
                            ("%pie", ""),
                            ("-fPIE", " "),
                            ("%fPIE"," "),
                            ("-Wno-deprecated-declarations"," "),
                            ("%linux_static_libstdcplusplus", " "),
                            ("-fsanitize-address-use-after-scope", "/fsanitize=address"),
                            ("set ASAN_OPTIONS=suppressions=\"(.*)\"", lit.TestingConfig.SubstituteCaptures("set ASAN_OPTIONS=suppressions='\g<1>'")),
                            ("2>&1"," 2>&1 "),
                            ("echo ", os.environ["UNIX_BIN_DIR"]+"\\echo.exe "),
                            ("diff ", os.environ["UNIX_BIN_DIR"]+"\\diff.exe "),
                            ("-Wno-fortify-source", " "),
                            ("-Wl,-debug"," "),
                            ("-Wl,-OPT:REF", "/link /OPT:REF"),
                            ("%os", "Windows")
                            }

testConfig.substitutions |= optimization_subs
testConfig.environment["INCLUDE"] = testConfig.environment["INCLUDE"] + litConfig.compiler_rt_src_root + "\\include" + ";" + litConfig.compiler_rt_src_root + "\\test\\asan\\TestCases" + ";" + litConfig.compiler_rt_src_root + "\\lib\\fuzzer" + ";"
testConfig.environment["PATH"] += ";" + os.environ["ASAN_RT_BIN_DIR"] +";"+ os.environ["ASAN_RT_LIB_DIR"] + ";"
testConfig.environment['_NT_SYMBOL_PATH'] = os.environ['ASAN_RT_BIN_DIR']

#print litConfig.getToolsPath(opts.path[0],"",["cl.exe"])
if opts.debug_runtimes:
    testConfig.substitutions |= {("[\/\-](MT|MD)(?!d)", lit.TestingConfig.SubstituteCaptures("/\g<1>d"))}
    testConfig.available_features.append("debug-crt")
else:
    testConfig.available_features.append("non-debug-crt")
suite = lit.Test.TestSuite("msvc",sys.argv[1], os.environ['TEST_OUTPUT_DIR'], testConfig)


# grab the list of test source files in the directory we've selected
# If the suite uses .test files, only use those (ex: fuzzer). Otherwise, treat all source files as tests (ex: asan).
files = os.listdir(suite.source_root)
cc_files = [x for x in files if ".test" in x[-5:]]
if not cc_files:
    cc_files = [x for x in files if ".c" in x[-2:] or ".cpp" in x[-4:]]

#set up some blank lists and dicts for use later.
tests_to_run = []
results = {}
xfails = dict()

for cc_file in cc_files:
    # we're making a copy of each config and environment since we're
    # passing a copy to each thread we start.
    __testConfig = copy.deepcopy(testConfig)
    __litConfig = copy.deepcopy(litConfig)
    saved_subs = set([ copy.deepcopy(i) for i in copy.deepcopy(testConfig.substitutions) ])
    saved_env =  copy.deepcopy(testConfig.environment)
    for key in testConfig.environment:
        saved_env[key] = copy.deepcopy(testConfig.environment[key])
    __testConfig.substitutions = saved_subs
    __testConfig.environment = saved_env

    # start with a default test object, this may be re-created later.
    #test = lit.Test.Test(suite,[ cc_file],__litConfig)

    if opts.runTest == "" or opts.runTest in cc_file:
        if ".c" not in cc_file[-2:]:
            __testConfig.substitutions.add((" /EHs ", " "))
        #all
        saved_cl = __testConfig.environment["_CL_"]
        saved_link = __testConfig.environment["_LINK_"]

        if "unsymbolized" in cc_file:
            __testConfig.environment["_CL_"] = "/Zi /fsanitize=address"
            __testConfig.environment["_LINK_"] = " "
            __testConfig.substitutions -= {
                ("-O2","/O2i-"),
            }
            # this test assumes you'll need to manually link these libs,
            # our linker is now smart enough to omit these from the link line for this test on MT and MD.
            __testConfig.substitutions |= {
                    ("-o %t.obj","/Fo:%t.obj"),
                    ("%asan_lib", ""),
                    ("%asan_cxx_lib", "")
                }
        else:
            #elsewhere asan_lib and asan_cxx_lib should still resolve to the regular library names
            __testConfig.substitutions |= {
                out_to_obj_tuple,
                out_to_exe_tuple,
                ("%asan_lib", __litConfig.compiler_rt_libdir + "\\" + import_lib + ""),
                ("%asan_cxx_lib", __litConfig.compiler_rt_libdir + "\\" + runtime_thunk + ""),
            }
        if "seh.cpp" in cc_file:
            __testConfig.environment["_CL_"] = __testConfig.environment["_CL_"].replace("/EHs", "/EHa")
            __testConfig.substitutions |= {
                ("/EHs","/EHa"),
                ("/GS ", " /GS- ")
            }

        if "user-exception" in cc_file:
            __testConfig.substitutions |= {
                ("env ASAN_OPTIONS=([\w=0-9]+) ",lit.TestingConfig.SubstituteCaptures("set ASAN_OPTIONS=\g<1> && "))
            }

        if "use-after-scope" in cc_file:
            __testConfig.substitutions.remove(("-O1", "/O1i-"))
            __testConfig.substitutions.add(("-O1", "/Od"))
            __testConfig.substitutions.add(("-O1i-", "/Od"))

        __testConfig.environment['_CL_'] += " /Fd" + cc_file + ".pdb " + " "
        __testConfig.environment['_LINK_'] += " /force:multiple "
        __suite = lit.Test.TestSuite("msvc",sys.argv[1], os.path.join(__testConfig.environment['TEST_OUTPUT_DIR'],cc_file.replace(".","")+opts.testTargetArch), __testConfig)
        __test = lit.Test.Test(__suite,[ cc_file],__testConfig)
        print("found test %s"%(cc_file))
        tests_to_run.append( (cc_file, __test, __litConfig) )
        #print test.suite.getSourcePath(test.path_in_suite)
        if opts.print_env:
            for item in sorted(__testConfig.environment.keys()):
                print(str(item) + "=" + __testConfig.environment[item])
            for item in sorted(__testConfig.substitutions):
                print(item)
        """
        #print result.output
        results[cc_file] = result



        litConfig.environment["_CL_"] = saved_cl
        litConfig.environment["_LINK_"] = saved_link
        litConfig.environment["ASAN_OPTIONS"] = " "

        """

    else:
        continue

threads = []
run_single_tests = []

# thread function to kick off an individual test
def RunTest(tester,testObj):
    _name, _test, _config = testObj
    #print _config.environment['PATH']
    result = tester.executeShTest(_test,_config,True)
    _test.setResult(result)
    results[_name] = result

for testObj in tests_to_run:
    t = threading.Thread(target=RunTest, args=(lit.TestRunner, testObj,))
    t.name = testObj[0]
    """
    if "dll" in testObj[0]:
        run_single_tests.append((testObj[0],t))

    else:
    """
    threads.append(t)
started = []

max_active = 0
if opts.numThreads:
    max_active = opts.numThreads
else:
    max_active = 2 * int(os.environ["NUMBER_OF_PROCESSORS"])

current_active = 0
threads = set(threads)
waiting_on_count = len(threads)
started_threads = []

while waiting_on_count > 0:
    while current_active < max_active and len(threads) > 0:
        thread = threads.pop()
        started_threads.append(thread)
        thread.start()
        time.sleep(.1)
        current_active += 1
    remove_temp = []
    for thread in started_threads:

        thread.join(.1)
        if thread.is_alive():
            print("\rwaiting on %03d threads (%s)."% (waiting_on_count, thread.name))
        else:
            current_active -= 1
            waiting_on_count -= 1
            remove_temp.append(thread)
    for thread in remove_temp:
        started_threads.remove(thread)




"""
for thread in run_single_tests:
    print "running single test: " + thread[0]
    thread[1].start()
    thread[1].join()
"""

xpassed = 0
passed = 0
xfailed = 0
failed = 0
total = 0

print("Outputs =================================================================")

for result in results:
    print("%s ================================================================="%result)
    print(results[result].code)
    print(results[result].output)

xpasses = []
xfails = []
passes = []
fails = []

print("Expected Passes =================================================================")

for result in sorted(results.keys()):
    total += 1
    robj = results[result]
    if robj.code == lit.Test.PASS:
        xpassed += 1
        xpasses.append(result)
        print(result)

print("Expected Failures =================================================================")

for result in sorted(results.keys()):
    total += 1
    robj = results[result]
    if robj.code == lit.Test.XFAIL:
        xfailed += 1
        xfails.append(result)
        print(result)

print("Unexpected Passes =================================================================")
count = 0
for result in sorted(results.keys()):
    robj = results[result]
    if robj.code == lit.Test.XPASS:
        passed += 1
        passes.append(result)
        print(result)

print("Unexpected Failures =================================================================")

count = 0
for result in sorted(results.keys()):
    robj = results[result]
    if robj.code == lit.Test.FAIL:
        failed += 1
        fails.append(result)
        print(result)

print("passed %d out of %d tests"%(xpassed + xfailed ,xpassed+xfailed+passed+failed))

retcode = 1
if xpassed+xfailed  == xpassed+xfailed+passed+failed:
    retcode = 0

sys.exit( retcode )
