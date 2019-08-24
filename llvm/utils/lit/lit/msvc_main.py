#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import absolute_import
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
import lit.Test
import lit.run
import lit.util
import lit.discovery
import lit.TestRunner
import threading

SUPPORTED_DB_ENGINES = ['postgres', 'sqlite3','pyodbc']

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
        print('%s: %s (%d of %d)' % (test.result.code.name, test_name,
                                     self.completed, self.numTests))

        # Show the test failure output, if requested.
        if (test.result.code.isFailure and self.opts.showOutput) or \
           self.opts.showAllOutput:
            if test.result.code.isFailure:
                print("%s TEST '%s' FAILED %s" % ('*'*20, test.getFullName(),
                                                  '*'*20))
            print(test.result.output)
            print("*" * 20)

        # Report test metrics, if present.
        if test.result.metrics:
            print("%s TEST '%s' RESULTS %s" % ('*'*10, test.getFullName(),
                                               '*'*10))
            items = sorted(test.result.metrics.items())
            for metric_name, value in items:
                print('%s: %s ' % (metric_name, value.format()))
            print("*" * 10)

        # Report micro-tests, if present
        if test.result.microResults:
            items = sorted(test.result.microResults.items())
            for micro_test_name, micro_test in items:
                print("%s MICRO-TEST: %s" %
                         ('*'*3, micro_test_name))

                if micro_test.metrics:
                    sorted_metrics = sorted(micro_test.metrics.items())
                    for metric_name, value in sorted_metrics:
                        print('    %s:  %s ' % (metric_name, value.format()))

        # Ensure the output is flushed.
        sys.stdout.flush()

print """
    Run LLVM/Clang/ASAN unit tests on MSVC/ASAN
    usage:
    a) run vcvarsall or setenv from the compiler path you want to use to add include libs etc.
    b) set TEST_C_COMPILER=c:\\the\compiler\path\\to\use.exe
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
"""
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
parser.add_argument("-d", "--database", dest="dbengine",
                    help="Choose the database engine. Accepted values are:" + ','.join(SUPPORTED_DB_ENGINES),
                    type=str, default="postgres")
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
execution_group.add_argument("--max-failures", dest="maxFailures",
                    help="Stop execution after the given number of failures.",
                    action="store", type=int, default=None)

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

debug_group.add_argument("--write-sql-results", dest="write_sql_results",
                    help="write_sql_results to sqlite_database",
                    action="store_true", default=False)

debug_group.add_argument("--disable-optimizations", dest="disable_opt",
                    help="disable optimization",
                    action="store_true", default=False)

opts = parser.parse_args()
args = opts.test_paths



if opts.show_version:
    print("lit %s" % (lit.__version__,))


if not args:
    parser.error('No inputs specified')

if opts.numThreads is None:
    opts.numThreads = lit.util.detectCPUs()

if opts.maxFailures == 0:
    parser.error("Setting --max-failures to 0 does not have any effect.")

if opts.echoAllCommands:
    opts.showOutput = True

if opts.dbengine not in SUPPORTED_DB_ENGINES:
    parser.error('Unsupported DB engine. Should be one of: ' + ','.join(SUPPORTED_DB_ENGINES) + ' got ' + opts.dbengine)

inputs = args

MT_VERSION = None
MD_VERSION = None
if opts.debug_runtimes:
    MT_VERSION = " /MTd "
    MD_VERSION = " /MDd "
else:
    MT_VERSION = " /MT "
    MD_VERSION = " /MD "

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
        maxFailures = opts.maxFailures,
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
litConfig.clang = os.environ['TEST_C_COMPILER'] #"C:\Users\mamcgove.REDMOND\Desktop\\binaries\\bin\i386\cl.exe" #"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\amd64\cl.exe"
setattr(litConfig,"target_cflags","")
litConfig.environment = os.environ
litConfig.target_suffix = litConfig.target_arch
litConfig.compiler_rt_libdir = litConfig.environment['ASAN_RT_LIB_DIR']
litConfig.compiler_rt_src_root = litConfig.environment['ASAN_RT_SRC_ROOT']
litConfig.python_executable = "c:\python27\python.exe"
litConfig.android = False
litConfig.bits = "32"

if opts.force_dynamic:
     litConfig.available_features = [\
    'clang-dynamic-runtime', 'asan-32-bits',\
    'asan-dynamic-runtime','lld-available','stable-runtime','x86-target-arch',
    "shadow-scale-3", "msvc-host", "win32",'win32-dynamic-asan', 'windows-msvc']
else:
    litConfig.available_features = ["clang-static-runtime",
    'asan-32-bits', 'asan-static-runtime',
    'lld-available','stable-runtime','x86-target-arch',
    "shadow-scale-3", "msvc-host", "win32" , "windows-msvc" ]

litConfig.limit_to_features = False
litConfig.unsupported = False
default_flags = " /EHs  /DMSVC /D_WIN32 /Zi "
selected_runtime = None
link_these_libs = litConfig.compiler_rt_libdir + "\\clang_rt.asan-i386.lib " + litConfig.compiler_rt_libdir + "\\clang_rt.asan_cxx-i386.lib"
if opts.force_dynamic:
    link_these_libs = litConfig.compiler_rt_libdir + "\\clang_rt.asan_dynamic-i386.lib "
    litConfig.environment['_LINK_'] ="/debug /wholearchive:" + litConfig.compiler_rt_libdir + "\\clang_rt.asan_dynamic-i386.lib /wholearchive:"+litConfig.compiler_rt_libdir+"\\clang_rt.asan_dynamic_runtime_thunk-i386.lib /incremental:no "
    litConfig.environment['_CL_'] = MD_VERSION + " /Od "
    selected_runtime = MD_VERSION
    default_flags += " /Od "
    default_flags += MD_VERSION
else:
    link_these_libs = litConfig.compiler_rt_libdir + "\\clang_rt.asan-i386.lib "
    litConfig.environment['_LINK_'] ="/debug /wholearchive:" + litConfig.compiler_rt_libdir + "\\clang_rt.asan-i386.lib /wholearchive:"+litConfig.compiler_rt_libdir+"\\clang_rt.asan_cxx-i386.lib /incremental:no  "
    litConfig.environment['_CL_'] = MT_VERSION
    selected_runtime = MT_VERSION
    default_flags += MT_VERSION



full_cxx_asan_sub =  ("%clangxx_asan", litConfig.clang +  default_flags + " /d2ASAN " + link_these_libs )
truncated_cxx_asan_sub = ("%clangxx_asan", litConfig.clang +  default_flags + " /d2ASAN " )
truncated_cl_asan_sub = ("%clang_cl_asan", litConfig.clang + default_flags + " /d2ASAN " )
full_cl_asan_sub = ("%clang_cl_asan", litConfig.clang + default_flags + " /d2ASAN " +  litConfig.compiler_rt_libdir + "\\clang_rt.asan-i386.lib " +  litConfig.compiler_rt_libdir + "\\clang_rt.asan_cxx-i386.lib")
optimization_subs = {
       ("-O0", "/Od"),
        ("/O0", "/Od"),
        ("-O1","/O1i-"),
        ("-O2","/O2i-"),
        ("-O3", "/O2i-"),
          ("-Od", "/Od"),
          ("-O ", "/O2 "),
}
if opts.disable_opt:
    optimization_subs = {
         ("-O0", "/Od"),
         ("/O0", "/Od"),
        ("-O1","/Od"),
        ("-O2","/Od"),
        ("-O3", "/Od"),
        ("-Od", "/Od"),
        ("-O ", "/Od "),
    }

subsitute_obj = lit.TestingConfig.SubstituteCaptures("/Fe:%t\g<1>")

litConfig.substitutions = {
                            truncated_cl_asan_sub,
                            truncated_cxx_asan_sub,
                            ("%clang_asan", litConfig.clang +  default_flags + " /d2ASAN "),
                            ("%clang_cl ", litConfig.clang + default_flags),
                            ("%clang ", litConfig.clang + default_flags),
                            ("%asan_dll_thunk_lib", litConfig.compiler_rt_libdir + "\\clang_rt.asan_dynamic_runtime_thunk-i386.lib"),
                            ("%asan_dll_lib", litConfig.compiler_rt_libdir + "\\clang_rt.asan_dynamic-i386.lib"),
                            ("%asan_dll ", litConfig.compiler_rt_libdir + "\\clang_rt.asan_dynamic-i386.dll "),
                            ("(%env_asan_opts=)(([a-zA-Z0-9_]+=(?:[0-9]{1,4}|true|[a-zA-Z]{1,6}|false|\'\"[%\/a-zA-Z0-9\\\-_:=\. ]{1,50}\"\')[:  ]?){1,5})", lit.TestingConfig.SubstituteCaptures("cmd /v /c \"set ASAN_OPTIONS=\g<2> && ") ),
                            ("-Fe","/Fe: "),
                            ("-o %t.obj","/Fo:%t.obj"),
                            ("-o %t( |)",subsitute_obj),
                            ("%run"," cmd /c "),
                            ("-fomit-frame-pointer","/Oy"),
                            ("-fstack-protector"," /GS "),
                            ("%stdcxx11","/std:c++14"), # Apparently we don't have a c++11 flag :(
                            ("-std=","/std:"),
                            ("%clang_cfi", litConfig.clang + " /guard:cf "),
                            ("%asan_dll_thunk", litConfig.compiler_rt_libdir + "\\clang_rt.asan_dll_thunk-i386.lib"),
                            ("-link","/link /incremental:no"),
                            ("sed ",litConfig.environment["UNIX_BIN_DIR"]+"\\sed.exe "),
                            ("mv ",litConfig.environment["UNIX_BIN_DIR"]+"\\mv.exe "),
                            ("mkdir ",litConfig.environment["UNIX_BIN_DIR"]+"\\mkdir.exe "),
                            ("grep ", litConfig.environment["UNIX_BIN_DIR"]+"\\grep.exe "),
                            ("awk ", litConfig.environment["UNIX_BIN_DIR"]+"\\awk.exe "),
                            ("-LD","/LD"),
                            (" -D"," /D"),
                            ("cmd /v /c (\"|)(.*)(\|)\"?", lit.TestingConfig.SubstituteCaptures("cmd /v /c \"\g<2> \" 2>&1 \g<3>")), ##relies on capture for env_asan_opts above
                            ("-x c "," /Tc%s "),
                            ("-x c\+\+ "," /Tp%s "),
                            ("-pie", ""),
                            ("%pie", ""),
                            ("-fPIE", " "),
                            ("%fPIE"," "),
                            ("-Wno-deprecated-declarations"," "),
                            ("%linux_static_libstdcplusplus", " "),
                            ("-fsanitize-address-use-after-scope", "/d2ASAN"),
                            ("set ASAN_OPTIONS=suppressions=\"(.*)\"", lit.TestingConfig.SubstituteCaptures("set ASAN_OPTIONS=suppressions='\g<1>'")),
                            ("2>&1"," 2>&1 "),
                            ("echo ", litConfig.environment["UNIX_BIN_DIR"]+"\\echo "),
                            ("-Wno-fortify-source", " "),
                            ("-Wl,-debug"," ")
                            }
litConfig.substitutions |= optimization_subs
litConfig.environment["INCLUDE"] = litConfig.environment["INCLUDE"] + litConfig.compiler_rt_src_root + "\\include" + ";" + litConfig.compiler_rt_src_root + "\\test\\asan\\TestCases" + ";"
litConfig.environment["PATH"] += ";" + litConfig.environment["ASAN_RT_BIN_DIR"] +";"+ litConfig.environment["ASAN_RT_LIB_DIR"] + ";"
litConfig.pipefail = True
litConfig.bashPath = ""
#print litConfig.getToolsPath(opts.path[0],"",["cl.exe"])
if opts.debug_runtimes:
    litConfig.substitutions |= {("[\/\-](MT|MD)(?!d)", lit.TestingConfig.SubstituteCaptures("/\g<1>d"))}
    litConfig.available_features.append("debug-crt")
    litConfig.environment["_CL_"] += " /U_DEBUG /DNDEBUG=1 "
else:
    litConfig.available_features.append("non-debug-crt")
suite = lit.Test.TestSuite("msvc",sys.argv[1], litConfig.environment['TEST_OUTPUT_DIR'], litConfig)

files = os.listdir(suite.source_root)

cc_files = filter(lambda x: ".c" in x[-4:] and ".cfg" not in x[-4:], files)

#print cc_files
tests_to_run = []
results = {}
results_lock = threading.Lock()

def slashsan(stri):
    return stri.replace("\\","\\\\")

xfails = dict()

def RunTest(tester,testObj):
    _name, _test, _config = testObj
    #print _config.environment['PATH']
    result = tester.executeShTest(_test,_config,True)
    _test.setResult(result)
    results_lock.acquire()
    results[_name] = result
    results_lock.release()


for cc_file in cc_files:
    __litConfig = copy.deepcopy(litConfig)
    saved_subs = set([ copy.deepcopy(i) for i in copy.deepcopy(litConfig.substitutions) ])
    saved_env =  copy.deepcopy(litConfig.environment)
    for key in litConfig.environment:
        saved_env[key] = copy.deepcopy(litConfig.environment[key])
    __litConfig.substitutions = saved_subs
    __litConfig.environment = saved_env
    test = lit.Test.Test(suite,[ cc_file],__litConfig)

    if opts.runTest == "" or opts.runTest in cc_file:
        if ".cpp" not in cc_file:
            __litConfig.substitutions.add((" /EHs ", " "))
        #all
        saved_cl = __litConfig.environment["_CL_"]
        saved_link = __litConfig.environment["_LINK_"]
        if not opts.force_dynamic and "single_dll_thunk" in cc_file:
            __litConfig.substitutions.add(("%clang_cl_asan", __litConfig.clang + default_flags ))
            __litConfig.substitutions.add(("-fsanitize=address", " /d2ASAN "))
            __litConfig.substitutions.add(("[-/]DEXE(.*)", lit.TestingConfig.SubstituteCaptures(" /DEXE \g<1>" + " /link /wholearchive:" \
                        + slashsan(__litConfig.compiler_rt_libdir +  "\\clang_rt.asan-i386.lib " ) + " /wholearchive:" \
                        + slashsan(__litConfig.compiler_rt_libdir +  "\\clang_rt.asan_cxx-i386.lib " ) )))
            #__litConfig.substitutions.add(("[-/]DDLL(.*)", lit.TestingConfig.SubstituteCaptures(" /DDLL \g<1> ")))
        if not opts.force_dynamic and ("dll" in cc_file or "report_globals_vs_freelibrary" in cc_file):
            __litConfig.environment["_CL_"] = " /Zi "
            __litConfig.environment["_LINK_"] = "/debug /incremental:no "
            __litConfig.substitutions.remove(truncated_cl_asan_sub)
            __litConfig.substitutions.add(("%clang_cl_asan(.*)dll_host.cc", lit.TestingConfig.SubstituteCaptures("cl.exe \g<1>dll_host.cc ")))
            dll_combined = "cl.exe " + default_flags + " /d2ASAN \g<1> -Fe\g<2>.dll " + __litConfig.compiler_rt_libdir.replace("\\","\\\\") + "\clang_rt.asan-i386.lib " + "\g<3>"
            #this will work for most tests. There are some that require special cases.
            heap_alloc_capture = "%clang_cl_asan(.*)\.lib(.*)[/-]Fe(.*) -MT"
            heap_alloc_replace = slashsan(__litConfig.clang) + default_flags + " \g<1>.lib \g<2>/Fe\g<3> -MT"
            __litConfig.substitutions.add((heap_alloc_capture, lit.TestingConfig.SubstituteCaptures(heap_alloc_replace)))
            dll_large_func_capture = "%clang_cl_asan (.*).obj"
            dll_large_func_replace = slashsan(__litConfig.clang) + default_flags + " /d2ASAN \g<1>.obj"
            __litConfig.substitutions.add((dll_large_func_capture, lit.TestingConfig.SubstituteCaptures(dll_large_func_replace)))

            if "dll_null_deref" in cc_file:
                __litConfig.substitutions.add(("[-/]DDLL(.*)", lit.TestingConfig.SubstituteCaptures("/d2ASAN /DDLL \g<1> /link /wholearchive:" + slashsan(__litConfig.compiler_rt_libdir) + slashsan( "\\clang_rt.asan-i386.lib")) ))
            if "dll_host" in cc_file:
                __litConfig.substitutions.add(("%clang_cl_asan", lit.TestingConfig.SubstituteCaptures(slashsan(__litConfig.clang) + default_flags + " /d2ASAN ")))
                __litConfig.environment["_LINK_"] = saved_link
            if "multiple_dlls" in cc_file or "report_globals" in cc_file:
                __litConfig.environment["_CL_"] = " /Zi "
                __litConfig.environment["_LINK_"] = "/debug /incremental:no "
                __litConfig.substitutions.add(("%clang_cl_asan", __litConfig.clang + default_flags ))
                __litConfig.substitutions.add(("[-/]DEXE(.*)", lit.TestingConfig.SubstituteCaptures(" /DEXE \g<1>" )))
                if "report_globals_vs" not in cc_file :
                    __litConfig.substitutions.add(("[-/]DDLL(.*)", lit.TestingConfig.SubstituteCaptures("/d2ASAN /DDLL\g<1>" + " /link /wholearchive:" \
                        + slashsan(__litConfig.compiler_rt_libdir +  "\\clang_rt.asan_dynamic-i386.lib " + " /wholearchive:" + __litConfig.compiler_rt_libdir +\
                        "\\clang_rt.asan_dynamic_runtime_thunk-i386.lib "))))
                else:
                    __litConfig.substitutions.add(("[-/]DDLL(.*)", lit.TestingConfig.SubstituteCaptures("/d2ASAN /DDLL\g<1>" + " /link /wholearchive:" \
                        + slashsan(__litConfig.compiler_rt_libdir +  "\\clang_rt.asan-i386.lib " + " /wholearchive:" + __litConfig.compiler_rt_libdir +\
                        "\\clang_rt.asan_cxx-i386.lib "))))
            elif "heapalloc_dll" in cc_file or "dll_unload" in cc_file:
                __litConfig.substitutions.add(("%clang_cl_asan(.*)[-/]Fe(.*)\.dll(.*)", lit.TestingConfig.SubstituteCaptures(\
                    "cl.exe " + default_flags + " /d2ASAN \g<1> -Fe\g<2>.dll "  + "\g<3>" + __litConfig.compiler_rt_libdir.replace("\\","\\\\") + "\clang_rt.asan_dynamic-i386.lib ")))
            else:
                __litConfig.substitutions.add(("%clang_cl_asan(.*)[-/]Fe(.*)\.dll(.*)", lit.TestingConfig.SubstituteCaptures(dll_combined)))

        if "unsymbolized" in cc_file:
            __litConfig.environment["_CL_"] = "/Zi /d2ASAN"
            __litConfig.environment["_LINK_"] = " "
            __litConfig.substitutions -= {
                ("-O2","/O2i-"),
                ("-o %t( |)",subsitute_obj),
            }
            __litConfig.substitutions |= {
                ("-o %t.obj","/Fo:%t.obj"),
                ("%asan_lib", "/wholearchive:" + __litConfig.compiler_rt_libdir + "\\clang_rt.asan-i386.lib"),
                ("%asan_cxx_lib", "/wholearchive:" + __litConfig.compiler_rt_libdir + "\\clang_rt.asan_cxx-i386.lib"),
            ("-O2","/Od")
            }
        else:
            __litConfig.substitutions |= {
                ("%asan_lib", __litConfig.compiler_rt_libdir + "\\clang_rt.asan-i386.lib"),
                ("%asan_cxx_lib", __litConfig.compiler_rt_libdir + "\\clang_rt.asan_cxx-i386.lib"),
            }
        if "seh.cpp" in cc_file:
            __litConfig.environment["_CL_"] = __litConfig.environment["_CL_"].replace("/EHs", "/EHa")
            __litConfig.substitutions.add(("/EHs","/EHa"))



        if "interception_failure_test" in cc_file:
            __litConfig.environment["_CL_"] = " /Z7 "
            __litConfig.environment["_LINK_"] = "/debug /force:multiple  /incremental:no /wholearchive:" + __litConfig.compiler_rt_libdir + \
                "\\clang_rt.asan_dynamic-i386.lib " +" /wholearchive:" + __litConfig.compiler_rt_libdir + "\\clang_rt.asan_dynamic_runtime_thunk-i386.lib "
        if "throw_call_test.cc" in cc_file:
            __litConfig.environment["_CL_"] = " /Z7 /Od /d2ASAN "

        if "inline" in cc_file:
             __litConfig.environment["_CL_"] = " /Z7 "
        if ("global_dead_strip" in cc_file and "dll" not in cc_file) and not opts.force_dynamic:
             __litConfig.substitutions.add(full_cl_asan_sub)
             __litConfig.substitutions.add(("(.*)2>&1(.*)\|", lit.TestingConfig.SubstituteCaptures("\g<1> \g<2> \" 2>&1 |  ")))
        if "dll_global_dead_strip" in cc_file and not opts.force_dynamic:
            __litConfig.substitutions.add(truncated_cl_asan_sub)
            #__litConfig.substitutions.add(("(.*)2>&1(.*)\|", lit.TestingConfig.SubstituteCaptures("\g<1> \g<2> 2>&1 |  ")))
            __litConfig.substitutions.add(("2>&1", lit.TestingConfig.SubstituteCaptures("\" 2>&1")))
            __litConfig.environment['_LINK_'] ="/debug /wholearchive:" + litConfig.compiler_rt_libdir + "\\clang_rt.asan-i386.lib /wholearchive:"+litConfig.compiler_rt_libdir+"\\clang_rt.asan_cxx-i386.lib /incremental:no  "
        if "global_dead_strip" in cc_file and "dll" not in cc_file and opts.force_dynamic:
            pass

        __litConfig.environment['_CL_'] += " /Fd" + cc_file + ".pdb " + selected_runtime + " "
        __litConfig.environment['_LINK_'] += " /force:multiple "
        __suite = lit.Test.TestSuite("msvc",sys.argv[1], os.path.join(litConfig.environment['TEST_OUTPUT_DIR'],cc_file.replace(".","")), __litConfig)
        litConfig.substitutions = sorted(litConfig.substitutions)[::-1]
        __test = lit.Test.Test(__suite,[ cc_file],__litConfig)
        print "found test %s"%(cc_file)
        tests_to_run.append( (cc_file, __test, __litConfig) )
        #print test.suite.getSourcePath(test.path_in_suite)
        if opts.print_env:
            for item in sorted(litConfig.environment.keys()):
                print str(item) + "=" + litConfig.environment[item]
            for item in sorted(litConfig.substitutions):
                print item
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
for testObj in tests_to_run:
    t = threading.Thread(target=RunTest, args=(lit.TestRunner, testObj,))
    t.setName(testObj[0])
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
while waiting_on_count > 0:
    remove_threads = set([])
    for thread in threads:
        if current_active < max_active and thread not in started:
            started.append(thread)
            thread.start()
            current_active += 1
            time.sleep(.3)
            continue
        if thread not in started:
            continue
        else:
            thread.join(0.3)
            if thread.is_alive():
                print "thread join timed out for %s" % (thread.getName())
                time.sleep(.2)
                continue

            waiting_on_count -= 1
            current_active -= 1
            remove_threads |= {thread}
            print "\rWaiting on %d threads, %d active..."%(waiting_on_count,current_active)
    print "\rWaiting on %d threads, %d active..."%(waiting_on_count,current_active)
    threads = set(threads) - remove_threads
    time.sleep(.2)



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

print "Outputs ================================================================="

for result in results:
    print "%s ================================================================="%result
    print results[result].code
    print results[result].output

xpasses = []
xfails = []
passes = []
fails = []

print "Expected Passes ================================================================="

for result in sorted(results.keys()):
    total += 1
    robj = results[result]
    if robj.code == lit.Test.PASS:
        xpassed += 1
        xpasses.append(result)
        print result


print "Expected Failures ================================================================="

for result in sorted(results.keys()):
    total += 1
    robj = results[result]
    if robj.code == lit.Test.XFAIL:
        xfailed += 1
        xfails.append(result)
        print result


print "Unexpected Failures ================================================================="

count = 0
for result in sorted(results.keys()):
    robj = results[result]
    if robj.code == lit.Test.FAIL:
        failed += 1
        fails.append(result)
        print result

print "Unexpected Passes ================================================================="
count = 0
for result in sorted(results.keys()):
    robj = results[result]
    if robj.code == lit.Test.XPASS:
        passed += 1
        passes.append(result)
        print result



print "passed %d out of %d tests"%(xpassed + xfailed ,xpassed+xfailed+passed+failed)

retcode = 1
if xpassed+xfailed  == xpassed+xfailed+passed+failed:
    retcode = 0

if opts.write_sql_results:
    import os
    if opts.dbengine == 'postgres':
        import psycopg2 as dbengine
    elif opts.dbengine == 'sqlite3':
        import sqlite3 as dbengine
    elif opts.dbengine == 'pyodbc':
        import pyodbc as dbengine
    else:
        print "Unexpected DB engine %s" % opts.dbengine
        exit(-1)



    conn = None
    if opts.dbengine != 'pyodbc':
        if not os.environ.get("SQL_TABLE_PATH") or not os.environ.get("SQL_TABLE_NAME"):
            print "Must set the environment variables SQL_TABLE_PATH and SQL_TABLE_NAME"
            exit(-1)
        conn = dbengine.connect(os.environ["SQL_TABLE_PATH"])
    else:
        if not os.environ.get("GTDB_SECRET") and os.environ.get("SQL_TABLE_NAME"):
            print "Must set the environment variables GTDB_SECRET and SQL_TABLE_NAME"
            exit(-1)
        conn = dbengine.connect("Driver={ODBC Driver 17 for SQL Server};Server=tcp:asan.database.windows.net,1433;Database=asantests;Uid=greenteam@asan;Pwd="+os.environ["GTDB_SECRET"]+";Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;")
    c = conn.cursor()

    # Insert a row of data
    try:
            c.execute("INSERT INTO %s VALUES ( SYSDATETIME() , ?,?,?,?,?,?,?,?)"%os.environ["SQL_TABLE_NAME"], (xpassed,xfailed,passed,failed,",".join(xpasses),",".join(xfails),",".join(passes),",".join(fails)))
    except dbengine.ProgrammingError as err:
            c.execute('''CREATE TABLE %s (date DATETIME, expected_pass INTEGER, expected_fail INTEGER, unexpected_pass INTEGER, unexpected_fail INTEGER, xpasses text, xfails text, passes text, fails text)'''%os.environ["SQL_TABLE_NAME"])
            c.execute("INSERT INTO %s VALUES ( SYSDATETIME() , ?,?,?,?,?,?,?,?)"%os.environ["SQL_TABLE_NAME"], (xpassed,xfailed,passed,failed,",".join(xpasses),",".join(xfails),",".join(passes),",".join(fails)))


    # Save (commit) the changes
    conn.commit()
    # We can also close the connection if we are done with it.
    # Just be sure any changes have been committed or they will be lost.
    conn.close()

sys.exit( retcode )
