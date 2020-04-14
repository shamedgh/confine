import os, sys, subprocess, signal
import logging
import optparse

sys.path.insert(0, './python-utils/')

import bisect
import graph
import syscall
import seccomp

def isValidOpts(opts):
    """
    Check if the required options are sane to be accepted
        - Check if the provided files exist
        - Check if two sections (additional data) exist
        - Read all target libraries to be debloated from the provided list
    :param opts:
    :return:
    """
    if not options.cfginput or not options.funcinput:
        parser.error("All options -c and -f should be provided.")
        return False

    return True


def setLogPath(logPath):
    """
    Set the property of the logger: path, config, and format
    :param logPath:
    :return:
    """
    if os.path.exists(logPath):
        os.remove(logPath)

    rootLogger = logging.getLogger("coverage")
    if options.debug:
        logging.basicConfig(filename=logPath, level=logging.DEBUG)
        rootLogger.setLevel(logging.DEBUG)
    else:
        logging.basicConfig(filename=logPath, level=logging.INFO)
        rootLogger.setLevel(logging.INFO)

#    ch = logging.StreamHandler(sys.stdout)
    consoleHandler = logging.StreamHandler()
    rootLogger.addHandler(consoleHandler)
    return rootLogger
#    rootLogger.addHandler(ch)

if __name__ == '__main__':
    """
    Main function for finding physical memory usage of process
    """
    usage = "Usage: %prog -e <Target executable path> -p <PID of process to retrieve information about>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-c", "--cfginput", dest="cfginput", default=None, nargs=1,
                      help="Call function graph input")

    parser.add_option("-f", "--funcinput", dest="funcinput", default=None, nargs=1,
                      help="List of function names input")

    parser.add_option("-o", "--output", dest="output", default=None, nargs=1,
                      help="Output file path")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("syscallextractor.log")
        allSyscalls = set()
        myGraph = graph.Graph(rootLogger)
        myGraph.createGraphFromInput(options.cfginput, "->")
        exceptList = ["access","arch_prctl","brk","close","execve","exit_group","fcntl","fstat","geteuid","lseek","mmap","mprotect","munmap","openat","prlimit64","read","rt_sigaction","rt_sigprocmask","set_robust_list","set_tid_address","stat","statfs","write","setns","capget","capset",
    "chdir",
    "fchown",
    "futex",
    "getdents64",
    "getpid",
    "getppid",
    "lstat",
    "openat",
    "prctl",
    "setgid",
    "setgroups",
    "setuid",
    "stat",
    "io_setup",
    "getdents",
    "clone",
    "readlinkat",
    "newfstatat",
    "getrandom",
    "sigaltstack",
    "getresgid",
    "getresuid",
    "setresgid",
    "setresuid",
    "alarm",
    "getsid",
#    "pwrite64",
    "getpgrp"]
        
        syscallList = []
        i = 1
        while i < 400:
            syscallList.append("syscall(" + str(i) + ")")
            i += 1
 
        funcFile = open(options.funcinput, 'r')
        funcLine = funcFile.readline()
        while ( funcLine ):
            '''myGraph.addEdge(funcLine.strip(), "__" + funcLine.strip())
            myGraph.addEdge("__" + funcLine.strip(), funcLine.strip())
            if ( not funcLine.strip().endswith("64") ):
                myGraph.addEdge(funcLine.strip() + "64", funcLine.strip())
                myGraph.addEdge(funcLine.strip(), funcLine.strip() + "64")
            if ( funcLine.strip().endswith("64") ):
                myGraph.addEdge(funcLine.strip()[:-2], funcLine.strip())
                myGraph.addEdge(funcLine.strip(), funcLine.strip()[:-2])'''
            leaves = myGraph.getLeavesFromStartNode(funcLine.strip(), syscallList, list())
            allSyscalls = allSyscalls.union(leaves)
            funcLine = funcFile.readline()
        syscallList = list()
        for syscallStr in allSyscalls:
            syscallNum = int(syscallStr[8:-1])
            bisect.insort(syscallList, syscallNum)
        print (str(len(syscallList)))
        print (syscallList)
        syscallMapper = syscall.Syscall(rootLogger)
        syscallMap = syscallMapper.createMap()

        blackList = []
        i = 1
        while i < 400:
            if ( i not in syscallList and syscallMap.get(i, None) and syscallMap[i] not in exceptList):
                blackList.append(syscallMap[i])
            i += 1

        print ("Num of black listed syscalls: " + str(len(blackList)))
        seccompProfile = seccomp.Seccomp(rootLogger)
        blackListProfile = seccompProfile.createProfile(blackList)
        outputPath = options.output
        if ( options.output is None ):
            outputPath = "seccomp.out"
        outputFile = open(outputPath, 'w')
        outputFile.write(blackListProfile)
        outputFile.flush()
        outputFile.close()
