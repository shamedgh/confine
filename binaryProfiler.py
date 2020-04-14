import os, sys, subprocess, signal
import logging
import optparse

sys.path.insert(0, './python-utils/')

import util
import graph
import re
import syscall

import binaryAnalysis

def isValidOpts(opts):

    if not options.input or not options.callgraph or not options.separator or not options.mainapp:
        parser.error("All options -i, -m and -c should be specified")
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
    Find system calls for function
    """
    usage = "Usage: %prog -c <Callgraph> -s <Separator in callgraph file llvm=-> glibc=: > -f <Function name>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-i", "--input", dest="input", default=None, nargs=1,
                      help="Path to folder with binaries to analyze")

    parser.add_option("-c", "--callgraph", dest="callgraph", default=None, nargs=1,
                      help="Libc CFG")

    parser.add_option("-s", "--separator", dest="separator", default="->", nargs=1,
                      help="Separator")

    parser.add_option("-m", "--mainapp", dest="mainapp", default=None, nargs=1,
                      help="Main application name")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("binaryprofiler.log")

        libcCfg = graph.Graph(rootLogger)
        libcCfg.createGraphFromInput(options.callgraph, options.separator)

        dockerSyscalls = ["access","arch_prctl","brk","close","execve","exit_group","fcntl","fstat","geteuid","lseek","mmap","mprotect","munmap","openat","prlimit64","read","rt_sigaction","rt_sigprocmask","set_robust_list","set_tid_address","stat","statfs","write","setns","capget","capset","chdir","fchown","futex","getdents64","getpid","getppid","lstat","openat","prctl","setgid","setgroups","setuid","stat","io_setup","getdents","clone","readlinkat","newfstatat","getrandom","sigaltstack","getresgid","getresuid","setresgid","setresuid","alarm","getsid","getpgrp", "epoll_pwait", "vfork"]

        syscallObj = syscall.Syscall(rootLogger)
        syscallMap = syscallObj.createMap()
        syscallInverseMap = syscallObj.getInverseMap()
        dockerSyscallNums = set()
        for syscallStr in dockerSyscalls:
            rootLogger.debug("syscallInverseMap.get(syscallStr, -1): %s", str(syscallInverseMap.get(syscallStr, -1)))
            dockerSyscallNums.add(syscallInverseMap.get(syscallStr, -1))

        containerSyscallSet = set()
        containerSyscallSet.update(dockerSyscallNums)

        lib =  ".so"
        binList = set()
        libList = set()
        modList = set()
        indirectList = set()
        fileList = set()
        filesAdded = set()

        libcList = ["ld.so", "libc.so", "libdl.so", "libcrypt.so", "libnss_compat.so", "libnsl.so", "libnss_files.so", "libnss_nis.so", "libpthread.so", "libm.so", "libresolv.so", "librt.so", "libutil.so", "libnss_dns.so"]

        for fileName in os.listdir(options.input):
            if ( util.isElf(options.input + "/" + fileName) ):
                if ( lib in fileName ):
                    tmpFileName = re.sub("-.*so",".so",fileName)
                    tmpFileName = tmpFileName[:tmpFileName.index(".so")]
                    tmpFileName = tmpFileName + ".so"
                else:
                    tmpFileName = fileName
                if (  tmpFileName not in filesAdded ):
                    if ( tmpFileName not in libcList ):
                        indirectList.add(options.input + "/" + fileName)
                    if ( fileName.startswith("lib") and lib in fileName ):
                        libList.add(options.input + "/" + fileName)
                    elif ( fileName.startswith("mod") and lib in fileName ):
                        modList.add(options.input + "/" + fileName)
                    else:
                        binList.add(options.input + "/" + fileName)
                    fileList.add(options.input + "/" + fileName)
                    filesAdded.add(tmpFileName)

        syscallDict = dict()        #Key: bin/lib/mod Value: syscall set
        ALLLIBS = "libs"
        MAINAPP = options.mainapp
        syscallDict[ALLLIBS] = set()
        syscallDict[MAINAPP] = set()
        for filePath in fileList:
            directSyscallSet = set()
            indirectSyscallSet = set()
            fileName = filePath[filePath.rindex("/")+1:]
            myBinary = binaryAnalysis.BinaryAnalysis(filePath, rootLogger)

            if ( filePath in indirectList ):
                rootLogger.info("Extracting direct syscalls for: %s", fileName)
                directSyscallSet, successCount, failCount = myBinary.extractDirectSyscalls()
                rootLogger.info("Successfull direct syscalls: %d", successCount)
                rootLogger.warning("Failed syscalls: %d", failCount)

            rootLogger.info("Extracting indirect syscalls for: %s", fileName)
            indirectSyscallSet = myBinary.extractIndirectSyscalls(libcCfg)

            rootLogger.info("ELF: %s, directSyscallCount: %d, indirectSyscallCount: %d", fileName, len(directSyscallSet), len(indirectSyscallSet))
            rootLogger.info("   directSyscallCount: %s\n    indirectSyscallCount: %s", str(directSyscallSet), str(indirectSyscallSet))
            elfSyscallNameSet = set()
            elfSyscallNumSet = directSyscallSet.copy()
            elfSyscallNumSet.update(indirectSyscallSet)
            for syscallNum in directSyscallSet:
                elfSyscallNameSet.add(syscallMap.get(int(syscallNum)))
            for syscallNum in indirectSyscallSet:
                elfSyscallNameSet.add(syscallMap.get(int(syscallNum)))
            
            rootLogger.info("ELF-Syscall-Name-List: %s: %s", fileName, str(elfSyscallNameSet))
            rootLogger.info("ELF-Syscall-Num-List: %s: %s", fileName, str(elfSyscallNumSet))


            containerSyscallSet.update(directSyscallSet)
            containerSyscallSet.update(indirectSyscallSet)
            if ( filePath in libList ):
                syscallDict[ALLLIBS].update(directSyscallSet)
                syscallDict[ALLLIBS].update(indirectSyscallSet)
            elif ( filePath in modList ):
                syscallDict[MAINAPP].update(directSyscallSet)
                syscallDict[MAINAPP].update(indirectSyscallSet)
            elif ( filePath in binList ):
                if ( syscallDict.get(fileName, None) == None ):
                    syscallDict[fileName] = set()
                syscallDict[fileName].update(directSyscallSet)
                syscallDict[fileName].update(indirectSyscallSet)


        rootLogger.info("////////////////////final results///////////////////////////////")
        for fileName, syscallSet in syscallDict.items():
            if ( fileName != ALLLIBS ):
                if ( fileName == MAINAPP ):
                    syscallDict[MAINAPP].update(syscallDict[ALLLIBS])
                perFileSyscallList = set()
                for syscallNum in syscallDict[fileName]:
                    perFileSyscallList.add(syscallMap.get(int(syscallNum)))
                rootLogger.info("Bin: %s, len(syscallSet): %d, syscallSet: %s", fileName, len(syscallDict[fileName]), str(perFileSyscallList))

        rootLogger.info("Main App: %s: len(syscallSet): %d, len(containerSyscallSet): %d", MAINAPP, len(syscallDict[MAINAPP]), len(containerSyscallSet))
        containerWoAppSyscallSet = set(containerSyscallSet-syscallDict[MAINAPP])
        rootLogger.info("Main App: %s: (containerSyscallSet-syscallSet): %s", MAINAPP, str(containerWoAppSyscallSet))
        for syscallNum in containerWoAppSyscallSet:
            rootLogger.info("%s", syscallMap.get(int(syscallNum)))
