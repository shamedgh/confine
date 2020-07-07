import os, sys, subprocess, signal
import logging
import optparse
import ast

from random import seed
from random import randint

sys.path.insert(0, './python-utils')

import util
import graph
import callfunctiongraph

def isValidOpts(opts):
    """
    Check if the required options are sane to be accepted
        - Check if the provided files exist
        - Check if two sections (additional data) exist
        - Read all target libraries to be debloated from the provided list
    :param opts:
    :return:
    """
    if not options.filterfile or not options.cvefile or not options.vulntypefile:
        parser.error("Both options -f, -c and -v should be provided.")
        return False

    return True

def getNContainers(containerSet, n):
    importantImages = ['nginx', 'httpd', 'mysql', 'mongodb', 'redis', 'couchdb']
    resultSet = set()
    tempSet = set()
    for importantItem in importantImages:
        if ( importantItem in containerSet ):
            tempSet.add(importantItem)
    if ( len(tempSet) > n ):
        tempList = list(tempSet)
        seed(1)
        while ( len(resultSet) < n ):
            resultSet.add(tempList[randint(0,n)])
    else:
        containerList = list(containerSet)
        seed(1)
        while ( len(resultSet) < n ):
            resultSet.add(containerList[randint(0,n)])
    return resultSet
            
def getNCves(cveSet, n):
    if ( len(cveSet) <= n ):
        return cveSet
    resultSet = set()
    tempSet = set()
    cveList = list(cveSet)
    seed(1)
    while ( len(resultSet) < n ):
#        print ("len(cveSet): " + str(len(cveSet)) + " n: " + str(n))
        resultSet.add(cveList[randint(0,n)])
    return resultSet

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

    parser.add_option("-c", "--cvefile", dest="cvefile", default=None, nargs=1,
                      help="Path for CVE input file")

    parser.add_option("-f", "--filterfile", dest="filterfile", default=None, nargs=1,
                      help="Path to file containing Seccomp filter")

    parser.add_option("-o", "--output", dest="output", default="filterToCve", nargs=1,
                      help="Path to output file")

    parser.add_option("-v", "--vulntypefile", dest="vulntypefile", default=None, nargs=1,
                      help="Path to cve type file")

    parser.add_option("", "--manualcvefile", dest="manualcvefile", default=None, nargs=1,
                      help="Path to cve to syscall manual file")

    parser.add_option("", "--manualtypefile", dest="manualtypefile", default=None, nargs=1,
                      help="Path to cve to vulnerability type manual file")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("filterprofile.log")

        defaultSeccompList = ['acct', 'add_key', 'bpf', 'clock_adjtime', 'clock_settime', 'clone', 'create_module', 'delete_module', 'finit_module', 'get_kernel_syms', 'get_mempolicy', 'init_module', 'ioperm', 'iopl', 'kcmp', 'kexec_file_load', 'kexec_load', 'keyctl', 'lookup_dcookie', 'mbind', 'mount', 'move_pages', 'name_to_handle_at', 'nfsservctl', 'open_by_handle_at', 'perf_event_open', 'personality', 'pivot_root', 'process_vm_readv', 'process_vm_writev', 'ptrace', 'query_module', 'quotactl', 'reboot', 'request_key', 'set_mempolicy', 'setns', 'settimeofday', 'stime', 'swapon', 'swapoff', 'sysfs', '_sysctl', 'umount', 'umount2', 'unshare', 'uselib', 'userfaultfd', 'ustat', 'vm86', 'vm86old']

        prefix = "__x64_sys_"

        cveDict = dict()
        cveToVulnTypeDict = dict()
        cveToContainer = dict()
        cveDefaultSet = set()


        #1. We extract the type of vulnerability for each CVE
        vulnTypeFile = open(options.vulntypefile, 'r')
        vulnTypeLine = vulnTypeFile.readline()
        while ( vulnTypeLine ):
            splittedLine = vulnTypeLine.strip().split(";")
            cveId = splittedLine[0]
            vulnType = splittedLine[1] if splittedLine[1] != "set()" else None
            vulnTypes = set()
            if ( vulnType ):
                vulnType = vulnType.replace("{", "")
                vulnType = vulnType.replace("}", "")
                vulnType = vulnType.replace("'", "")
                if ( "," in vulnType ):
                    splittedVulns = vulnType.split(", ")
                    for vulnItem in splittedVulns:
                        vulnTypes.add(vulnItem.strip())
                else:
                    vulnTypes.add(vulnType.strip())                
            cveToVulnTypeDict[cveId] = vulnTypes
            vulnTypeLine = vulnTypeFile.readline()

        if ( options.manualtypefile ):
            cveTypeFile = open(options.manualtypefile, 'r')
            vulnTypeLine = cveTypeFile.readline()
            while ( vulnTypeLine ):
                splittedLine = vulnTypeLine.strip().split(";")
                cveId = splittedLine[0]
                vulnType = splittedLine[1] if splittedLine[1] != "set()" else None
                vulnTypes = set()
                if ( vulnType ):
                    vulnType = vulnType.replace("{", "")
                    vulnType = vulnType.replace("}", "")
                    vulnType = vulnType.replace("'", "")
                    if ( "," in vulnType ):
                        splittedVulns = vulnType.split(", ")
                        for vulnItem in splittedVulns:
                            vulnTypes.add(vulnItem.strip())
                    else:
                        vulnTypes.add(vulnType.strip())
                cveToVulnTypeDict[cveId] = vulnTypes
                vulnTypeLine = vulnTypeFile.readline()

        #2. We parse the main cve file which is generated automatically (using cfg, cve)
        cveFile = open(options.cvefile, 'r')
        cveLine = cveFile.readline()
        while ( cveLine ):
            validation = False
            validCve = False
            rootLogger.debug(cveLine)
            splittedLine = cveLine.split(";")
            cveId = splittedLine[0]
            syscallListStr = splittedLine[1]
            if ( len(splittedLine) > 2 ):
                validation = True
                validCve = True if int(splittedLine[2]) == 1 else False
            if ( not validation or validCve ):
                syscallList = ast.literal_eval(syscallListStr)
                cveDict[cveId] = syscallList
                cveToContainer[cveId] = set()
            cveLine = cveFile.readline()

        rootLogger.info("Finished parsing CVEs from %s", options.cvefile)

        #3. We parse any cve file generated manually
        if ( options.manualcvefile ):
            cveManualFile = open(options.manualcvefile, 'r')
            cveLine = cveManualFile.readline()
            while ( cveLine ):
                cveLine = cveLine.strip()
                rootLogger.debug(cveLine)
                splittedLine = cveLine.split(";")
                cveId = splittedLine[0]
                syscallListStr = splittedLine[1]
                if ( not cveDict.get(cveId, None) ):
                    rootLogger.debug("adding cveId: %s manually", cveId)
                    syscallListStr = "{'" + syscallListStr + "'}"
                    syscallListStr = syscallListStr.replace(", ", "', '")
                    syscallList = ast.literal_eval(syscallListStr)
                    cveDict[cveId] = syscallList
                    cveToContainer[cveId] = set()

                cveLine = cveManualFile.readline()
    
        #4. We extract the list of system calls filtered for each container
        filterFile = open(options.filterfile, 'r')
        filterLine = filterFile.readline()
        while ( filterLine ):
            rootLogger.debug(filterLine)
            splittedLine = filterLine.split(";")
            if ( len(splittedLine) > 7 ):
                imageName = splittedLine[1]
                syscallListStr = splittedLine[7]
                syscallSet = set(ast.literal_eval(syscallListStr))

                for cveId, syscallList in cveDict.items():
                    rootLogger.debug("cveId: %s len(syscallList): %d", cveId, len(syscallList))
                    applicable = True
                    oneSyscall = False
                    for syscallItem in syscallList:
                        syscallItemWoPrefix = syscallItem.replace("__x64_sys_", "")
                        if ( prefix in syscallItem ):
                            oneSyscall = True
                        if ( prefix in syscallItem and syscallItemWoPrefix not in syscallSet ):
                        #if ( syscallItem not in syscallSet ):
                            applicable = False
                            break
                    if ( applicable and oneSyscall ):
                        tempSet = cveToContainer.get(cveId, set())
                        tempSet.add(imageName)
                        cveToContainer[cveId] = tempSet

                    
            filterLine = filterFile.readline()

        #4. We extract the list of system calls filtered for each container
        syscallToCveDict = dict()
        for cveId, syscallList in cveDict.items():
            rootLogger.debug("cveId: %s len(syscallList): %d", cveId, len(syscallList))
            applicable = True
            oneSyscall = False
            for syscallItem in syscallList:
                syscallItemWoPrefix = syscallItem.replace("__x64_sys_", "")
                if ( prefix in syscallItem ):
                    oneSyscall = True
                if ( prefix in syscallItem and syscallItemWoPrefix not in defaultSeccompList ):
                #if ( syscallItem not in syscallSet ):
                    applicable = False
                    break
            if ( applicable and oneSyscall ):
                cveDefaultSet.add(cveId)
        cveDictToSyscallOnly = dict()
        for cveId, syscallList in cveDict.items():
            syscallSet = cveDictToSyscallOnly.get(cveId, set())
            for syscall in syscallList:
                if ( "_x64_sys_" in syscall ):
                    syscallSet.add(syscall)
            cveSet = syscallToCveDict.get(str(syscallSet), set())
            cveSet.add(cveId)
            syscallToCveDict[str(syscallSet)] = cveSet
            cveDictToSyscallOnly[cveId] = syscallSet

        #containerDetailedOutput = open(options.output + ".container.detailed.csv", 'w')
        containerOutput = open(options.output + ".container.csv", 'w')

        for cveId, containerSet in cveToContainer.items():
            cveInDefault = True if cveId in cveDefaultSet else False
            vulnType = cveToVulnTypeDict.get(cveId, "None")
            if ( len(containerSet) > 0 ):
                resultContainerSet = util.cleanStrList(str(containerSet))
                if ( len(containerSet) > 3 ):
                    resultContainerSet = util.cleanStrList(str(getNContainers(containerSet, 3)))

                #containerDetailedOutput.write(cveId + ";" + util.cleanStrList(cveDictToSyscallOnly[cveId]).replace("__x64_sys_", "") + ";" + util.cleanStrList(vulnType) + ";" + str(cveInDefault) + ";" + str(len(containerSet)) + ";" + str(containerSet) + "\n")
                #containerDetailedOutput.flush()
                containerOutput.write(cveId + ";" + util.cleanStrList(cveDictToSyscallOnly[cveId]).replace("__x64_sys_", "") + ";" + util.cleanStrList(vulnType) + ";" + str(cveInDefault) + ";" + str(len(containerSet)) + ";" + resultContainerSet + "\n")
                containerOutput.flush()
        containerOutput.close()

        #containerBySyscallDetailedOutput = open(options.output + ".container.by.syscall.detailed.csv", 'w')
        #containerBySyscallOutput = open(options.output + ".container.by.syscall.csv", 'w')
        #for syscallSet, cveSet in syscallToCveDict.items():
        #    cveId = next(iter(cveSet))
        #    containerSet = cveToContainer.get(cveId, set())
        #    cveInDefault = True if cveId in cveDefaultSet else False
        #    vulnTypes = set()
        #    resultCveSet = getNCves(cveSet, 2)
        #    for cveId in cveSet:
        #        if ( cveToVulnTypeDict.get(cveId, None) ):
        #            vulnTypes.update(cveToVulnTypeDict.get(cveId, "None"))
        #    if ( len(containerSet) > 0 ):
        #        resultContainerSet = util.cleanStrList(str(containerSet))
        #        if ( len(containerSet) > 3 ):
        #            resultContainerSet = util.cleanStrList(str(getNContainers(containerSet, 3)))
        #        containerBySyscallDetailedOutput.write(util.cleanStrList(syscallSet).replace("__x64_sys_", "") + ";" + str(cveSet) + ";" + str(vulnTypes) + ";" + str(cveInDefault) + ";" + str(len(containerSet)) + ";" + resultContainerSet + "\n")
        #        containerBySyscallDetailedOutput.flush()
        #        containerBySyscallOutput.write(util.cleanStrList(syscallSet).replace("__x64_sys_", "") + ";" + str(len(cveSet)) + ";" + util.cleanStrList(resultCveSet) + ";" + str(util.cleanStrList(vulnTypes)) + ";" + str(cveInDefault) + ";" + str(len(containerSet)) + ";" + resultContainerSet + "\n")
        #        containerBySyscallOutput.flush()
        #containerBySyscallDetailedOutput.close()
        #containerBySyscallOutput.close()
        #    

        #defaultOutput = open(options.output + ".default.csv", 'w')

        #for cveId in cveDefaultSet:
        #    defaultOutput.write(cveId + ";" + str(cveDictToSyscallOnly[cveId]) + ";all;all\n")
        #    defaultOutput.flush()
        #defaultOutput.close()
