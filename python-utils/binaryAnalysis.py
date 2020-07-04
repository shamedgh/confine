import sys
import os
import util

class BinaryAnalysis:
    """
    This class can be used to extract direct system calls and possibly other information from a binary
    """
    def __init__(self, binaryPath, logger):
        self.binaryPath = binaryPath
        self.logger = logger

    def extractIndirectSyscalls(self, libcGraphObj):
        syscallList = list()

        i = 0
        while i < 400:
            syscallList.append("syscall(" + str(i) + ")")
            syscallList.append("syscall(" + str(i) + ")")
            syscallList.append("syscall ( " + str(i) + " )")
            syscallList.append("syscall( " + str(i) + " )")
            i += 1

        functionList = util.extractImportedFunctions(self.binaryPath, self.logger)
        self.logger.debug("binary: %s functionList: %s", self.binaryPath, str(functionList))
        tmpSet = set()
        for function in functionList:
            leaves = libcGraphObj.getLeavesFromStartNode(function, syscallList, list())
            tmpSet = tmpSet.union(leaves)

        allSyscalls = set()
        for syscallStr in tmpSet:
            syscallStr = syscallStr.replace("syscall( ", "syscall(")
            syscallStr = syscallStr.replace("syscall ( ", "syscall(")
            syscallStr = syscallStr.replace(" )", ")")
            syscallNum = int(syscallStr[8:-1])
            allSyscalls.add(syscallNum)

        return allSyscalls


    def extractDirectSyscalls(self):
        #Dump binary to tmp file
        dumpFileName = self.binaryPath + ".dump"
        if ( "/" in dumpFileName ):
            dumpFileName = dumpFileName[dumpFileName.rindex("/")+1:]
        dumpFilePath = "/tmp/" + dumpFileName
        cmd = "objdump -d {} > " + dumpFilePath
        if ( os.path.isfile(self.binaryPath) ):
            cmd = cmd.format(self.binaryPath)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Couldn't create dump file for: %s with err: %s", self.binaryPath, dumpFilePath)
                return None
            #Find direct syscalls and arguments
            #Specify how many were found successfully and how many were not
            syscallSet, successCount, failedCount = self.parseObjdump(dumpFilePath)
            #Return syscall list along with number of not found syscalls
            self.logger.debug("Finished extracting direct syscalls for %s, deleting temp file: %s", self.binaryPath, dumpFilePath)
            os.unlink(dumpFilePath)
            return (syscallSet, successCount, failedCount)
        else:
            self.logger.error("binary path doesn't exist: %s", self.binaryPath)
            return (None, -1)

    
    def sanitizeFnName(self, instr):
        outstr = ""
        for s in instr:
            if s == "<":
                continue
            if s == ">":
                continue
            if s == ":":
                continue
            outstr += s
        return outstr
    
    def decimalify(self, token):
        number = ""
        intnum = -1
        if token[0] == "$":
            number = token[1:]
        try:
            intnum = int(number, 16)
        except ValueError:
            pass
        return intnum
    
    def extractNum(self, ins):
        num = -1
        split = ins.split()
        for i in range(len(split)):
            if split[i] == "mov":
                # Next token should be src,dest
                srcdst = split[i+1].split(",")
                src = srcdst[0]
                dst = srcdst[1]
                if dst == "%rax" or dst == "%eax" or dst == "%rcx" or dst == "%ecx" or dst == "%edi" or dst == "%rdi":
                    num = self.decimalify(src)
             
        return num
    
    
    def parseObjdump(self, outputFileName):
        FnNameBodyMap = {}
        FnSysCallMap = {}
        failCount = 0
        successCount = 0
        f = open(outputFileName)
        fnName = ""
        for line in f:
            if "<" in line and ">:" in line:
                # Most likely new function start
                namesplit = line.split()
                fnName = self.sanitizeFnName(namesplit[1])
                FnNameBodyMap[fnName] = []
                FnSysCallMap[fnName] = []
                continue
            if fnName != "":
                FnNameBodyMap[fnName].append(line)
        f.close()
    
        # For each function
        syscallSet = set() 
        for fnName in FnNameBodyMap:
            body = FnNameBodyMap[fnName]
            for i in range(len(body)):
                line = body[i]
                if ("syscall" in line and "0f 05" in line) or ("syscall" in line and "e8" in line) :
                    # Check the past three lines for the value of the rax register
                    tmpI = i-1
                    num = self.extractNum(body[tmpI])
                    while ( num == -1 and (i - tmpI) < 15 and tmpI > 0 ):
                        tmpI = tmpI - 1
                        num = self.extractNum(body[tmpI])
                    #if num == -1:
                    #    num = extractNum(body[i-2])
                    #if num == -1:
                    #    num = extractNum(body[i-3])
                    #if num == -1:
                    #    num = extractNum(body[i-4])
                    #if num == -1:
                    #    num = extractNum(body[i-5])
                    #if num == -1:
                    #    num = extractNum(body[i-6])
                    #if num == -1:
                    #    num = extractNum(body[i-7])
                    #if num == -1:
                    #    num = extractNum(body[i-8])
                    #if num == -1:
                    #    num = extractNum(body[i-9])
                    #if num == -1:
                    #    num = extractNum(body[i-10])
                    if num == -1:
                        failCount += 1
                        self.logger.error("Can't reason about syscall in function: %s in line: %s", fnName, line)
                    else:
                        successCount += 1
                        syscallSet.add(num)
                        #FnSysCallMap[fnName].append(num)
   
        #for fnName in FnSysCallMap:
        #    for syscall in FnSysCallMap[fnName]:
        #        syscallSet.add(syscall)
        return (syscallSet, successCount, failCount)
