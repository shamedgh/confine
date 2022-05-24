import os, sys, subprocess, signal
import util

class Syscall():
    """
    This class can be used to create a graph and run DFS and BFS on it
    """
    def __init__(self, logger):
        self.logger = logger
        self.syscallMapType = ""
        self.syscallMap = dict()        #Num->Name
        self.syscallInverseMap = dict()     #Name->Num

    def createMap(self, mapType):
        self.syscallMapType = mapType
        if self.syscallMapType == "awk":
            mapDict = self.createMapWithAwk()
        elif self.syscallMapType == "auditd":
            mapDict = self.createMapWithAuditd()
        elif self.syscallMapType == "libseccomp":
            mapDict = self.createMapWithLibseccompTool()
        else:
            self.logger.info("Invalid syscall number mapping type specified, using awk")
            mapDict = self.createMapWithAwk()

        return mapDict

    def createMapWithAwk(self):
        mapCmd = 'awk \'BEGIN { print "#include <sys/syscall.h>" } /p_syscall_meta/ { syscall = substr($NF, 19); printf "syscalls[SYS_%s] = \\"%s\\";\\n", syscall, syscall }\' /proc/kallsyms | sort -u | gcc -E -P -'
        proc = subprocess.Popen([mapCmd], shell=True, stdout=subprocess.PIPE)
        (out, err) = proc.communicate()
        splittedOut = out.splitlines()
        self.logger.debug("Syscall map count found: %d", len(splittedOut))
        for outLineObj in splittedOut:
#            syscalls[137] = "statfs";
            outLine = str(outLineObj.decode("utf-8"))
            leftHand = outLine.split(" = ")[0]
            syscallNum = leftHand[9:-1]
            rightHand = outLine.split(" = ")[1]
            syscallName = rightHand[1:-2]
            try:
                self.syscallMap[int(syscallNum)] = syscallName.strip()
                self.syscallInverseMap[syscallName.strip()] = int(syscallNum)
            except:
                self.logger.debug("Syscall Number isn't integer: %s", syscallNum)
                continue
        return self.syscallMap

    def createMapWithAuditd(self):
        mapCmd = "ausyscall --dump"
        returncode, out, err = util.runCommand(mapCmd)
        if ( returncode != 0 ):
            self.logger.error("Error creating syscall map using ausyscall: %s", err)
            return None
        splittedOutStr = out.splitlines()
        self.logger.debug("Auditd Syscall map count found: %d", len(splittedOutStr))
        for outLine in splittedOutStr[1:]:
            syscallNum = outLine.split()[0]
            syscallName = outLine.split()[1]
            try:
                self.syscallMap[int(syscallNum)] = syscallName.strip()
                self.syscallInverseMap[syscallName.strip()] = int(syscallNum)
            except:
                self.logger.debug("Syscall Number isn't integer: %s", syscallNum)
                continue
        return self.syscallMap

    def createMapWithLibseccompTool(self):
        mapCmd = 'syscall-num-name'
        if util.shutil.which(mapCmd) == None:
            self.logger.error(mapCmd + " not found. Please install " + mapCmd + " tool")
            self.logger.error("Refer https://github.com/chethanah/syscall-num-name for installation steps")
            sys.exit("Error creating syscall map using libseccomp tool, exiting program")

        proc = subprocess.Popen([mapCmd], shell=True, stdout=subprocess.PIPE)
        (out, err) = proc.communicate()
        splittedOut = out.splitlines()
        self.logger.debug("Libsecccomp-rs based syscall map count found: %d", \
                            len(splittedOut))
        for outLineObj in splittedOut:
            outLine = str(outLineObj.decode("utf-8"))
            leftHand = outLine.split(" = ")[0]
            syscallNum = leftHand[9:-1]
            rightHand = outLine.split(" = ")[1]
            syscallName = rightHand[1:-2]
            try:
                self.syscallMap[int(syscallNum)] = syscallName.strip()
                self.syscallInverseMap[syscallName.strip()] = int(syscallNum)
            except:
                self.logger.debug("Syscall Number isn't integer: %s", syscallNum)
                continue
        return self.syscallMap

    def getInverseMap(self):
        return self.syscallInverseMap

    def getSyscallMapType(self):
        return self.syscallMapType

    def findDiff(self, dict1, dict2):
        for key, value in dict1.items():
            if ( dict2[key] != value ):
                self.logger.debug("Syscall map different for: %d, %s and %s", key, value, dict2[key])
            else:
                self.logger.debug("Num to value is the same for %d to %s", key, value)
        
#awk 'BEGIN { print "#include <sys/syscall.h>" } /p_syscall_meta/ { syscall = substr($NF, 19); printf "syscalls[SYS_%s] = \"%s\";\n", syscall, syscall }' /proc/kallsyms | sort -u | gcc -E -P -
