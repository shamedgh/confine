import os, sys, subprocess, signal
import json

sys.path.insert(0, './python-utils/')

import util
import constants as C

class Container():
    """
    This class can be used to extract information regarding a container created from a docker image
    """
    def __init__(self, name, options, logger, remote=None, args=None):
        self.logger = logger
        self.imageName = name
        self.containerName = name
        if ( "/" in self.containerName ):
            self.containerName = name.replace("/", "-")
        if ( ":" in self.containerName ):
            self.containerName = self.containerName[:self.containerName.index(":")]
        self.containerName += "-container"
        self.options = options
        if ( remote ):
            self.remote = remote
        else:
            self.remote = ""
        if ( args ):
            self.args = args
        else:
            self.args = ""
        self.containerId = None
        self.debian = -1    #-1: Not checked yet    0: Redhat based    1: Debian based

    '''
    TODO:
    *** We have to consider different OS types (debian or redhat based)
    *** Since all the commands will change we should use inheritance and create different classes for each type of OS
    1. Run container image (name should be passed by constructor)
    2. Take snapshot of executables running (through ps, probably need to install ps first)
    3. Find path to binaries extracted from snapshot
    4. Extract list of all libc functions required for snapshot binaries
    5. Run extractSysCalls script to create seccomp profile
    6. 
    '''

    def isRemote(self):
        return self.remote != ""

    def getRemoteIp(self):
        if ( self.isRemote() ):
            return self.remote.split("@")[1]
        else:
            self.logger.warning("Trying to get remote IP on non-remote container object")

    def setContainerId(self, containerId):
        self.containerId = containerId

    def pruneVolumes(self):
        cmd = "sudo docker volume prune -f --filter \"label=={}\""
        cmd = cmd.format(C.TOOLNAME)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running prune on docker with label: %s", err)
            return False
        return True

    def run(self):
        self.logger.info("Running container %s", self.imageName)
        #TODO extract log in both scenarios, mariadb logs is the same with unconfined percona the other
        #cmd = "sudo docker {} run -l {}  --security-opt seccomp=unconfined --name {} {} -td {}"
        cmd = "sudo docker {} run -l {} --name {} {} -td {} {}"
        cmd = cmd.format(self.remote, C.TOOLNAME, self.containerName, self.options, self.imageName, self.args)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running docker: %s", err)
            return False
        self.containerId = out.strip()
        return True

    def runWithoutSeccomp(self):
        self.logger.info("Running container %s", self.imageName)
        #TODO extract log in both scenarios, mariadb logs is the same with unconfined percona the other
        cmd = "sudo docker {} run -l {} --security-opt seccomp=unconfined --name {} {} -td {} {}"
        cmd = cmd.format(self.remote, C.TOOLNAME, self.containerName, self.options, self.imageName, self.args)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running docker: %s", err)
            return False
        self.containerId = out.strip()
        return True

    def runWithRuntime(self, runtime):
        self.logger.info("Running container %s with runtime: %s", self.imageName, runtime)
        #TODO extract log in both scenarios, mariadb logs is the same with unconfined percona the other
        cmd = "sudo docker {} run -l {} --runtime={} --name {} {} -td {} {}"
        cmd = cmd.format(self.remote, C.TOOLNAME, runtime, self.containerName, self.options, self.imageName, self.args)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running docker: %s", err)
            return False
        self.containerId = out.strip()
        return True

    def runInAttachedMode(self):
        self.logger.info("Running container in attached mode %s", self.imageName)
        cmd = "sudo docker {} run -l {} --name {} {} -it {} {}"
        cmd = cmd.format(self.remote, C.TOOLNAME, self.containerName, self.options, self.imageName, self.args)
        proc = util.runCommandWithoutWait(cmd)
        if ( not proc ):
            self.logger.error("Error running docker in attached mode: %s", err)
            return False
        self.containerId = self.containerName
        return True

    def runWithSeccompProfile(self, seccompPath):
        self.logger.info("Running container %s", self.imageName)
        cmd = "sudo docker {} run -l {} --name {} {} --security-opt seccomp={} -td {} {}"
        cmd = cmd.format(self.remote, C.TOOLNAME, self.containerName, self.options, seccompPath, self.imageName, self.args)
        returncode, out, err = util.runCommand(cmd)
        self.containerId = out.strip()
        if ( returncode != 0 ):
            self.logger.error("Error running docker: %s", err)
            return False
        return True
    

    def kill(self):
        if ( self.containerId ):
            self.logger.info("Killing container %s", self.imageName)
            cmd = "sudo docker {} kill {}"
            cmd = cmd.format(self.remote, self.containerId)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error killing docker: %s", err)
                return False
            return True
        else:
            self.logger.error("Trying to kill non-existent container")
            return False

    def find(self, folder, fileName):
        if ( self.containerId ):
            self.logger.info("Finding on container %s", self.imageName)
            cmd = "sudo docker {} exec -it {} find {} -name {}"
            cmd = cmd.format(self.remote, self.containerId, folder, fileName)
            self.logger.debug("Find command: %s", cmd)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error running find docker: %s", err)
                return ""
            return out
       
    def runCommand(self, cmd):
        if ( self.containerId ):
            self.logger.info("Running cmd: %s on container: %s", cmd, self.containerId)
            cmd = "sudo docker {} exec -it {} " + cmd
            cmd = cmd.format(self.remote, self.containerId)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error running cmd: %s", cmd)
                return False
        return True

    def getImageName(self):
        return self.imageName
 
    def delete(self):
        if ( self.containerId ):
            self.logger.info("Deleting container %s", self.imageName)
            cmd = "sudo docker {} rm {}"
            cmd = cmd.format(self.remote, self.containerId)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error deleting docker: %s", err)
                return False
            return True
        else:
            self.logger.error("Trying to delete non-existent container")
            return False

    def checkStatus(self):
        if ( not self.containerId ):
            self.logger.error("Trying to check status of non-running container! self.containerId: %s", self.containerId)
            return False
        cmd = "docker " + self.remote + " inspect -f '{{.State.Running}}' " + self.containerName
        returncode, out, err = util.runCommand(cmd)
        self.logger.debug("docker inspect status returned: %s", out)
        if ( returncode != 0 ):
            self.logger.error("Problem checking container status, error: %s", err)
            return False
        if ( out.strip() == "false" ):
            return False
        return True

    def copyFromContainer(self, filePath, outFolderPath):
        if ( not self.containerId ):
            self.logger.error("Trying to copy file from non-running container! self.containerId: %s", self.containerId)
            return False
        cmd = "sudo docker {} cp -L {}:{} {}"
        cmd = cmd.format(self.remote, self.containerId, filePath, outFolderPath)
        self.logger.debug("Running command: %s", cmd)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error copying from docker. dockerId: %s, filePath: %s, outputFolderPath: %s Error message: %s", self.containerId, filePath, outFolderPath,  err)
            return False
        return True

    def copyFromContainerWithLibs(self, filePath, outFolderPath):
        if ( not self.containerId ):
            self.logger.error("Trying to copy file from non-running container! self.containerId: %s", self.containerId)
            return False


        originalCmd = "sudo docker {} cp -L {}:{} {}"
        cmd = originalCmd.format(self.remote, self.containerId, filePath, outFolderPath)
        returncode, out, err = util.runCommand(cmd)
        tempFilePath = filePath
        if ( returncode != 0 ):
            self.logger.error("Error copying from docker. Starting to check for file in environment paths. dockerId: %s, filePath: %s, outputFolderPath: %s Error message: %s", self.containerId, filePath, outFolderPath,  err)
            cmd = "sudo docker exec -it {} echo $PATH"
            cmd = cmd.format(self.containerId)
            returncode, envPaths, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.warning("Error running echo PATH command on docker: %s, forfeiting file: %s", err, filePath)
                return False
            envPaths = envPaths.split(":")
            for envPath in envPaths:
                envPath = envPath.strip()
                filePath = envPath + "/" + tempFilePath
                cmd = originalCmd.format(self.remote, self.containerId, filePath, outFolderPath)
                returncode, out, err = util.runCommand(cmd)
                if ( returncode == 0 ):
                    tempFilePath = filePath
                    break
        if ( filePath != tempFilePath ):    #Use it as an identifier of having been able to find file in one of the env. paths or not
            return False
        
        if ( tempFilePath.strip() != "" and util.isFolder(outFolderPath + "/" + util.getNameWithExtFromPath(tempFilePath)) ):
            folderPath = outFolderPath + "/" + util.getNameWithExtFromPath(tempFilePath)
            util.deleteFolder(folderPath, self.logger)
            return True
        return self.extractLibsFromBinary(filePath, outFolderPath)

    def getIp(self):
        if ( not self.containerId ):
            self.logger.error("Trying to get IP from non-running container! self.containerId: %s", self.containerId)
            return ""
        cmd = "docker " + self.remote + " inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' " + self.containerId
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error trying to extract IP for container: %s errmsg: %s", self.containerId, err)
            return ""
        return out.strip()

    def extractLibsFromBinary(self, filePath, outFolderPath):
        if ( not self.containerId ):
            self.logger.error("Trying to extract binary libs from non-running container! self.containerId: %s", self.containerId)
            return False
        cmd = "sudo docker " + self.remote + " exec -it {} ldd {}"
        cmd = cmd.format(self.containerId, filePath)
        self.logger.debug("Running command: %s", cmd)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 and out.strip() == "" ):   #In cases the binary doesn't have a dynamic section and so the return code isn't 0 but we don't have an error either
            self.logger.error("Error extracting library dependencies from docker: %s", err)
            return False

        splittedOut = out.splitlines()
        for outItem in splittedOut:
            if ( "=>" in outItem ):
                splittedItem = outItem.split("=>")
                if ( len(splittedItem) > 1 ):
                    splittedItem = splittedItem[1].split()
                    if ( not self.copyFromContainer(splittedItem[0].strip(), outFolderPath) ):
                        self.logger.warning("Wasn't able to copy library: %s dependent of: %s", splittedItem[0].strip(), filePath)
                else:
                    self.logger.warning("This should not happen! ldd output line has => but can't be split into two parts by that substring.")
        return True

    def extractAllUsersFromPasswd(self):
        userList = list()
        cmd = "sudo docker " + self.remote + " exec -it {} cat /etc/passwd"
        cmd = cmd.format(self.containerId)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Can't cat /etc/passwd: %s", err)
#            sys.exit(-1)
        outLines = out.splitlines()
        for user in outLines:
            splittedLine = user.split(":")
            userList.append(splittedLine[0].strip())
        return userList

    def extractDetailsFromPidList(self, pidList):
        #Extract all usernames from /etc/passwd
        #We do this because we can't rely on getting the full username from ps (because of compatibility issues in differen OSes, alpine, ubuntu, busybox, ....)
        pidToUserDict = dict()
        pidToCmdDict = dict()
        userList = self.extractAllUsersFromPasswd()
        self.logger.debug("userList from passwd: %s", str(userList))
        #Check if ps is available in the container
        pidIndex = 0
        userIndex = 1
        cmdIndex = 2
        self.installPackage("procps")
        cmd = "sudo docker " + self.remote + " exec -it {} ps -aux"
        cmd = cmd.format(self.containerId)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            cmd = "sudo docker " + self.remote + " exec -it {} ps -a"
            cmd = cmd.format(self.containerId)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.warning("ps options isn't available")
                return pidToUserDict, pidToCmdDict
        outLines = out.splitlines()
        headerLine = outLines[0]
        index = 0
        for headerItem in headerLine.split():
            if ( headerItem.lower() == "pid" ):
                pidIndex = index
            if ( headerItem.lower() == "user" ):
                userIndex = index
            if ( headerItem.lower() == "command" ):
                cmdIndex = index
            index += 1
        for outLine in outLines[1:]:
            splittedOut = outLine.split()
            if ( len(splittedOut) > 1 ):
                pid = splittedOut[pidIndex].strip()
                cmd = splittedOut[cmdIndex].strip()
                partialUserName = splittedOut[userIndex].strip()
                if ( partialUserName.endswith("+") ):
                    partialUserName = partialUserName[:-1]
                    for user in userList:
                        if ( user.startswith(partialUserName) ):
                            userName = user
                            break
                else:
                    userName = partialUserName
                pidToUserDict[pid] = userName
                pidToCmdDict[pid] = cmd
        #cmd = "sudo docker exec -it {} ps -q {} axo user"
        #for pid in pidList:
        #    finalCmd = cmd.format(self.containerId, pid)
        #    returncode, out, err = util.runCommand(finalCmd)
        #    if ( returncode != 0 ):
        #        self.logger.error("Can't extract user for pid: %s", pid)
        #    else:
        #        splittedOut = out.splitlines()
        #        print ("splittedOut: " + str(splittedOut))
        #        print ("len(splittedOut): " + str(len(splittedOut)))
        #        if ( len(splittedOut) > 1 ):
        #            pidToUserDict[pid] = splittedOut[1].strip()
        #        else:
        #            self.logger.error("ps command doesn't have enough output lines for pid: %s", pid)
        return pidToUserDict, pidToCmdDict

    def extractLibsFromProc(self):
        libSet = set()
        if ( not self.containerId ):
            self.logger.error("Trying to extract binary libs from non-running container! self.containerId: %s", self.containerId)
            return False

        #Installing packages procps and runuser, regardless of whether it's already installed or not
        self.installPackage("runuser")
        #TODO Extract list of processes from proc
        psList = list()
        cmd = "sudo docker " + self.remote + " exec -it " + self.containerId + " ls -1a /proc/ > /tmp/proc.tmp"
        returncode, out, err = util.runCommand(cmd)
        myfile = open("/tmp/proc.tmp", 'r')
        line = myfile.readline()
        while ( line ):
            line = line.strip()
            line = line.replace("\x1b[1;34m", "")
            line = line.replace("\x1b[m", "")
            if ( line != "" and line.isdigit() ):
                psList.append(line)
            line = myfile.readline()
#        outLines = out.splitlines()
#        for line in outLines:
#            line = line.strip()
#            if ( line.isdigit() ):
#                psList.append(line)
        self.logger.debug("ps from /proc: %s", str(psList))

        #TODO Find user of running process (preferably without ps)
        pidToUserDict, pidToCmdDict = self.extractDetailsFromPidList(psList)
        self.logger.debug("pidToUserDict: %s", str(pidToUserDict))
        #TODO Extract list of dependent libraries per process
        cmd = "sudo docker {} exec -it {} cat /proc/{}/maps"
        cmdWithUser = "sudo docker {} exec -it {} runuser -l {} -c 'cat /proc/{}/maps'"
        cmdWithUserWithSh = "sudo docker {} exec -it {} su -s \"/bin/sh\" -c \"cat /proc/{}/maps\" {}"
        getPidOnHostCmd = "sudo ps -aux | grep {}"
        cmdOnHost = "sudo cat /proc/{}/maps"
        for pid in psList:
            finalCmd = cmd.format(self.remote, self.containerId, pid)
            returncode, out, err = util.runCommand(finalCmd)
            if ( returncode != 0 ):
                self.logger.warning("Couldn't run cat /proc/%s with default user, trying with runuser command", pid)
                user = pidToUserDict.get(pid, None)
                if ( not user ):
                    self.logger.error("Can't retrieve username for pid: %s", pid)
                    user = "root"
                finalCmd = cmdWithUser.format(self.remote, self.containerId, user, pid)
                returncode, out, err = util.runCommand(finalCmd)
                if ( returncode != 0 ):
                    self.logger.warning("Couldn't run cat /proc with runuser, trying with su")
                    finalCmd = cmdWithUserWithSh.format(self.remote, self.containerId, pid, user)
                    returncode, out, err = util.runCommand(finalCmd)
                    if ( returncode != 0 ):
                        self.logger.warning("Couldn't run cat /proc with su, trying on host!")
                        if ( pidToCmdDict.get(pid, None) ):
                            getPidOnHostFinalCmd = getPidOnHostCmd.format(pidToCmdDict[pid])
                            returncode, out, err = util.runCommand(getPidOnHostFinalCmd)
                            if ( out != "" ):
                                outLines = out.splitlines()
                                hostOut = ""
                                for outLine in outLines:
                                    hostPid = outLine.split()[1]
                                    cmdOnHostFinal = cmdOnHost.format(hostPid)
                                    returncode, tmpOut, err = util.runCommand(cmdOnHostFinal) 
                                    if ( returncode == 0 ):
                                        hostOut += tmpOut + "\n"
                                out = hostOut
                        else:
                            self.logger.error("Can't extract maps from host because pidToCmd is empty for %s", pid)
            outLines = out.splitlines()
            for line in outLines:
                splittedLine = line.split()
                if ( len(splittedLine) == 6 ):
                    libName = splittedLine[5]
                    permissions = splittedLine[1]
                    if ( permissions[2] == 'x' ):
                        libSet.add(libName)
        self.logger.debug("libs from /proc: %s", str(libSet))
        return libSet

    def checkOs(self):
        cmd = "sudo docker {} exec -it {} cat /etc/*release"
        cmd = cmd.format(self.remote, self.containerId)
        returncode, out, err = util.runCommand(cmd)
        if ( out.strip() == "" ):
            self.logger.error("Can't check release for os type, falling back to ubuntu")
            return "debian"
        out = out.lower()
        if ( "ubuntu" in out or "debian" in out ):
            return "debian"
        else:
            return "redhat"

    def checkLogs(self):
        if ( not self.containerId ):
            self.logger.error("Trying to check logs on non-running container! self.containerId: %s", self.containerId)
            return False
        cmd = "sudo docker {} logs {}"
        cmd = cmd.format(self.remote, self.containerId)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running logs command on docker: %s", err)
            return None
        return out

    def installPackage(self, packageName):
        if ( not self.containerId ):
            self.logger.error("Trying to install package on non-running container! self.containerId: %s", self.containerId)
            return False
        if ( self.checkOs() == "debian" ):
            self.logger.info("Running apt-get update on container")
            cmd = "sudo docker {} exec -it {} apt-get update"
            cmd = cmd.format(self.remote, self.containerId)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error running apt-get update on docker: %s", err)
                return False
            self.logger.info("Running apt install -y %s", packageName)
            cmd = "sudo docker {} exec -it {} apt install -y {}"
            cmd = cmd.format(self.remote, self.containerId, packageName)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error installing procps docker: %s", err)
                return False
            self.logger.info("Finished running apt install -y %s", packageName)
        else:
            self.logger.info("Running yum -y update on container")
            cmd = "sudo docker {} exec -it {} yum -y update"
            cmd = cmd.format(self.remote, self.containerId)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error running yum -y update on docker: %s", err)
                return False
            self.logger.info("Running yum install -y %s", packageName)
            cmd = "sudo docker {} exec -it {} yum install -y {}"
            cmd = cmd.format(self.remote, self.containerId, packageName)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Error installing procps docker: %s", err)
                return False
            self.logger.info("Finished running yum install -y %s", packageName)
        return True

    def extractAllBinaries(self):
        if ( not self.containerId ):
            self.logger.error("Trying to extract binaries from non-running container! self.containerId: %s", self.containerId)
            return False
        processList = []
        cmd = "sudo docker {} exec -it {} "
        cmd = cmd.format(self.remote, self.containerId)
        cmd = cmd + util.getCmdRetrieveAllBinaries("/")
        self.logger.debug("Running command: %s", cmd)
        returncode, out, err = util.runCommand(cmd)
        splittedOut = out.splitlines()
        for binaryFilePath in splittedOut:
            binaryFilePath = binaryFilePath[:binaryFilePath.index(":")]
            processList.append(binaryFilePath)
        return processList

    def extractBinariesFromAuditLog(self, auditLogOutput):
        if ( not self.containerId ):
            self.logger.error("Trying to extract binaries from non-running container! self.containerId: %s", self.containerId)
            return None
        processList = []

        cmd = "sudo docker {} exec -it {} echo $PATH"
        cmd = cmd.format(self.remote, self.containerId)
        returncode, envPaths, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running echo PATH command on docker: %s", err)
            return None


        splittedOut = auditLogOutput.splitlines()
        for outLine in splittedOut:
            #type=EXECVE msg=audit(05/09/2019 14:49:01.489:29065511) : argc=3 a0=/usr/sbin/sshd a1=-D a2=-R
            splittedArgs = outLine.split()
            for argkv in splittedArgs:
                if ( argkv.startswith("a0=") ):
                    processList.append(argkv[3:])
                    break

        return processList
        

    def extractListOfRunningProcesses(self, tempOutputFolder):
        if ( not self.containerId ):
            self.logger.error("Trying to extract list of running processes on non-running container! self.containerId: %s", self.containerId)
            return None
        processList = []
        self.logger.info("Running process snapshot")
        cmd = "sudo docker {} exec -it {} ps axo user:20,pid,pcpu,pmem,vsz,rss,tty,stat,start,time,comm:50"
        cmd = cmd.format(self.remote, self.containerId)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running process snapshot on docker: %s", err)
            return None
        outLines = out.splitlines()
        userIndex = 0
        pidIndex = 1
        for line in outLines[1:]:
            splittedLine = line.split()
            if ( userIndex < len(splittedLine) and pidIndex < len(splittedLine)):
                cmd = "sudo docker {} exec -it {} runuser -l {} -c 'ls -l /proc/{}/exe'"
                cmd = cmd.format(self.remote, self.containerId, splittedLine[userIndex].strip(), splittedLine[pidIndex].strip())
                self.logger.debug("Running command: %s", cmd)
                returncode, out, err = util.runCommand(cmd)
                if ( returncode != 0 ):
                    self.logger.error("Error running cmd: %s on docker: %s", cmd, err)
                else:
                    splittedOut = out.split()
                    processList.append(splittedOut[-1])
            else:
                self.logger.warning("ps output header has PID at index: %d, but current line: %s doesn't have that index!", pidIndex, line)

        serviceProcessList = self.extractRunningServices(tempOutputFolder)
        if ( serviceProcessList ):
            processList.extend(serviceProcessList)

        return processList

    def extractCronJobs(self, tempOutputFolder):
        if ( not self.containerId ):
            self.logger.error("Trying to extract list of cron jobs from non-running container! self.containerId: %s", self.containerId)
            return None
        processList = []
        
        cmd = "sudo docker {} exec -it {} echo $PATH"
        cmd = cmd.format(self.remote, self.containerId)
        returncode, envPaths, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running echo PATH command on docker: %s", err)
            return None
        
        cronFolderPath = "/etc/cron*"
        cmd = util.getCmdRetrieveAllShellScripts(cronFolderPath)
        cmd = "sudo docker {} exec -it {} " + cmd
        cmd = cmd.format(self.remote, self.containerId)
        self.logger.debug("Running command: %s", cmd)
        returncode, out, err = util.runCommand(cmd)
        splittedOut = out.splitlines()
        for scriptFilePath in splittedOut:
            scriptFilePath = scriptFilePath[:scriptFilePath.index(":")]
            self.logger.debug("Found script file: %s", scriptFilePath)
            self.copyFromContainer(scriptFilePath, tempOutputFolder)
            scriptFilePath = tempOutputFolder + "/" + util.getNameWithExtFromPath(scriptFilePath)
            processList.extend(self.extractProcessListFromShellScript(envPaths, scriptFilePath, tempOutputFolder))
        return processList


    def extractRunningServices(self, tempOutputFolder):
        if ( not self.containerId ):
            self.logger.error("Trying to extract list of running services on non-running container! self.containerId: %s", self.containerId)
            return None
        processList = []

        cmd = "sudo docker {} exec -it {} echo $PATH"
        cmd = cmd.format(self.remote, self.containerId)
        returncode, envPaths, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running echo PATH command on docker: %s", err)
            return None

        self.logger.info("Running service snapshot")
        cmd = "sudo docker {} exec -it {} ps auxww"
        cmd = cmd.format(self.remote, self.containerId)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running service snapshot on docker: %s", err)
            return None

        outLines = out.splitlines()
        cmdIndex = 10

        for line in outLines[1:]:
            splittedLine = line.split()
            if ( cmdIndex < len(splittedLine) ):
                if ( splittedLine[cmdIndex].strip().startswith("runsvdir") ):
                    #TODO Handle runsvdir
                    cmdComplete = splittedLine[cmdIndex:]
                    cmdComplete = ' '.join(cmdComplete)
                    serviceFolderPath = util.extractCommandArgument(cmdComplete, "-P")
                    self.logger.debug("Handling runsvdir process special case, serviceFolder: %s", serviceFolderPath)
                    if ( serviceFolderPath ):
                        cmd = util.getCmdRetrieveAllShellScripts(serviceFolderPath)
                        cmd = "sudo docker {} exec -it {} " + cmd
                        cmd = cmd.format(self.remote, self.containerId)
                        self.logger.debug("Running command: %s", cmd)
                        returncode, out, err = util.runCommand(cmd)
                        splittedOut = out.splitlines()
                        for scriptFilePath in splittedOut:
                            scriptFilePath = scriptFilePath[:scriptFilePath.index(":")]
                            self.logger.debug("Found script file: %s", scriptFilePath)
                            self.copyFromContainer(scriptFilePath, tempOutputFolder)
                            scriptFilePath = tempOutputFolder + "/" + util.getNameWithExtFromPath(scriptFilePath)
                            processList.extend(self.extractProcessListFromShellScript(envPaths, scriptFilePath, tempOutputFolder))

                elif ( splittedLine[cmdIndex].strip().startswith("runsv") ):
                    #TODO Handle runsv
                    continue
            else:
                self.logger.warning("ps output header has Command at index: %d, but current line: %s doesn't have that index!", cmdIndex, line)
        return processList


    def extractEntryPointDependencies(self, outFolderPath):
        if ( not self.containerId ):
            self.logger.error("Trying to extract contents of entrypoint script on non-running container! self.containerId: %s", self.containerId)
            return None
        processList = []
        self.logger.info("Extracting entrypoint dependencies.")
        cmd = "sudo docker {} inspect {}"
        cmd = cmd.format(self.remote, self.imageName)
        returncode, out, err = util.runCommand(cmd)
        if ( returncode != 0 ):
            self.logger.error("Error running entrypoint extraction on docker: %s", err)
            return None
        out = out.strip()
        out = out[1:-1]
        entrypointJson = json.loads(out)
        entrypointVal = None
        cmdVal = None
        envVal = None
        if ( entrypointJson.get("ContainerConfig", None) ):
            if ( entrypointJson["ContainerConfig"].get("Entrypoint", None) ):
                entrypointVal = entrypointJson["ContainerConfig"]["Entrypoint"]
                entrypointVal = entrypointVal[0].strip()
            if ( entrypointJson["ContainerConfig"].get("Env", None) ):
                for envItem in entrypointJson["ContainerConfig"]["Env"]:
                    self.logger.debug("envItem: %s", envItem)
                    splittedEnvItem = envItem.split("=")
                    if ( splittedEnvItem[0] == "PATH" ):
                        envVal = splittedEnvItem[1]   
        if ( not entrypointVal and entrypointJson.get("Config", None) ):
            if ( entrypointJson["Config"].get("Entrypoint", None) ):
                entrypointVal = entrypointJson["Config"]["Entrypoint"]
                entrypointVal = entrypointVal[0].strip()
            if ( entrypointJson["Config"].get("Cmd", None) ):
                cmdVal = entrypointJson["Config"]["Cmd"]
                cmdVal = cmdVal[0].strip()
        if ( not envVal and entrypointJson.get("Config", None) ):
            if ( entrypointJson["Config"].get("Env", None) ):
                for envItem in entrypointJson["Config"]["Env"]:
                    self.logger.debug("envItem: %s", envItem)
                    splittedEnvItem = envItem.split("=")
                    if ( splittedEnvItem[0] == "PATH" ):
                        envVal = splittedEnvItem[1]   
        if ( entrypointVal ):
            entrypointFile = ""
            if ( entrypointVal.startswith("[") ):
                entrypointVal = entrypointVal[1:]
            if ( entrypointVal.endswith("]") ):
                entrypointVal = entrypointVal[:-1]
            if ( "\"" in entrypointVal ):
                entrypointVal = entrypointVal.replace("\"", "")
            if ( self.copyFromContainer(entrypointVal, outFolderPath) ):
                entrypointFile = outFolderPath + "/" + util.getNameWithExtFromPath(entrypointVal)
                self.logger.debug("Setting entrypointFile: %s / %s", outFolderPath, util.getNameWithExtFromPath(entrypointVal))
                self.logger.debug("Setting entrypointFile: %s", entrypointFile)
            elif ( envVal ):
                splittedEnvPaths = envVal.split(":")
                for envPath in splittedEnvPaths:
                    if ( self.copyFromContainer(envPath + "/" + entrypointVal, outFolderPath) ):
                        entrypointFile = outFolderPath + "/" + util.getNameWithExtFromPath(envPath + "/" + entrypointVal)
                        self.logger.debug("Setting entrypointFile: %s / %s", outFolderPath, util.getNameWithExtFromPath(envPath + "/" + entrypointVal))
                        self.logger.debug("Setting entrypointFile: %s", entrypointFile)
                        break
            else:
                self.logger.error("Can't copy entrypoint file...")
            if ( entrypointFile != "" ):
                processList = self.extractProcessListFromShellScript(envVal, entrypointFile, outFolderPath)
        return processList


    def extractProcessListFromShellScript(self, envPaths, scriptFilePath, outFolderPath):
        processList = []
        bashExceptList = ["-", "=", "if", "else", "fi", "then"]
        bashFile = open(scriptFilePath, 'r')
        line = bashFile.readline()
        while ( line ):
            line = bashFile.readline()
            splittedLine = line.split()
            for item in splittedLine:
                item = item.strip()
                if ( not item.startswith("#") and not item.startswith("-") and not item.startswith("\"") and not item.startswith("$") and not item.startswith("'") and item not in bashExceptList):
                    splittedEnvPaths = envPaths.split(":")
                    '''findResultStr = self.find("/", item)
                    if ( findResultStr != "" ):
                        findResults = findResultStr.splitlines()
                        for findResult in findResults:
                            if ( findResult[:findResult.rindex("/")] in splittedEnvPaths ):
                                processList.append(findResult)'''
                    for envPath in splittedEnvPaths:
                        if ( self.copyFromContainer(envPath + "/" + item, outFolderPath) ):
                            processList.append(envPath + "/" + item)
                            break
        return processList
