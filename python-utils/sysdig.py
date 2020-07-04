import os, sys, subprocess, signal
import util

class Sysdig():
    """
    This class can be used to start a sysdig process and extract information from the output when required
    """
    def __init__(self, logger):
        self.logger = logger
        self.proc = None
        self.tmpFile = "/tmp/forkstat.out.1"

    def runSysdig(self, eventType):
        cmd = "sysdig evt.type={} -w {}"
        cmd = cmd.format(eventType, self.tmpFile)
        self.proc = util.runCommandWithoutWait(cmd)
        if ( not self.proc ):
            self.logger.error("%s failed: %s", cmd, err)
            return False
        return True

    def runSysdigWithDuration(self, eventType, duration):
        cmd = "sysdig evt.type={} -M {} -w {}"
        cmd = cmd.format(eventType, duration, self.tmpFile)
        self.proc = util.runCommandWithoutWait(cmd)
        if ( not self.proc ):
            self.logger.error("%s failed: %s", cmd, err)
            return False
        return True

    def runSysdigWithDurationWithContainer(self, eventType, duration, containerName):
        cmd = "sysdig evt.type={} and container.name={} -M {} -w {}"
        cmd = cmd.format(eventType, containerName, duration, self.tmpFile)
        self.proc = util.runCommandWithoutWait(cmd)
        if ( not self.proc ):
            self.logger.error("%s failed: %s", cmd, err)
            return False
        return True

    def stopSysdig(self):
        self.logger.debug("stopSysdig called!")
        if ( self.proc ):
            self.logger.debug("stopSysdig entered proc if...")
            try:
                if ( util.pkillProcess(self.proc.pid, "sysdig") ):
                    self.proc = None
                else:
                    self.proc = None
                    return False
            except OSError:
                self.proc = None
                return False
        else:
            self.logger.warning("Trying to stop non-existent sysdig process!")
            return False
        return True
    '''
525529 01:02:07.944909488 3 sshd (8366) > execve filename=/usr/sbin/sshd 
525530 01:02:07.945347374 3 sshd (8366) < execve res=0 exe=/usr/sbin/sshd args=-D.-R. tid=8366(sshd) pid=8366(sshd) ptid=1472(sshd) cwd= fdlimit=1024 pgft_maj=0 pgft_min=42 vm_size=1128 vm_rss=4 vm_swap=0 comm=sshd cgroups=cpuset=/.cpu=/system.slice/ssh.service.cpuacct=/system.slice/ssh.service.io=/... env=LANG=en_US.UTF-8.PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin... tty=0 
532865 01:02:11.450742037 2 sshd (8368) > execve filename=/usr/sbin/sshd 
532866 01:02:11.451150437 2 sshd (8368) < execve res=0 exe=/usr/sbin/sshd args=-D.-R. tid=8368(sshd) pid=8368(sshd) ptid=1472(sshd) cwd= fdlimit=1024 pgft_maj=0 pgft_min=42 vm_size=1128 vm_rss=4 vm_swap=0 comm=sshd cgroups=cpuset=/.cpu=/system.slice/ssh.service.cpuacct=/system.slice/ssh.service.io=/... env=LANG=en_US.UTF-8.PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin... tty=0 

    '''
    def extractPsNames(self):
        psNames = set()
        try:
            cmd = "sysdig -r {}"
            cmd = cmd.format(self.tmpFile)
            returncode, out, err = util.runCommand(cmd)
            if ( returncode != 0 ):
                self.logger.error("Couldn't open file: %s with err: %s trying again.", self.tmpFile, err)
                returncode, out, err = util.runCommand(cmd)
                if ( returncode != 0 ):
                    self.logger.error("Couldn't open file: %s with err: %s trying again.", self.tmpFile, err)
                    returncode, out, err = util.runCommand(cmd)
                    if ( returncode != 0 ):
                        self.logger.error("Couldn't open file: %s after 3 attempts with error: %s", self.tmpFile, err)
                        #sys.exit(-1)
                        return None
            self.logger.debug("sysdig output: %s", out)
            splittedOut = out.splitlines()
            for line in splittedOut:
                splittedLine = line.split()
                if ( len(splittedLine) >= 9 and splittedLine[8].startswith("exe=")):
                    psName = splittedLine[8].strip()[4:]
                    psName = psName.replace("[", "")
                    if ( not psName.strip().startswith("/proc/")):
                        psNames.add(psName)
                elif ( len(splittedLine) == 8 and splittedLine[7].startswith("filename=")):
                    psName = splittedLine[7].strip()[9:]
                    psName = psName.replace("[", "")
                    if ( not psName.strip().startswith("/proc/") ):
                        psNames.add(psName)
        except IOError as e:
            self.logger.error("Couldn't open file: %s", self.tmpFile)
            return None
        return psNames
