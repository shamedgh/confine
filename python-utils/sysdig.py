import os, sys, time, subprocess
import tempfile
import logging

class Sysdig():
    """
    This class can be used to start a sysdig process and extract information from the output when required
    """
    def __init__(self, logger):
        self.logger = logger
        self.proc = None
        fd, self.tmpFile = tempfile.mkstemp(prefix="confine-sysdig_")
        os.close(fd)
        self.logger.debug("Created sysdig trace file: " + self.tmpFile)

    def __del__(self):
        if self.proc != None:
            self.stopSysdig()

        # in debug mode don't remove the file
        if not self.logger.isEnabledFor(logging.DEBUG):
            os.remove(self.tmpFile)
        else:
            self.logger.debug("Sysdig output file not removed when in debug mode: " + self.tmpFile)

    def waitForSysdigToStart(self):
        start = time.monotonic_ns()
        
        # TODO: Add a timeout & throw an exception
        while (not os.path.exists(self.tmpFile) or os.stat(self.tmpFile).st_size == 0):
            subprocess.Popen(["/bin/true"]) # Cause an event!
            time.sleep(0.1)

        time.sleep(1) # wait another second for good measure? (this is so hack)
        self.logger.debug("Waited: " + str((time.monotonic_ns() - start) / 1000000) + "ms for sysdig to start.")

    def waitUntilComplete(self):
        if not self.proc:
            return
        
        # TODO: Add a timeout & throw an exception
        while (self.proc.poll() == None):
            justRunTrue = subprocess.Popen(["/bin/true"])
            justRunTrue.wait()
            self.proc.wait(timeout=1)

    def runSysdigWithDuration(self, duration):
        cmd = ["sysdig", "-pc", "-M", str(duration),
               "-w", self.tmpFile]
        self.logger.debug("Running command:" + str(cmd))
        self.proc = subprocess.Popen(cmd)
        if ( not self.proc ):
            self.logger.error("%s failed", cmd)
            return False
        self.waitForSysdigToStart()
        return True

    def stopSysdig(self):
        if ( self.proc ):
            if ( self.proc.poll() == None ):
                self.logger.debug("Terminating Sysdig process: " + str(self.proc.pid))
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=10)
                    self.proc = None
                    return True
                except subprocess.SubprocessError:
                    self.logger.warning("exception while termianting sysdig subprocess!")
                    self.proc = None
                    return False
            else:
                self.logger.debug("Sysdig already quit with exit code: " + str(self.proc.poll()) )
                self.proc = None
                return True;
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
    def extractPsNames(self, eventType, containerName):
        self.logger.debug("extractPsNames called!")
        if self.proc != None:
            self.stopSysdig()

        psNames = set()
        try:
            cmd = ["sudo", "sysdig", "-r", self.tmpFile, "evt.type=" + eventType, "and", "container.name=" + containerName]
            result = None
            for loopCounter in range(3):
                result = subprocess.run(cmd, capture_output=True)
                if result.returncode == 0:
                    break
                self.logger.error("Couldn't open file: %s with err: %s", self.tmpFile, result.stderr)
            if result.returncode != 0:
                self.logger.error("Failed to open file %s", self.tmpFile)
                return None

            outStr = str(result.stdout.decode("utf-8"))
            self.logger.debug("sysdig output: %s", outStr)
            splittedOut = outStr.splitlines()
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



import logging
import sys
import time
if __name__ == '__main__':
    rootLogger = logging.getLogger("test")
    rootLogger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('SYSDIG_STANDALONE %(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    rootLogger.addHandler(handler)

    mySysdig = Sysdig(rootLogger)
    mySysdig.runSysdigWithDuration(60)
    # sysdig runs asynchronously, so we need to wait around too...
    time.sleep(61)


