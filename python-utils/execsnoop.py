import os, sys, time, subprocess
import tempfile
import logging
from monitoringTool import MonitoringTool

class Execsnoop(MonitoringTool):
    """
    This class can be used to start an execsnoop process and extract information from the output when required
    """
    def __init__(self, logger, psListPath=None):
        MonitoringTool.__init__(self, logger)
        fd, self.tmpFile = tempfile.mkstemp(prefix="confine-execsnoop_")
        os.close(fd)
        self.logger.debug("Created execsnoop trace file: " + self.tmpFile)

    def waitForExecsnoopToStart(self):
        start = time.monotonic_ns()
        
        # TODO: Add a timeout & throw an exception
        while (not os.path.exists(self.tmpFile) or os.stat(self.tmpFile).st_size == 0):
            subprocess.Popen(["/bin/true"]) # Cause an event!
            time.sleep(0.1)

        time.sleep(1) # wait another second for good measure? (this is so hack)
        self.logger.debug("Waited: " + str((time.monotonic_ns() - start) / 1000000) + "ms for execsnoop to start.")

    def waitUntilComplete(self):
        self.stopMonitoringTool()
        return
        #if not self.proc:
        #    return
        #
        ## TODO: Add a timeout & throw an exception
        #while (self.proc.poll() == None):
        #    justRunTrue = subprocess.Popen(["/bin/true"])
        #    justRunTrue.wait()
        #    self.proc.wait(timeout=1)

    def runWithDuration(self, duration):
        cmd = ["sudo", "execsnoop-bpfcc"]
        self.logger.debug("Running command:" + str(cmd))
        outputFile = open(self.tmpFile, 'w')
        self.proc = subprocess.Popen(cmd, stdout=outputFile)
        if ( not self.proc ):
            self.logger.error("%s failed", cmd)
            return False
        self.waitForExecsnoopToStart()
        return True

    '''
    clear_console    816681 816672   0 /usr/bin/clear_console -q
    '''
    def extractPsNames(self, eventType, containerName, cgroupId=""):
        self.logger.debug("extractPsNames called!")
        if self.proc != None:
            self.stopMonitoringTool()

        psNames = set()
        outputFile = open(self.tmpFile, 'r')
        outputLine = outputFile.readline()
        while ( outputLine ):
            tokens = outputLine.strip().split()
            if ( len(tokens) > 4 ):
                psName = tokens[4].strip()
                if ( not psName.strip().startswith("/proc/") ):
                    psNames.add(psName)
            else:
                self.logger.warning("execsnoop output line has fewer tokens than expected: %s", outputLine.strip())
            outputLine = outputFile.readline()
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

    myExecsnoop = Execsnoop(rootLogger)
    myExecsnoop.runWithDuration(60)
    # sysdig runs asynchronously, so we need to wait around too...
    time.sleep(61)
