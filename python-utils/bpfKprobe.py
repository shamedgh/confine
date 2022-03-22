import os, sys, time, subprocess
import tempfile
import logging
import threading
from monitoringTool import MonitoringTool
from containerTraceEbpf import ContainerTraceEbpf

class BpfKprobe(MonitoringTool):
    """
    This class can be used to start an ebpf kprobe process and extract information from the output when required
    """
    def __init__(self, logger, psListPath=None):
        MonitoringTool.__init__(self, logger)
        fd, self.tmpFile = tempfile.mkstemp(prefix="confine-bpfkprobe_")
        os.close(fd)
        self.logger.debug("Created bpf kprobe trace file: " + self.tmpFile)

    def waitForBpfKprobeToStart(self):
        start = time.monotonic_ns()
        
        while (not os.path.exists(self.tmpFile) or os.stat(self.tmpFile).st_size == 0):
            subprocess.Popen(["/bin/true"]) # Cause an event!
            time.sleep(0.1)

        time.sleep(1) # wait another second for good measure? (this is so hack)
        self.logger.debug("Waited: " + str((time.monotonic_ns() - start) / 1000000) + "ms for bpfkprobe to start.")

    def waitUntilComplete(self):
        #self.stopMonitoringTool()
        self.stop_thread = True
        self.tracerThread.join()
        return

    def runWithDuration(self, duration):
        tracer = ContainerTraceEbpf(self.tmpFile)
        self.stop_thread = False
        self.tracerThread = threading.Thread(target= tracer.run, args=(lambda: self.stop_thread,))
        self.tracerThread.start()



        #cmd = ["sudo", "python3.7", "-u", "python-utils/containerTraceEbpf.py"]
        #self.logger.debug("Running command:" + str(cmd))
        #outputFile = open(self.tmpFile, 'w')
        #self.proc = subprocess.Popen(cmd, bufsize=64, stdout=outputFile, shell=False, universal_newlines=True, preexec_fn=os.setpgrp)
        #if ( not self.proc ):
        #    self.logger.error("%s failed", cmd)
        #    return False
        #self.waitForBpfKprobeToStart()
        return True
    
    '''
    clear_console    816681 816672   0 /usr/bin/clear_console -q
    '''
    def extractPsNames(self, eventType="", containerName="", cgroupId=""):
        self.logger.debug("bpf extractPsNames called!")
        self.stop_thread = True
        self.tracerThread.join()
        #if self.proc != None:
            #self.stopMonitoringTool()
            #pgid = os.getpgid(self.proc.pid)
            #subprocess.check_output("sudo kill {}".format(pgid))


        psNames = set()
        outputFile = open(self.tmpFile, 'r')
        outputLine = outputFile.readline()
        while ( outputLine ):
            tokens = outputLine.strip().split()
            if ( len(tokens) >= 3 and tokens[0] == "Container"): # exec call
                psName = tokens[2].strip() 
                if ( not psName.strip().startswith("/proc/")):
                    psNames.add(psName)
            elif ( len(tokens) > 3 and tokens[0] == "Open," ):
                psName = tokens[3].strip()[:-1]
                if ( not psName.strip().startswith("/proc/") ):
                    psNames.add(psName)
            try:
                outputLine = outputFile.readline()
            except Exception as e:
                print(str(e))
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

    myBpfKprobe = BpfKprobe(rootLogger)
    myBpfKprobe.runWithDuration(60)
    # sysdig runs asynchronously, so we need to wait around too...
    time.sleep(61)
    names = myBpfKprobe.extractPsNames()
    print(names)

