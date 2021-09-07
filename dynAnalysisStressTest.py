import os, sys, subprocess, signal
import re

sys.path.insert(0, './python-utils/')

import optparse
import container
import util
import bisect
import time
from datetime import datetime
import sysdig
import constants as C
import processMonitorFactory


class DynamicAnalysisTester():
    """
    This class can be used to stress test the monitoring tool used in our dynamic analysis phase
    """
    def __init__(self, name, imagePath, options, 
                 monitoringTool, logger, isDependent=False):
        self.logger = logger
        self.name = name
        self.imagePath = imagePath
        self.options = options
        self.status = False
        self.runnable = False
        self.installStatus = False
        self.debloatStatus = False
        self.errorMessage = ""
        self.isDependent = isDependent
        self.containerName = None
        self.monitoringTool = monitoringTool

    def getStatus(self):
        return self.status

    def getRunnableStatus(self):
        return self.runnable

    def getInstallStatus(self):
        return self.installStatus

    def getDebloatStatus(self):
        return self.debloatStatus

    def getErrorMessage(self):
        return self.errorMessage

    def getContainerName(self):
        return self.containerName

    def run(self, totalCount):
        psListSizes = list()
        if os.geteuid() != 0:
            self.logger.error("This script must be run as ROOT only!")
            exit("This script must be run as ROOT only. Exiting.")

        myContainer = container.Container(self.imagePath, self.options, self.logger)
        self.containerName = myContainer.getContainerName()

        if ( not myContainer.pruneVolumes() ):
            self.logger.warning("Pruning volumes failed, storage may run out of space\n")

        ttr = 10
        logSleepTime = 60
        runCount = 1
        sysdigErrCount = 0

        if ( self.name == "softwareag-apigateway" ):
            logSleepTime = 60

        if ( self.name == "cirros" ):
            logSleepTime = 120
        

        psListAll = set()

        self.logger.info("--->Starting MONITOR phase:")
        while ( runCount <= totalCount ):
            myMonitor = processMonitorFactory.Factory(self.logger, self.monitoringTool)
            self.logger.debug("Trying to kill and delete container which might not be running in loop... Not a problem if returns error")
            str(myContainer.kill())
            str(myContainer.delete())
            self.logger.info("Running monitoring tool multiple times. Run count: %d from total: %d", runCount, totalCount)
            #sysdigResult = mySysdig.runSysdigWithDuration(logSleepTime)
            monitorResult = myMonitor.runWithDuration(logSleepTime)
            if ( not monitorResult ):
                self.logger.error("Running sysdig with execve failed, not continuing for container: %s", self.name)
                self.logger.error("Please make sure sysdig is installed and you are running the script with root privileges. If problem consists please contact our support team.")
                self.errorMessage = "Running sysdig with execve failed"
            
            if ( monitorResult and myContainer.runWithoutSeccomp() ):#myContainer.run() ):
                self.status = True
                self.logger.info("Ran container sleeping for %d seconds to generate logs and extract execve system calls", logSleepTime)
                time.sleep(logSleepTime)
                myMonitor.waitUntilComplete()
                originalLogs = myContainer.checkLogs()
                self.logger.debug("originalLog: %s", originalLogs)
                time.sleep(10)
                if ( not myContainer.checkStatus() ):
                    self.logger.warning("Container exited after running, trying to run in attached mode!")
                    self.logger.debug(str(myContainer.delete()))
                    if ( not myContainer.runInAttachedMode() ):
                        self.errorMessage = "Container didn't run in attached mode either, forfeiting!"
                        self.logger.error("Container didn't run in attached mode either, forfeiting!")
                        self.logger.error("There is a problem launching a container for %s. Please validate you can run the container without Confine. If so, contact our support team.", self.name)
                        self.logger.debug(str(myContainer.delete()))
                        return C.NOATTACH
                    else:
                        time.sleep(10)
                        if ( not myContainer.checkStatus() ):
                            self.errorMessage = "Container got killed after running in attached mode as well!"
                            self.logger.error("Container got killed after running in attached mode as well, forfeiting!")
                            self.logger.error("There is a problem launching a container for %s. Please validate you can run the container without Confine. If so, contact our support team.", self.name)
                            self.logger.debug(str(myContainer.kill()))
                            self.logger.debug(str(myContainer.delete()))
                            return C.CONSTOP
            psList = myMonitor.extractPsNames("execve", myContainer.getContainerName())
            if ( not psList or len(psList) == 0 ):
                self.logger.error("PS List is None or empyt from extractPsNames(). Retrying this container: %s", self.name)
                self.logger.debug(str(myContainer.kill()))
                self.logger.debug(str(myContainer.delete()))
                self.errorMessage = "PS List is None or empty from extractPsNames(), error in sysdig, retrying this container"
                sysdigErrCount += 1
            if ( psList ):
                psListSizes.append(len(psList))
            else:
                psListSizes.append(0)
            runCount += 1

        return psListSizes


import logging
if __name__ == '__main__':

    usage = "Usage: --imagename nginx --monitoringtool [sysdig/execsnoop] --count 1000"


    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("", "--imagename", dest="imagename", default=None, nargs=1,
                      help="Image name to use for stress test")

    parser.add_option("", "--monitoringtool", dest="monitoringtool", default="sysdig", nargs=1,
                      help="Monitoring tool to be used for dynamic analysis")

    parser.add_option("-n", "--count", dest="count", default=1000, nargs=1,
                      help="Number of times to run stress test")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()


    rootLogger = logging.getLogger("test")
    rootLogger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    rootLogger.addHandler(handler)

    killAllContainers = container.killToolContainers(rootLogger)
    deleteAllContainers = container.deleteStoppedContainers(rootLogger)

    dynTester = DynamicAnalysisTester(options.imagename, options.imagename,
                                     None, options.monitoringtool, rootLogger)
    psListSizes = dynTester.run(int(options.count))

    rootLogger.info("psListSizes: %s", str(psListSizes))
