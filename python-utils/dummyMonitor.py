import os, sys, time, subprocess
import tempfile
import logging
from monitoringTool import MonitoringTool

class DummyMonitor(MonitoringTool):
    """
    This class does not run any monitoring tool, it just returns the files sent through the filePath argument
    We want everything to go through the monitoring tool interface
    """
    def __init__(self, logger, psListPath=None):
        MonitoringTool.__init__(self, logger)
        self.psListPath = psListPath

    def waitUntilComplete(self):
        return

    def runWithDuration(self, duration):
        return True

    def extractPsNames(self, eventType, containerName, cgroupId=""):
        self.logger.debug("extractPsNames called!")
        psNames = set()
        inputFile = open(self.psListPath, 'r')
        inputLine = inputFile.readline()
        while ( inputLine ):
            psNames.insert(inputLine.strip())
            inputLine = inputFile.readline()
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

    myDummyMonitor = DummyMonitor(rootLogger)
    myDummyMonitor.runWithDuration(60)
