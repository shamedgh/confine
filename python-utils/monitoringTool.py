import os, sys, time, subprocess
import tempfile
import logging

class MonitoringTool():
    """
    This base class holds the functions which are shared among the different monitoring tool classes
    """
    def __init__(self, logger):
        self.logger = logger
        self.proc = None
        self.tmpFile = None

    def __del__(self):
        if self.proc != None:
            self.stopMonitoringTool()

        # in debug mode don't remove the file
        #if not self.logger.isEnabledFor(logging.DEBUG):
        #    os.remove(self.tmpFile)
        #else:
        #    self.logger.debug("Monitoring tool output file not removed when in debug mode: " + self.tmpFile)

    def waitUntilComplete(self):
        return

    def stopMonitoringTool(self):
        if ( self.proc ):
            if ( self.proc.poll() == None ):
                self.logger.debug("Terminating monitoring process: " + str(self.proc.pid))
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=10)
                    self.proc = None
                    return True
                except subprocess.SubprocessError as err:
                    self.logger.warning("exception while terminating monitoring subprocess! : " + str(err))
                    self.proc.kill()
                    self.proc = None
                    return False
            else:
                self.logger.debug("Monitoring already quit with exit code: " + str(self.proc.poll()) )
                self.proc = None
                return True;
        else:
            self.logger.warning("Trying to stop non-existent monitoring process!")
            return False
        return True

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
    mySysdig.runWithDuration(60)
    # sysdig runs asynchronously, so we need to wait around too...
    time.sleep(61)


