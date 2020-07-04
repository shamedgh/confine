import os, sys, subprocess, signal
import util

class ForkStat():
    """
    This class can be used to start a forkstat process and extract information from the output when required
    """
    def __init__(self, logger):
        self.logger = logger
        self.proc = None
        self.tmpFile = "/tmp/forkstat.out.1"

    def runForkStat(self, forkStatType):
        cmd = "forkstat -l -e {} > {}"
        cmd = cmd.format(forkStatType, self.tmpFile)
        self.proc = util.runCommandWithoutWait(cmd)
        if ( not self.proc ):
            self.logger.error("%s failed: %s", cmd, err)
            return False
        return True

    def runForkStatWithDuration(self, forkStatType, duration):
        cmd = "forkstat -l -e {} -D {} > {}"
        cmd = cmd.format(forkStatType, duration, self.tmpFile)
        self.proc = util.runCommandWithoutWait(cmd)
        if ( not self.proc ):
            self.logger.error("%s failed: %s", cmd, err)
            return False
        return True

    def stopForkStat(self):
        if ( self.proc ):
            try:
                if ( util.pkillProcess(self.proc.pid, "forkstat") ):
                    self.proc = None
                else:
                    self.proc = None
                    return False
            except OSError:
                self.proc = None
                return False
        else:
            self.logger.warning("Trying to stop non-existent forkstat process!")
            return False
        return True

    def extractPsNames(self):
        psNames = []
        try:
            with open(self.tmpFile, 'r') as myFile:
                line = myFile.readline()
                while ( line ):
                    splittedLine = line.split()
                    if ( len(splittedLine) >= 4 and splittedLine[1] == "exec" and splittedLine[3] != "Info" ):
                        psName = splittedLine[3].strip()
                        psName = psName.replace("[", "")
                        psNames.append(psName)
                    line = myFile.readline()
            myFile.close()
        except IOError as e:
            self.logger.error("Couldn't open file: %s", self.tmpFile)
            return None
        return psNames
