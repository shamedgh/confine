import os, sys, subprocess, signal
import logging
import optparse

import container

def isValidOpts(opts):
    """
    Check if the required options are sane to be accepted
        - Check if the provided files exist
        - Check if two sections (additional data) exist
        - Read all target libraries to be debloated from the provided list
    :param opts:
    :return:
    """
#    if not options.perfpath:
#        parser.error("All options -e, -p and -l and should be provided.")
#        return False

    return True


def setLogPath(logPath):
    """
    Set the property of the logger: path, config, and format
    :param logPath:
    :return:
    """
    if os.path.exists(logPath):
        os.remove(logPath)

    rootLogger = logging.getLogger("coverage")
    if options.debug:
        logging.basicConfig(filename=logPath, level=logging.DEBUG)
        rootLogger.setLevel(logging.DEBUG)
    else:
        logging.basicConfig(filename=logPath, level=logging.INFO)
        rootLogger.setLevel(logging.INFO)

#    ch = logging.StreamHandler(sys.stdout)
    consoleHandler = logging.StreamHandler()
    rootLogger.addHandler(consoleHandler)
    return rootLogger
#    rootLogger.addHandler(ch)

if __name__ == '__main__':
    """
    Main function for finding physical memory usage of process
    """
    usage = "Usage: %prog -e <Target executable path> -p <PID of process to retrieve information about>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-c", "--cfginpu", dest="cfginput", default=None, nargs=1,
                      help="CFG input for creating graph from CFG")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("container.log")
        myContainer = container.Container("couchbase", "", rootLogger)
        myContainer.setContainerId("74b061b7a73e66d3e7971e26b56bcd81dea03c438ae3d0f0252c21772a276189")
        #myContainer.extractEntryPointDependencies()
        '''if ( myContainer.run() ):
            if ( myContainer.installPackage("procps") ):
                psList = myContainer.extractListOfRunningProcesses()
                print ("psList: " + str(psList))
            print (str(myContainer.kill()))
            print (str(myContainer.delete()))
        '''            
