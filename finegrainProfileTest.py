import os, sys, subprocess, signal
import logging
import optparse
import containerProfiler
import time
import json

sys.path.insert(0, './python-utils/')

import constants as C
import util

def isValidOpts(opts):
    """
    Check if the required options are sane to be accepted
        - Check if the provided files exist
        - Check if two sections (additional data) exist
        - Read all target libraries to be debloated from the provided list
    :param opts:
    :return:
    """
    if not options.input or not options.outputfolder or not options.reportfolder or not options.defaultprofile or not options.libccfginput or not options.muslcfginput or not options.gofolderpath or not options.cfgfolderpath:
        parser.error("All options -c, -i, -p, -r, -l, -f, -m, -n, -g, -c and -o should be provided.")
        return False

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
    usage = "Usage: %prog -c <CFG input from libc> -i <Input containing list of docker images to run and debloat> -o <A temporary output folder to store intermediate results in>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-l", "--libccfginput", dest="libccfginput", default=None, nargs=1,
                      help="libc call function graph input")

    parser.add_option("-f", "--libcfuncpath", dest="libcfuncpath", default=None, nargs=1,
                      help="libc exported function list")

    parser.add_option("-m", "--muslcfginput", dest="muslcfginput", default=None, nargs=1,
                      help="musl call function graph input")

    parser.add_option("-n", "--muslfuncpath", dest="muslfuncpath", default=None, nargs=1,
                      help="musl exported function list")

    parser.add_option("-i", "--input", dest="input", default=None, nargs=1,
                      help="Input file containing list of image names to be debloated.")

    parser.add_option("-o", "--outputfolder", dest="outputfolder", default=None, nargs=1,
                      help="Output folder path")

    parser.add_option("-r", "--reportfolder", dest="reportfolder", default=None, nargs=1,
                      help="Report file path")

    parser.add_option("-p", "--defaultprofile", dest="defaultprofile", default=None, nargs=1,
                      help="Report file path")

    parser.add_option("-s", "--strictmode", dest="strictmode", default=False,
                      help="Enable strict mode")

    parser.add_option("-g", "--gofolder", dest="gofolderpath", default=None, nargs=1,
                      help="Golang system call folder path")

    parser.add_option("-c", "--cfgfolder", dest="cfgfolderpath", default=None, nargs=1,
                      help="Path to other cfg files")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("finegrainedcontainerprofiler.log")

        #Read list of libc and musl functions
        glibcFuncList = util.extractAllFunctions(options.libcfuncpath, rootLogger)
        if ( not glibcFuncList ):
            rootLogger.error("Problem extracting list of functions from glibc")
            sys.exit(-1)
        muslFuncList = util.extractAllFunctions(options.muslfuncpath, rootLogger)
        if ( not muslFuncList ):
            rootLogger.error("Problem extracting list of functions from musl")
            sys.exit(-1)

        inputFile = open(options.input, 'r')
        inputLine = inputFile.readline()

        retry = False
        skipList = []
        while ( inputLine ):
            inputLine = inputLine.strip()
            imageName = inputLine
            imageOptions = ""
            if ( ";" in inputLine ):
                splittedInput = inputLine.split(";")
                imageRank = splittedInput[0]
                imageName = splittedInput[1]
                imageNameFullPath = splittedInput[2]
                if ( imageNameFullPath == "" ):
                    imageNameFullPath = imageName
                #imageName = imageNameFullPath
                #if ( "/" in imageName ):
                #    imageName = imageName.replace("/", "-")
                #if ( ":" in imageName ):
                #    imageName = imageName[:imageName.find(":")]
                imageCategory = splittedInput[3].strip()
                imageCategory = imageCategory.replace("'", "")
                imageCategory = imageCategory[1:-1]
                if ( imageCategory != "" ):
                    imageCategoryList = imageCategory.split(",")
                else:
                    imageCategoryList = ["Other"]
                if ( len(splittedInput) > 6 ):
                    for splitPart in splittedInput[6:]:
                        imageOptions += splitPart + ";"
                    imageOptions = imageOptions[:-1]

            if ( not imageRank.startswith("#") and imageName not in skipList ):
                start = time.time()
                newProfile = containerProfiler.ContainerProfiler(imageName, imageNameFullPath, imageOptions, options.libccfginput, options.muslcfginput, glibcFuncList, muslFuncList, options.strictmode, options.gofolderpath, options.cfgfolderpath, rootLogger)
#                returncode = newProfile.createSeccompProfile(options.outputfolder + "/" + imageName + "/", options.reportfolder)
                returncode = newProfile.createFineGrainedSeccompProfile(options.outputfolder + "/" + imageName + "/", options.reportfolder)
                end = time.time()
                if ( returncode == C.SYSDIGERR and not retry ):
                    retry = True
                else:
                    retry = False
            else:
                rootLogger.info("Skipping %s", imageName)
            if ( not retry ):
                inputLine = inputFile.readline()
        inputFile.close()
