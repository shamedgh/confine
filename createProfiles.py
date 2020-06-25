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
        parser.error("All options -c, -i, -p, -r, -l, -m, -g, -c and -o should be provided.")
        return False

    if (options.strictmode and ( not options.libcfuncpath or not options.muslfuncpath ) ):
        parser.error("Options -f (libc path) and -n (musl path) should be provided in strict mode.")
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

    parser.add_option("", "--finegrain", dest="finegrain", action="store_true", default=False,
                      help="Enable/Disable finegrained library function debloating")

    parser.add_option("", "--allbinaries", dest="allbinaries", action="store_true", default=False,
                      help="Enable/Disable extracting all binaries from the container")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("containerprofiler.log")

        rootLogger.info("////////////////////////////////////////////////////")
        rootLogger.info("finegrain set!: %s", options.finegrain)
        rootLogger.info("////////////////////////////////////////////////////")

        #Read list of libc and musl functions
        glibcFuncList = None
        muslFuncList = None
        if ( options.strictmode ):
            glibcFuncList = util.extractAllFunctions(options.libcfuncpath, rootLogger)
            if ( not glibcFuncList ):
                rootLogger.error("Problem extracting list of functions from glibc")
                sys.exit(-1)
            muslFuncList = util.extractAllFunctions(options.muslfuncpath, rootLogger)
            if ( not muslFuncList ):
                rootLogger.error("Problem extracting list of functions from musl")
                sys.exit(-1)

        #Load list of default black listed system calls
        defaultProfileFile = open(options.defaultprofile, 'r')
        defaultProfileStr = defaultProfileFile.read()
        defaultProfileJson = json.loads(defaultProfileStr)
        defaultSyscallSet = set(defaultProfileJson["default"])

        #Check for previous report file and skip profiling previous containers
        skipList = []
        reportFilePath = options.reportfolder + "/profile.report"
        try:
            reportFile = open(reportFilePath + ".csv", 'r')
            reportLine = reportFile.readline()
            while reportLine:
                skipList.append(reportLine.split(";")[1])
                reportLine = reportFile.readline()
            reportFile.close()
        except IOError as e:
            rootLogger.info("Report file doesn't exist, no previous reports exist")


        reportFile = open(reportFilePath + ".csv", 'a+')
        reportFileSummary = open(options.reportfolder + "/container.stats.csv", 'w+')
        reportFileDetailed = open(reportFilePath + ".details.csv", 'a+')
        reportFileCategorized = open(options.reportfolder + "/syscall.categorized.csv", 'w+')
        reportFileLanguageBased = open(options.reportfolder + "/container.language.stats.csv", 'w+')

        try:
            inputFile = open(options.input, 'r')
            imageToPropertyStr = inputFile.read()
            imageToPropertyMap = json.loads(imageToPropertyStr)
        except Exception as e:
            rootLogger.warning("Trying to load image list map json from: %s, but doesn't exist: %s", options.input, str(e))
            rootLogger.debug("Finished loading json")
            sys.exit(-1)

        #inputLine = inputFile.readline()

        statsTotalImage = 0
        statsLaunchableImage = 0
        statsStaysRunningImage = 0
        statsDebloatableImage = 0

        langCount = dict()

        retry = False

        #while ( inputLine ):
        #    inputLine = inputLine.strip()
        #    imageName = inputLine
        #    imageOptions = ""
        #    if ( ";" in inputLine ):
        #        splittedInput = inputLine.split(";")
        #        imageRank = splittedInput[0]
        #        imageName = splittedInput[1]
        #        imageNameFullPath = splittedInput[2]
        #        if ( imageNameFullPath == "" ):
        #            imageNameFullPath = imageName
        #        #imageName = imageNameFullPath
        #        #if ( "/" in imageName ):
        #        #    imageName = imageName.replace("/", "-")
        #        #if ( ":" in imageName ):
        #        #    imageName = imageName[:imageName.find(":")]
        #        imageCategory = splittedInput[3].strip()
        #        imageCategory = imageCategory.replace("'", "")
        #        imageCategory = imageCategory[1:-1]
        #        if ( imageCategory != "" ):
        #            imageCategoryList = imageCategory.split(",")
        #        else:
        #            imageCategoryList = ["Other"]
        #        if ( len(splittedInput) > 6 ):
        #            for splitPart in splittedInput[6:]:
        #                imageOptions += splitPart + ";"
        #            imageOptions = imageOptions[:-1]

        for imageKey, imageVals in imageToPropertyMap.items():
            #retry = True
            retryCount = 0
            imageName = imageVals.get("image-name", imageKey)
            if ( imageVals.get("enable", "false") == "true" and imageName not in skipList ):
                imageRank = imageVals.get("id", -1)
                imageNameFullPath = imageVals.get("image-url", None)
                if ( imageNameFullPath == "" ):
                    imageNameFullPath = imageName
                imageCategoryList = imageVals.get("category", ["Other"])
                imageOptions = imageVals.get("options", "")
                imageArgs = imageVals.get("args", "")
                imagePullCount = imageVals.get("pull-count", 0)
                imageOfficial = imageVals.get("official", False)
                while ( retryCount < 2 ):
                    start = time.time()
                    newProfile = containerProfiler.ContainerProfiler(imageName, imageNameFullPath, imageOptions, options.libccfginput, options.muslcfginput, glibcFuncList, muslFuncList, options.strictmode, options.gofolderpath, options.cfgfolderpath, options.finegrain, options.allbinaries, rootLogger)
                    returncode = newProfile.createSeccompProfile(options.outputfolder + "/" + imageName + "/", options.reportfolder)
                    end = time.time()
                    if ( returncode != C.SYSDIGERR ):
                    #    if ( retryCount != 0 ):
                    #        retryCount += 1
                    #else:
                        retryCount += 1
                        if ( newProfile.getBlacklistedSyscalls() ):
                            currentSet = set(newProfile.getBlacklistedSyscalls())
                        else:
                            currentSet = set()

                        if ( newProfile.getBlacklistedSyscallsOriginal() ):
                            originalSet = set(newProfile.getBlacklistedSyscallsOriginal())
                        else:
                            originalSet = set()

                        if ( newProfile.getBlacklistedSyscallsFineGrain() ):
                            finegrainSet = set(newProfile.getBlacklistedSyscallsFineGrain())
                        else:
                            finegrainSet = set()

                        unionSet = currentSet.copy()
                        unionSet.update(defaultSyscallSet)
                        remainingSetSize = len(unionSet.difference(currentSet))-1   #-1 for clone system call
                        reportFile.write(imageRank + ";" + imageName + ";" + str(newProfile.getStatus()) + ";" + str(newProfile.getRunnableStatus()) + ";" + str(newProfile.getInstallStatus()) + ";" + str(len(originalSet)) + ";" + str(len(finegrainSet)) + ";" + str(len(unionSet)-len(defaultSyscallSet)) + ";" + str(len(unionSet)) + ";" + str(newProfile.getDebloatStatus()) + ";" + newProfile.getErrorMessage() + ";" + str(newProfile.getDirectSyscallCount()) + ";" + str(newProfile.getLibcSyscallCount()) + ";" + str(end-start) + ";" + str(newProfile.getLanguageSet()) + ";" + str(remainingSetSize) + "\n")

                        statsTotalImage += 1
                        if ( newProfile.getStatus() ):
                            statsLaunchableImage += 1
                        if ( newProfile.getRunnableStatus() ):
                            statsStaysRunningImage += 1
                        if ( newProfile.getDebloatStatus() ):
                            statsDebloatableImage += 1

                        reportFile.flush()
                        rootLogger.debug("Default syscalls not in extracted ones: %s", str(unionSet.difference(currentSet)))
                        if ( newProfile.getDebloatStatus() ):
                            reportFileDetailed.write(imageRank + ";" + imageName + ";" + str(len(currentSet)) + ";" + str(len(unionSet)-len(defaultSyscallSet)) + ";" + str(len(unionSet)) + ";" + str(newProfile.getDirectSyscallCount()) + ";" + str(newProfile.getLibcSyscallCount()) + ";" + str(currentSet) + "\n")
                            reportFileDetailed.flush()
                            for category in imageCategoryList:
                                reportFileCategorized.write(category + "," + str(len(currentSet)) + "\n")
                                reportFileCategorized.flush()
                        if ( newProfile.getStatus() and newProfile.getRunnableStatus() ):
                            successStatus = 0
                            if ( newProfile.getDebloatStatus() ):
                                successStatus = 1
                            #langCount[lang][success] += 1
                            profileLangSet = newProfile.getLanguageSet()
                            if ( len(profileLangSet) == 0 ):
                                rootLogger.warning("Container with successfull debloat but empty language set!")
                            if ( len(profileLangSet) > 1 ):
                                profileLangSet.discard(util.BinaryLang.CCPP.value)
                            for lang in profileLangSet:
                                print ("lang: " + lang)
                                langDict = langCount.get(lang, dict())
                                count = langDict.get(successStatus, 0)
                                count += 1
                                langDict[successStatus] = count
                                langCount[lang] = langDict
                        rootLogger.info("Finished extracting system calls for %s, sleeping for 5 seconds", imageName)
                        time.sleep(5)
                    retryCount += 1
            else:
                rootLogger.info("Skipping %s", imageName)
            #if ( not retry ):
            #    inputLine = inputFile.readline()
        reportFile.close()
        reportFileDetailed.close()
        reportFileCategorized.close()
        inputFile.close()

        reportFileSummary.write(str(statsTotalImage) + "," + str(statsLaunchableImage) + "," + str(statsStaysRunningImage) + "," + str(statsDebloatableImage) + "\n")
        reportFileSummary.flush()
        reportFileSummary.close()

        for lang in langCount:
            for success in langCount[lang]:
                if ( success == 1 ):
                    reportFileLanguageBased.write(lang + ",True," + str(langCount[lang][success]) + "\n")
                else:
                    reportFileLanguageBased.write(lang + ",False," + str(langCount[lang][success]) + "\n")
                reportFileLanguageBased.flush()
        reportFileLanguageBased.close()
