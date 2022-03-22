import os, sys, subprocess, signal
import logging
import optparse
import containerProfiler
import container
import time
import json
import re

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
    if not options.input or not options.outputfolder or not options.reportfolder or not options.defaultprofile or not options.libccfginput or not options.muslcfginput or not options.gofolderpath:
        parser.error("All options -i, -p, -r, -l, -m, -g, -c and -o should be provided.")
        return False

    if options.finegrain and not options.cfgfolderpath:
        parser.error("Option --othercfgfolder must be specified when options --finegrain is set")

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
    Confine: Main script to generate restrictive Seccomp profiles for Docker images.
    """
    usage = "Usage: %prog -l <glibc call graph path> -m <musl-libc call graph path> -i <input containing list of docker images to run and harden> -o <a temporary output folder to store binaries and libraries identified and extracted from each container> -p <path to the default seccomp profile> -r <path to store results and generated seccomp profiles> -g <in case any applications (such as ones developed in golang> make direct system calls which must be extracted through source code analysis, put list of required system calls in a file named by the docker image [docker-image].syscalls>"

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

    parser.add_option("", "--monitoringtool", dest="monitoringtool", default="sysdig", nargs=1,
                      help="Monitoring tool to be used for dynamic analysis")

    parser.add_option("-p", "--defaultprofile", dest="defaultprofile", default=None, nargs=1,
                      help="Report file path")

    parser.add_option("-s", "--strictmode", dest="strictmode", default=False,
                      help="Enable strict mode")

    parser.add_option("-g", "--gofolder", dest="gofolderpath", default=None, nargs=1,
                      help="Golang system call folder path")

    parser.add_option("", "--othercfgfolder", dest="cfgfolderpath", default=None, nargs=1,
                      help="Path to other cfg files")

    parser.add_option("", "--finegrain", dest="finegrain", action="store_true", default=False,
                      help="Enable/Disable finegrained library function debloating")

    parser.add_option("", "--allbinaries", dest="allbinaries", action="store_true", default=False,
                      help="Enable/Disable extracting all binaries from the container")

    parser.add_option("", "--skip", dest="skippreviousruns", action="store_true", default=False,
                      help="Skip running analysis for containers ran previously")

    parser.add_option("", "--binliblist", dest="binliblist", default=None, nargs=1,
                      help="Path to file containing list of binaries and libraries")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    parser.add_option("-t", "--maptype", dest="maptype", default="awk",
                      help="Syscall number mapping method: awk, auditd, libseccomp")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("containerprofiler.log")

        if ( options.finegrain ):
            rootLogger.info("////////////////////////////////////////////////////")
            rootLogger.info("WARNING: You have enabled finegrain through the --finegrain option which is NOT fully operational yet. Use at your own risk.")
            rootLogger.info("////////////////////////////////////////////////////")

        #Read list of libc and musl functions
        glibcFuncList = None
        muslFuncList = None
        if ( options.strictmode ):
            rootLogger.info("////////////////////////////////////////////////////")
            rootLogger.info("WARNING: You have enabled strictmode through the --strictmode option which is NOT fully operational yet. Use at your own risk.")
            rootLogger.info("////////////////////////////////////////////////////")
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

        #Initialize results and output folder
        accessRights = 0o755
        reportFolder = options.reportfolder
        while ( reportFolder.endswith("/") ):
            reportFolder = reportFolder[:-1]
        if ( not os.path.exists(reportFolder) ):
            try:
                os.mkdir(reportFolder, accessRights)
            except OSError:
                rootLogger.error("There was a problem creating the results (-r) folder")
                sys.exit(-1)
        elif ( os.path.isfile(reportFolder) ):
            rootLogger.error("The folder specified for the results (-r) already exists and is a file. Please change the path or delete the file and re-run the script.")
            sys.exit(-1)

        outputFolder = options.outputfolder
        while ( outputFolder.endswith("/") ):
            outputFolder = outputFolder[:-1]
        if ( not os.path.exists(outputFolder) ):
            try:
                os.mkdir(outputFolder, accessRights)
            except OSError:
                rootLogger.error("There was a problem creating the output (-o) folder")
                sys.exit(-1)
        elif ( os.path.isfile(outputFolder) ):
            rootLogger.error("The folder specified for the output (-o) already exists and is a file. Please change the path or delete the file and re-run the script.")
            sys.exit(-1)

        #Check for previous report file and skip profiling previous containers
        skipList = []
        reportFilePath = options.reportfolder + "/profile.report"
        if ( options.skippreviousruns ):
            try:
                reportFile = open(reportFilePath + ".csv", 'r')
                reportLine = reportFile.readline()
                while reportLine:
                    skipList.append(reportLine.split(";")[1])
                    reportLine = reportFile.readline()
                reportFile.close()
            except IOError as e:
                rootLogger.info("Report file doesn't exist, no previous reports exist, creating...")


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
            rootLogger.error("Trying to load image list map json from: %s, but doesn't exist: %s", options.input, str(e))
            rootLogger.error("Exiting...")
            sys.exit(-1)

        statsTotalImage = 0
        statsLaunchableImage = 0
        statsStaysRunningImage = 0
        statsDebloatableImage = 0

        langCount = dict()

        retry = False
        for imageKey, imageVals in imageToPropertyMap.items():
            #retry = True
            retryCount = 0
            depLinkSet = set()
            imageName = imageVals.get("image-name", imageKey)
            tmpimageName = imageVals.get("image-name", imageKey)
            imageName = re.sub('\W+','-', tmpimageName)
            if ( imageVals.get("enable", "false") == "true" and imageName not in skipList ):
                rootLogger.info("------------------------------------------------------------------------")
                rootLogger.info("////////////////////////////////////////////////////////////////////////")
                rootLogger.info("----->Starting analysis for image: %s<-----", imageName)
                rootLogger.info("////////////////////////////////////////////////////////////////////////\n")
                killAllContainers = container.killToolContainers(rootLogger)
                #rootLogger.info("Killing all containers related to toolset returned: %s", killAllContainers)
                deleteAllContainers = container.deleteStoppedContainers(rootLogger)
                #rootLogger.info("Deleting all containers related to toolset returned: %s", deleteAllContainers)

                imageDependencies = imageVals.get("dependencies", dict())
                for depKey, depVals in imageDependencies.items():
                    tmpdepImageName = depVals.get("image-name", depKey)
                    depImageName = re.sub('\W+','-', tmpdepImageName)
                    depImageNameFullPath = depVals.get("image-url", depImageName)
                    depOptions = depVals.get("options", "")
                    depLink = True if depVals.get("link", False) else False
                    #rootLogger.info("depLink: %s", depLink)

                    retryCount = 0
                    while ( retryCount < 2 ):

                        newProfile = containerProfiler.ContainerProfiler(depImageName, 
                                depImageNameFullPath, depOptions, options.libccfginput, 
                                options.muslcfginput, glibcFuncList, muslFuncList, 
                                options.strictmode, options.gofolderpath, options.cfgfolderpath, 
                                options.finegrain, options.allbinaries, options.binliblist, 
                                options.monitoringtool, rootLogger, options.mapType, "", True)
                        returncode = newProfile.createSeccompProfile(options.outputfolder + "/" + depImageName + "/", options.reportfolder)
                        #if ( returncode != C.SYSDIGERR ):
                        if ( returncode == 0 ):
                            rootLogger.info("Hardened dependent image: %s for main image: %s", depImageName, imageName)
                            retryCount += 1
                        else:
                            rootLogger.error("Tried hardening container: %s returned: %d:%s", depImageName, returncode, C.ERRTOMSG[returncode])
                        retryCount += 1
                        if ( depLink and newProfile.getContainerName()):
                            #rootLogger.info("depLink is TRUE")
                            depLinkSet.add(newProfile.getContainerName())


                imageRank = imageVals.get("id", -1)
                imageNameFullPath = imageVals.get("image-url", None)
                if ( not imageNameFullPath ):
                    imageNameFullPath = imageName
                imageCategoryList = imageVals.get("category", ["Other"])
                imageOptions = imageVals.get("options", "")
                for linkedDep in depLinkSet:
                    imageOptions += " --link " + linkedDep

                imageArgs = imageVals.get("args", "")
                imagePullCount = imageVals.get("pull-count", 0)
                imageOfficial = imageVals.get("official", False)

                retryCount = 0
                while ( retryCount < 2 ):
                    start = time.time()

                    newProfile = containerProfiler.ContainerProfiler(imageName,
                            imageNameFullPath, imageOptions, options.libccfginput, 
                            options.muslcfginput, glibcFuncList, muslFuncList, 
                            options.strictmode, options.gofolderpath, 
                            options.cfgfolderpath, options.finegrain, 
                            options.allbinaries, options.binliblist, 
                            options.monitoringtool, rootLogger, options.maptype, imageArgs)
                    returncode = newProfile.createSeccompProfile(options.outputfolder + "/" + imageName + "/", options.reportfolder)
                    end = time.time()
                    #if ( returncode != C.SYSDIGERR ):
                    if ( returncode == 0 ):
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
                        reportFile.write(str(imageRank) + ";" + imageName + ";" + str(newProfile.getStatus()) + ";" + str(newProfile.getRunnableStatus()) + ";" + str(newProfile.getInstallStatus()) + ";" + str(len(originalSet)) + ";" + str(len(finegrainSet)) + ";" + str(len(unionSet)-len(defaultSyscallSet)) + ";" + str(len(unionSet)) + ";" + str(newProfile.getDebloatStatus()) + ";" + newProfile.getErrorMessage() + ";" + str(newProfile.getDirectSyscallCount()) + ";" + str(newProfile.getLibcSyscallCount()) + ";" + str(end-start) + ";" + str(newProfile.getLanguageSet()) + ";" + str(remainingSetSize) + "\n")

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
                            reportFileDetailed.write(str(imageRank) + ";" + imageName + ";" + str(len(currentSet)) + ";" + str(len(unionSet)-len(defaultSyscallSet)) + ";" + str(len(unionSet)) + ";" + str(newProfile.getDirectSyscallCount()) + ";" + str(newProfile.getLibcSyscallCount()) + ";" + str(currentSet) + "\n")
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
                            #if ( len(profileLangSet) == 0 ):
                            #    rootLogger.warning("Container with successfull debloat but empty language set!")
                            if ( len(profileLangSet) > 1 ):
                                profileLangSet.discard(util.BinaryLang.CCPP.value)
                            for lang in profileLangSet:
                                #print ("lang: " + lang)
                                langDict = langCount.get(lang, dict())
                                count = langDict.get(successStatus, 0)
                                count += 1
                                langDict[successStatus] = count
                                langCount[lang] = langDict
                        rootLogger.info("///////////////////////////////////////////////////////////////////////////////////////")
                        rootLogger.info("----->Finished extracting system calls for %s, sleeping for 5 seconds<-----", imageName)
                        rootLogger.info("///////////////////////////////////////////////////////////////////////////////////////")
                        rootLogger.info("---------------------------------------------------------------------------------------\n")
                        time.sleep(5)
                    else:
                        rootLogger.error("Tried hardening container: %s returned: %d:%s", imageName, returncode, C.ERRTOMSG[returncode])
                    retryCount += 1
            else:
                rootLogger.debug("Skipping %s because is disabled in the JSON file", imageName)
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
