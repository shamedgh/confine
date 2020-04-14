import os, sys, subprocess, signal
import logging
import optparse
import requests

sys.path.insert(0, './python-utils/')

import util
import json

def isValidOpts(opts):
    """
    Check if the required options are sane to be accepted
        - Check if the provided files exist
        - Check if two sections (additional data) exist
        - Read all target libraries to be debloated from the provided list
    :param opts:
    :return:
    """
    if not options.rawfilepath or not options.mapfilepath:
        parser.error("All options -r and -m should be provided.")
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
    Main function for extracting list of docker images from docker hub
    """
    usage = "Usage: %prog -e <Target executable path> -p <PID of process to retrieve information about>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-r", "--rawfilepath", dest="rawfilepath", default=None, nargs=1,
                      help="Raw images list file")

    parser.add_option("-m", "--mapfilepath", dest="mapfilepath", default=None, nargs=1,
                      help="Mapping images list file")

    parser.add_option("-o", "--outputpath", dest="outputpath", default="images.list", 
                        nargs=1, help="Output file")

    parser.add_option("-n", "--limit", dest="limit", default=200, 
                        nargs=1, help="Image count limit")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("combineimage.log")

    rawFile = open(options.rawfilepath, 'r')
    mapFile = open(options.mapfilepath, 'r')
    outFile = open(options.outputpath, 'w+')

    imageToFullName = dict()
    imageToOptions = dict()

    SEPARATOR = ";"

    mapLine = mapFile.readline()
    while (mapLine):
        image = mapLine.split(";")[0]
        imageName = mapLine.split(";")[1]
        option = mapLine.split(";")[2]
        imageToFullName[image.strip()] = imageName.strip()
        imageToOptions[image.strip()] = option.strip()
        mapLine = mapFile.readline()

    rawLine = rawFile.readline()
    count = 1
    while (rawLine):
        rawLine = rawLine.strip()
        splittedLine = rawLine.split(";")
        if ( len(splittedLine) == 5 ):
            rank = int(splittedLine[0])
            image = splittedLine[1].strip()
            category = splittedLine[2].strip()
            popularity = int(splittedLine[3])
            imagetype = splittedLine[4].strip()
            imageName = imageToFullName.get(image, "")
            option = imageToOptions.get(image, "")
            outLine = image + SEPARATOR + imageName + SEPARATOR + category + SEPARATOR + str(popularity) + SEPARATOR + imagetype + SEPARATOR + option
            if ( outLine.endswith(SEPARATOR) ):
                outLine = outLine[:-1]
            if ( count <= int(options.limit) ):
                outFile.write(str(rank) + SEPARATOR + outLine + "\n")
                outFile.flush()
                count += 1
            elif ( imagetype == "Official" ):
                outFile.write(str(count) + SEPARATOR + outLine + "\n")
                outFile.flush()
                count += 1
        rawLine = rawFile.readline()

    outFile.close()
    rawFile.close()
    mapFile.close()
