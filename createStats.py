import re
import os, sys, subprocess, signal
import logging
import optparse
import time
import json
import constants as C
import util
import ast

def isValidOpts(opts):
    """
    Check if the required options are sane to be accepted
        - Check if the provided files exist
        - Check if two sections (additional data) exist
        - Read all target libraries to be debloated from the provided list
    :param opts:
    :return:
    """
    if not options.reportfile or not options.detailedreportfile or not options.imagefile or not options.outputfolder or not options.cvefile or not options.binaryfolder:
        parser.error("All options -r, -e, -i, -c, -o and -b should be provided.")
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
    usage = "Usage: %prog -r <Main report> -d <Detailed report>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-r", "--reportfile", dest="reportfile", default=None, nargs=1,
                      help="Path to main report file")

    parser.add_option("-e", "--detailedreportfile", dest="detailedreportfile", default=None, nargs=1,
                      help="Path to detailed report file.")

    parser.add_option("-i", "--imagefile", dest="imagefile", default=None, nargs=1,
                      help="Path to detailed report file.")

    parser.add_option("-c", "--cvefile", dest="cvefile", default=None, nargs=1,
                      help="Path to CVE map file.")

    parser.add_option("-o", "--outputfolder", dest="outputfolder", default=None, nargs=1,
                      help="Output folder to store stats")

    parser.add_option("-b", "--binaryfolder", dest="binaryfolder", default=None, nargs=1,
                      help="Binary folder used to store all binaries")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        SEPARATOR = ";"
        rootLogger = setLogPath("containerstatgenerator.log")

        

        imageToBins = dict()
        imageToBinCount = dict()
        imageToLibs = dict()
        imageToLibCount = dict()
        imageToExes = dict()
        imageToExeCount = dict()
        for fileName in os.listdir(options.binaryfolder):
            folderPath = os.path.join(options.binaryfolder, fileName)
            if ( os.path.isdir(folderPath) ):
                for theFile in os.listdir(folderPath):
                    count = imageToExeCount.get(fileName, 0)
                    count += 1
                    imageToExeCount[fileName] = count
                    tempSet = imageToExes.get(fileName, set())
                    tempSet.add(theFile)
                    imageToExes[fileName] = tempSet
                    if ( ".so" not in theFile ):
                        count = imageToBinCount.get(fileName, 0)
                        count += 1
                        imageToBinCount[fileName] = count
                        tempSet = imageToBins.get(fileName, set())
                        tempSet.add(theFile)
                        imageToBins[fileName] = tempSet
                    else:
                        tmpFileName = re.sub("-.*so",".so", theFile)
                        tmpFileName = tmpFileName[:tmpFileName.index(".so")]
                        tmpFileName = tmpFileName + ".so"

                        tempSet = imageToLibs.get(fileName, set())
                        if ( tmpFileName not in tempSet ):      #Only add to image count if haven't seem similar library before
                            count = imageToLibCount.get(fileName, 0)
                            count += 1
                            imageToLibCount[fileName] = count
                        tempSet.add(tmpFileName)
                        imageToLibs[fileName] = tempSet
            print("imageName: " + fileName + " lib count: " + str(imageToLibCount.get(fileName, 0)))

        reportFileBinCdf = open(options.outputfolder + "/container.bins.csv", 'w+')
        reportFileLibCdf = open(options.outputfolder + "/container.libs.csv", 'w+')
        reportFileExeCdf = open(options.outputfolder + "/container.exes.csv", 'w+')
        reportFileBinCdf.write("index" + SEPARATOR + "count\n")
        reportFileLibCdf.write("index" + SEPARATOR + "count\n")
        reportFileExeCdf.write("index" + SEPARATOR + "count\n")

        index = 1
        for imageName, count in imageToBinCount.items():
            reportFileBinCdf.write(str(index) + SEPARATOR + str(count) + "\n")
            reportFileBinCdf.flush()
            index += 1

        index = 1
        for imageName, count in imageToLibCount.items():
            reportFileLibCdf.write(str(index) + SEPARATOR + str(count) + "\n")
            reportFileLibCdf.flush()
            index += 1

        index = 1
        for imageName, count in imageToExeCount.items():
            reportFileExeCdf.write(str(index) + SEPARATOR + str(count) + "\n")
            reportFileExeCdf.flush()
            index += 1

        reportFileBinCdf.close()
        reportFileLibCdf.close()
        reportFileExeCdf.close()

        reportFilePopularityCdf = open(options.outputfolder + "/container.popularity.csv", 'w+')
        reportFilePopularityCdf.write("index" + SEPARATOR + "count\n")
        imageToCategory = dict()
        imageToRank = dict()
        imageToOfficial = dict()
        rankToImageName = dict()
        imageListFile = open(options.imagefile, 'r')
        imageListLine = imageListFile.readline()
        index = 1
        while ( imageListLine ):
            splittedLine = imageListLine.split(";")
            if ( len(splittedLine) > 2 ):
                imageRank = int(splittedLine[0].strip())
                imageName = splittedLine[1].strip()
                #imageName = splittedLine[1].strip()
                #print ("imageName: " + imageName)
                #if ( "/" in imageName ):
                #    imageName = imageName.replace("/", "-")#[imageName.rfind("/")+1:]
                #if ( ":" in imageName ):
                #    imageName = imageName[:imageName.find(":")]
                imageToRank[imageName] = imageRank
                rankToImageName[imageRank] = imageName
                imageCategory = splittedLine[3].strip()
                imageCategory = imageCategory.replace("'", "")
                imageCategory = imageCategory[1:-1]
                if ( imageCategory != "" ):
                    imageCategoryList = imageCategory.split(",")
                else:
                    imageCategoryList = ["Other"]
                imageToCategory[imageName] = imageCategoryList
                imagePopularity = int(splittedLine[4].strip())
                if ( imagePopularity != 0 ):
                    reportFilePopularityCdf.write(str(index) + SEPARATOR + str(imagePopularity) + "\n")
                    reportFilePopularityCdf.flush()
                    index += 1
                imageOfficial = splittedLine[5].strip()
                imageToOfficial[imageName] = imageOfficial
                print ("imageName: " + imageName + " category: " + str(imageCategoryList))

            imageListLine = imageListFile.readline()

        reportFilePopularityCdf.close()
        reportFile = open(options.reportfile, 'r')

        officialCount = 0
        unofficialCount = 0
        reportFileSummary = open(options.outputfolder + "/container.stats.csv", 'w+')
        reportFileLanguageBased = open(options.outputfolder + "/container.language.stats.csv", 'w+')
        reportFileRankBased = open(options.outputfolder + "/container.rank.stats.csv", 'w+')
        reportFileCdf = open(options.outputfolder + "/container.cdf.csv", 'w+')
        reportFileCdf.write("index" + SEPARATOR + "count\n")
        reportFileTop20Popularity = open(options.outputfolder + "/container.debloat.stats.top20.popularity.csv", 'w+')
        reportFileTop20Debloatable = open(options.outputfolder + "/container.debloat.stats.top20.debloatable.csv", 'w+')
        reportFileTop20Popularity.write("Image Name" + SEPARATOR + "Filtered Syscall" + SEPARATOR + "Popularity Rank" + SEPARATOR + "Category\n")
        reportFileTop20Debloatable.write("Image Name" + SEPARATOR + "Filtered Syscall" + SEPARATOR + "Popularity Rank" + SEPARATOR + "Category\n")

        totalImageCount = 0
        runnableImageCount1 = 0
        runnableImageCount2 = 0
        debloatableImageCount = 0
        top20PopularityCount = 0
        index = 0
        TOPNCOUNT = 200

        rankRunnability1Success = dict()
        rankRunnability2Success = dict()
        rankDebloatabilitySuccess = dict()

        languageTotalCount = dict()        
        languageRunnability1Success = dict()
        languageRunnability2Success = dict()
        languageDebloatabilitySuccess = dict()

        top20PopularityExceptList = []#"busybox"]

        imageToSyscallCount = dict()
        imageToDebloatStatus = dict()
        reportLine = reportFile.readline()
        while ( reportLine ):
            splittedLine = reportLine.split(";")
            if ( len(splittedLine) > 13 ):
                rank = int(splittedLine[0])
                imageName = splittedLine[1]
                runStatus = splittedLine[2] == "True"
                continuesRunningStatus = splittedLine[3] == "True"
                syscallCount = int(splittedLine[5])
                if ( len(splittedLine) == 14 ):
                    debloatStatus = splittedLine[8] == "True"
                    langSetStr = splittedLine[13]
                else:
                    debloatStatus = splittedLine[9] == "True"
                    langSetStr = splittedLine[14]

                imageToDebloatStatus[imageName] = debloatStatus

                if ( continuesRunningStatus ):
                    if ( imageToOfficial[imageName] == "Unofficial" ):
                        unofficialCount += 1
                    elif ( imageToOfficial[imageName] == "Official" ):
                        officialCount += 1
                    else:
                        print("Image Name: %s isn't official or unofficial: %s", imageName, imageToOfficial[imageName])

                #rankToImageName[rank] = imageName

#                if ( rank <= TOPNCOUNT and debloatStatus and imageName not in top20PopularityExceptList ):
#                    top20PopularityCount += 1
#                    #reportFileTop20Popularity.write(imageName + "," + str(syscallCount) + "," + str(round((syscallCount/326)*100, 2)) + "\n")
#                    reportFileTop20Popularity.write(imageName + SEPARATOR + str(syscallCount) + SEPARATOR + str(imageToRank[imageName]) + SEPARATOR + str(imageToCategory[imageName]) + "\n")
#                    reportFileTop20Popularity.flush()
                if ( debloatStatus ):
                    imageToSyscallCount[imageName] = syscallCount
                    index += 1
                    reportFileCdf.write(str(index) + SEPARATOR + str(syscallCount) + "\n")
                    reportFileCdf.flush()

                #TODO Create stats:
                #TODO Overall
                totalImageCount += 1
                if ( runStatus ):
                    runnableImageCount1 += 1
                if ( continuesRunningStatus ):
                    runnableImageCount2 += 1
                if ( debloatStatus ):
                    debloatableImageCount += 1

                #TODO Rank vs runnability or debloatability
                rank = int(rank/10)
                count = rankRunnability1Success.get(rank, 0)
                if ( runStatus ):
                    count += 1
                    rankRunnability1Success[rank] = count
                count = rankRunnability2Success.get(rank, 0)
                if ( continuesRunningStatus ):
                    count += 1
                    rankRunnability2Success[rank] = count
                count = rankDebloatabilitySuccess.get(rank, 0)
                if ( debloatStatus ):
                    count += 1
                    rankDebloatabilitySuccess[rank] = count
                
                #TODO Success and failure based upon language
                if ( langSetStr.strip() == "set()" ):
                    langList = list()
                else:
                    langList = list(ast.literal_eval(langSetStr))
                if ( len(langList) > 1 ):
                    try:
                        langList.remove(util.BinaryLang.CCPP.name)
                    except:
                        rootLogger.warning("%s doesn't exist in list larger than 1", util.BinaryLang.CCPP.name)
                if ( len(langList) == 0 ):
                    langList = ["Unknown"]
                for lang in langList:
                    count = languageTotalCount.get(lang, 0)
                    count += 1
                    languageTotalCount[lang] = count
                    count = languageRunnability1Success.get(lang, 0)
                    if ( runStatus ):
                        count += 1
                        languageRunnability1Success[lang] = count
                    count = languageRunnability2Success.get(lang, 0)
                    if ( continuesRunningStatus ):
                        count += 1
                        languageRunnability2Success[lang] = count
                    count = languageDebloatabilitySuccess.get(lang, 0)
                    if ( debloatStatus ):
                        count += 1
                        languageDebloatabilitySuccess[lang] = count

            else:
                rootLogger.warning("Main report line has less than 14 elements: %s", reportLine)
            reportLine = reportFile.readline()

        reportFileSummary.write("Category" + SEPARATOR + "Count\n")
        reportFileSummary.write("Total" + SEPARATOR + str(totalImageCount) + "\n")
        reportFileSummary.write("Runnable" + SEPARATOR + str(runnableImageCount1) + "\n")
        reportFileSummary.write("Stays Running" + SEPARATOR + str(runnableImageCount2) + "\n")
        reportFileSummary.write("Debloatable" + SEPARATOR + str(debloatableImageCount) + "\n")
        reportFileSummary.flush()
        reportFileSummary.close()
        reportFileCdf.close()

        rankIndex = 1
        i = 0
        while i < TOPNCOUNT:
            imageName = rankToImageName.get(rankIndex, None)
            if ( imageName ):
                if ( imageToDebloatStatus[imageName] ):
                    syscallCount = imageToSyscallCount[imageName]
                    reportFileTop20Popularity.write(imageName + SEPARATOR + str(syscallCount) + SEPARATOR + str(rankIndex) + SEPARATOR + str(imageToCategory[imageName]) + "\n")
                    reportFileTop20Popularity.flush()
                    i += 1
                rankIndex += 1
            else:
                break
        reportFileTop20Popularity.close()

        sortedTop20Debloatable = [(k, imageToSyscallCount[k]) for k in sorted(imageToSyscallCount, key=imageToSyscallCount.get, reverse=True)]
        count = 0
        for imageName, syscallCount in sortedTop20Debloatable:
            print ("imageName: " + imageName + " count: " + str(syscallCount))
            if ( count < TOPNCOUNT ):
                reportFileTop20Debloatable.write(imageName + SEPARATOR + str(syscallCount) + SEPARATOR + str(imageToRank[imageName]) + SEPARATOR + str(imageToCategory[imageName]) + "\n")
#                reportFileTop20Debloatable.write(imageName + SEPARATOR + str(syscallCount) + "\n")
                reportFileTop20Debloatable.flush()
                count += 1
        reportFileTop20Debloatable.close()


        reportFileLanguageBased.write("Type" + SEPARATOR + "Language" + SEPARATOR + "Count\n")
        for lang, count in languageTotalCount.items():
            #reportFileLanguageBased.write(lang + "," + str(languageRunnability1Success.get(lang, 0)) + "," + str(languageRunnability2Success.get(lang, 0)) + "," + str(languageDebloatabilitySuccess.get(lang, 0)) + "," + str(count) + "\n")
            reportFileLanguageBased.write("Total" + SEPARATOR + lang + SEPARATOR + str(languageRunnability2Success.get(lang, 0)) + "\n")
            reportFileLanguageBased.write("Debloatable" + SEPARATOR + lang + SEPARATOR + str(languageDebloatabilitySuccess.get(lang, 0)) + "\n")
            #reportFileLanguageBased.write(lang + "," + str(round((languageDebloatabilitySuccess.get(lang, 0)/languageRunnability2Success.get(lang, 0))*100, 2)) + "," + str(languageDebloatabilitySuccess.get(lang, 0)) + "\n")
            reportFileLanguageBased.flush()
        reportFileLanguageBased.close()

        reportFileRankBased.write("RankGroup" + SEPARATOR + "Runnable" + SEPARATOR + "Debloatable\n")
        for rank, count in rankRunnability1Success.items():
            #reportFileRankBased.write(str(rank) + "," + str(rankRunnability1Success.get(rank, 0)) + "," + str(rankRunnability2Success.get(rank, 0)) + "," + str(rankDebloatabilitySuccess.get(rank, 0)) + "\n")
            reportFileRankBased.write(str(rank) + SEPARATOR + str(rankRunnability2Success.get(rank, 0)) + SEPARATOR + str(rankDebloatabilitySuccess.get(rank, 0)) + "\n")
            reportFileRankBased.flush()
        reportFileRankBased.close()


        cveDict = dict()
        cveToContainer = dict()
        cveFile = open(options.cvefile, 'r')
        cveLine = cveFile.readline()
        while ( cveLine ):
            cveId = cveLine.split(":")[0]
            syscallListStr = cveLine.split(":")[1]
            syscallList = ast.literal_eval(syscallListStr)
            cveDict[cveId] = syscallList
            cveToContainer[cveId] = set()
            cveLine = cveFile.readline()

        detailedReportFile = open(options.detailedreportfile, 'r')
        reportFileCategorized = open(options.outputfolder + "/syscall.categorized.csv", 'w+')
        reportFileSyscall = open(options.outputfolder + "/syscall.top.csv", 'w+')
        reportFileSyscallTop = open(options.outputfolder + "/syscall.top.200.csv", 'w+')
        cveStats = open(options.outputfolder + "/syscall.cve.stats.csv", 'w+')
        line = detailedReportFile.readline()
        categoryIntersection = dict()
        categoryUnion = dict()
        categoryCount = dict()
        blacklistCount = dict()


        while ( line ):
            splittedLine = line.split(";")
            if ( len(splittedLine) > 7 ):
                imageName = splittedLine[1]
                syscallListStr = splittedLine[7]
                '''syscallListStr = ""
                for item in splittedLine[7:]:
                    syscallListStr += item + ","
                if ( syscallListStr.endswith(",") ):
                    syscallListStr = syscallListStr[:-1]'''
                syscallSet = set(ast.literal_eval(syscallListStr))

                for cveId, syscallList in cveDict.items():
                    applicable = True
                    for syscallItem in syscallList:
                        if ( syscallItem not in syscallSet ):
                            applicable = False
                            break
                    if ( applicable ):
                        tempSet = cveToContainer.get(cveId, set())
                        tempSet.add(imageName)
                        cveToContainer[cveId] = tempSet

                #TODO Top 20 blacklisted system calls
                for syscall in syscallSet:
                    count = blacklistCount.get(syscall, 0)
                    count += 1
                    blacklistCount[syscall] = count

                #TODO Categorized system call statistics
                for category in imageToCategory[imageName]:
                    category = category.strip()
                    count = categoryCount.get(category, 0)
                    count += 1
                    categoryCount[category] = count
                    catSet = categoryIntersection.get(category, syscallSet)
                    catSet = catSet.intersection(syscallSet)
                    categoryIntersection[category] = catSet

                    catSet = categoryUnion.get(category, set())
                    catSet = catSet.union(syscallSet)
                    categoryUnion[category] = catSet
            line = detailedReportFile.readline()

        detailedReportFile.close()

        cveStats.write("CVE" + SEPARATOR + "System Call(s)" + SEPARATOR + "Description" + SEPARATOR + "Containers Effected Examples" + SEPARATOR + "Number of Containers Effected\n")
        for cveId, containerList in cveToContainer.items():
            syscallList = str(cveDict[cveId]).strip()
            syscallList = syscallList.replace("[","")
            syscallList = syscallList.replace("]","")
            syscallList = syscallList.replace("\"","")
            syscallList = syscallList.replace("'","")
            tmpList = list()
            if ( "nginx" in containerList ):
                tmpList.append("Nginx")
            if ( "mysql" in containerList ):
                tmpList.append("MySQL")
            if ( "postgres" in containerList ):
                tmpList.append("PostgreSQL")
            if ( "redis" in containerList ):
                tmpList.append("Redis")
            if ( "httpd" in containerList ):
                tmpList.append("Apache Httpd")
            if ( "couchbase" in containerList ):
                tmpList.append("Couchbase")
            if ( "mongo" in containerList ):
                tmpList.append("MongoDB")
            if ( "couchdb" in containerList ):
                tmpList.append("CouchDB")
            if ( len(tmpList) < 10 ):
                tmpList.extend(list(containerList)[:10-len(tmpList)])
            tmpListStr = str(tmpList)
            tmpListStr = tmpListStr.replace("[", "")
            tmpListStr = tmpListStr.replace("]", "")
            tmpListStr = tmpListStr.replace("'", "")
            cveStats.write(cveId + SEPARATOR + syscallList + SEPARATOR + "" + SEPARATOR + tmpListStr + SEPARATOR + str(len(containerList)) + "\n")
            cveStats.flush()
        cveStats.close()

        #reportFileCategorized.write("Type" + SEPARATOR + "CategoryName" + SEPARATOR + "SyscallCount\n")
        reportFileCategorized.write("CategoryName" + SEPARATOR + "SyscallCount\n")
        for categoryName, syscallSet in categoryIntersection.items():
            #reportFileCategorized.write(categoryName + "," + str(len(syscallSet)) + "," + str(categoryCount.get(categoryName, 0)) + "\n")
            #reportFileCategorized.write(categoryName + "," + str(len(categoryUnion.get(categoryName, set()))) + "," + str(categoryCount.get(categoryName, 0)) + "\n")
            reportFileCategorized.write(categoryName.strip() + SEPARATOR + str(len(syscallSet)) + "\n")
            #reportFileCategorized.write("intersection" + SEPARATOR + categoryName.strip() + SEPARATOR + str(len(syscallSet)) + "\n")
            #reportFileCategorized.write("union" + SEPARATOR + categoryName.strip() + SEPARATOR + str(len(categoryUnion.get(categoryName, set()))) + "\n")
            reportFileCategorized.flush()
        reportFileCategorized.close()

#        sortedBlacklist = dict(sorted(blacklistCount, key=blacklistCount.get, reverse=True)[:20])
        sortedBlacklist = [(k, blacklistCount[k]) for k in sorted(blacklistCount, key=blacklistCount.get, reverse=True)]
        reportFileSyscall.write("ContainerCount" + SEPARATOR + "SyscallCount\n")
        reportFileSyscallTop.write("Syscall" + SEPARATOR + "Count\n")
        countDict = dict()
        for syscall, count in sortedBlacklist:
            countPerCount = countDict.get(count, 0)
            countPerCount += 1
            countDict[count] = countPerCount
            reportFileSyscallTop.write(syscall + SEPARATOR + str(count) + "\n")
            reportFileSyscallTop.flush()
        for countKey, countValue in countDict.items():
            reportFileSyscall.write(str(countKey) + SEPARATOR + str(countValue) + "\n")
            reportFileSyscall.flush()
        reportFileSyscall.close()
        reportFileSyscallTop.close()


        print ("Official count: " + str(officialCount) + " Unofficial Count: " + str(unofficialCount))
