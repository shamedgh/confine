import os, sys, subprocess, signal
import logging
import optparse
import requests
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

def extractImageList(myUrl):
    print ("extractImageList called")
    myHeaders = {'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9', 'Search-Version': 'v3', 'Accept': 'application/json', 'Referer': 'https://hub.docker.com/search?q=&type=image', 'Cookie': 'ajs_user_id=null; ajs_group_id=null; ajs_anonymous_id=%22123c4d3e-4df1-4445-b363-e85a49bd9b69%22; FLAG_CONSOLIDATION=true; NPS_383366e9_last_seen=1557850469905', 'Connection': 'keep-alive', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36'}
    result = set()
    response = requests.get(url = myUrl, headers = myHeaders)
    resJson = response.json()
    resultList = resJson["summaries"]
    if ( resultList ):
        for resultItem in resultList:
            #print (resultItem["slug"])
            result.add(resultItem["slug"])
    else:
        print("resultList summaries is empty, url: " + myUrl + " entire response: " + str(response))
    return result

def extractImageListWithCurl(pageNumber, officialOnly):
    cmd = "curl 'https://hub.docker.com/api/content/v1/products/search?{}page={}&page_size=25&q=&type=image' -H 'Accept-Encoding: gzip, deflate, br' -H 'Accept-Language: en-US,en;q=0.9' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36' -H 'Search-Version: v3' -H 'Accept: application/json' -H 'Referer: https://hub.docker.com/search?q=&type=image' -H 'Cookie: ajs_user_id=null; ajs_group_id=null; ajs_anonymous_id=%22123c4d3e-4df1-4445-b363-e85a49bd9b69%22; FLAG_CONSOLIDATION=true; NPS_383366e9_last_seen=1557850469905' -H 'Connection: keep-alive' --compressed"
    result = list()
    imageFilter = ""
    if ( officialOnly ):
        imageFilter = "image_filter=official&"
    cmd = cmd.format(imageFilter, pageNumber)
    returncode, out, err = util.runCommand(cmd)
    if ( returncode == 0 ):
#        curlOutputFile = open('curl.tmp', 'r')
#        curlOutput = curlOutputFile.read()
        resJson = json.loads(out)
        resultList = resJson.get("summaries", list())
        if ( resultList ):
            for resultItem in resultList:
#                print (resultItem["slug"])
#                result.add(resultItem["slug"])
                result.append(resultItem["slug"])
        else:
            print("resultList summaries is empty, url: " + cmd + " entire response: " + out)
#        curlOutputFile.close()
    else:
        print ("err: " + err)
    return result

def getImageDetails(imageName):
    myUrl = "https://hub.docker.com/api/content/v1/products/images/{}"
    myUrl = myUrl.format(imageName)
    response = requests.get(url = myUrl)
    resJson = response.json()
    return resJson

def extractCategories(resJson):
    catList = []
    categoryList = resJson.get("categories", [])
    for catItem in categoryList:
        catList.append(catItem["label"])
    return catList

def extractPopularity(resJson):
#    print ("popularity: " + str(resJson["popularity"]))
    popularity = resJson.get("popularity", "0")
    return int(popularity)
    
def isFree(resJson):
    return True
    '''notFreeList = ["BYOL", "Developer Tier", "Standard - Trial", "Developer Tier (12.2.1.1)", "Developer Plan (12.2.1.3)", "Trial Plan"]
    planList = resJson["plans"]
    for planItem in planList:
#        print(planItem["name"])
        if ( planItem["name"] in notFreeList ):
            return False
    return True'''

if __name__ == '__main__':
    """
    Main function for extracting list of docker images from docker hub
    """
    usage = "Usage: %prog -e <Target executable path> -p <PID of process to retrieve information about>"

    parser = optparse.OptionParser(usage=usage, version="1")

    parser.add_option("-n", "--number", dest="number", default=100, nargs=1,
                      help="Number of top images to extract")

    parser.add_option("-i", "--imageswoptions", dest="imageswoptions", default=None, nargs=1,
                      help="Path to file with images with special options")

    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False,
                      help="Debug enabled/disabled")

    (options, args) = parser.parse_args()
    if isValidOpts(options):
        rootLogger = setLogPath("dockerimage.log")
#https://hub.docker.com/api/content/v1/products/search?page_size=15&type=image&image_filter=official
        searchUrl = "https://hub.docker.com/api/content/v1/products/search?page={}&page_size=25&type=image&image_filter=official"

        imageOptionsDict = dict()
        if ( options.imageswoptions ):
            myFile = open(options.imageswoptions, 'r')
            line = myFile.readline()
            while ( line ):
                imageName = line.split(",")[0].strip()
                imageOption = line.split(",")[1].strip()
                imageOptionsDict[imageName] = imageOption
                line = myFile.readline()

        imageListAll = list()
        imageListOfficialOnly = list()
        pageNumber = 1
        pageSize = 25
        while pageNumber*pageSize <= int(options.number):
            url = searchUrl.format(pageNumber)
            #imageList = imageList | extractImageList(url)
            imageListOfficialOnly.extend(extractImageListWithCurl(pageNumber, True))
            imageListAll.extend(extractImageListWithCurl(pageNumber, False))
            pageNumber += 1
        print (str(len(imageListAll)))
        print (str(len(imageListOfficialOnly)))
        imageType = set()
        imageSet = set()
        rank = 1
        imageOfficial = "Unofficial"
        for image in list(imageListAll):
            if ( image not in imageSet ):
                imageSet.add(image)
                imageJson = getImageDetails(image)
                if ( imageJson.get("plans", None) != None and len(imageJson["plans"]) > 0 and imageJson["plans"][0].get("name", None) != None ):
                    imageType.add(imageJson["plans"][0]["name"])
                if ( image in imageListOfficialOnly ):#imageJson["plans"][0]["name"] == "Official Image" ):
                    imageOfficial = "Official"
                else:
                    imageOfficial = "Unofficial"
                #print("Checking image: " + image)
                if ( not isFree(imageJson) ):
                    imageListAll.remove(image)
                else:
                    if ( imageOptionsDict.get(image, "") != "" ):
                        print (str(rank) + ";" + image + ";" + str(extractCategories(imageJson)) + ";" + str(extractPopularity(imageJson)) + ";" + imageOfficial + ";" + imageOptionsDict[image])
                    else:
                        print (str(rank) + ";" + image + ";" + str(extractCategories(imageJson)) + ";" + str(extractPopularity(imageJson)) + ";" + imageOfficial)
                    rank += 1
        print ("/////////////////////////////////Starting official list//////////////////////////")
        for image in list(imageListOfficialOnly):
            if ( image not in imageSet ):
                imageOfficial = "Official"
                imageSet.add(image)
                imageJson = getImageDetails(image)
                if ( imageJson.get("plans", None) != None and len(imageJson["plans"]) > 0 and imageJson["plans"][0].get("name", None) != None ):
                    imageType.add(imageJson["plans"][0]["name"])
                #print("Checking image: " + image + " type: " + imageJson["plans"][0]["name"])
                if ( not isFree(imageJson) ):
                    imageListOfficialOnly.remove(image)
                else:
                    if ( imageOptionsDict.get(image, "") != "" ):
                        print (str(rank) + ";" + image + ";" + str(extractCategories(imageJson)) + ";" + str(extractPopularity(imageJson)) + ";" + imageOfficial + ";" + imageOptionsDict[image])
                    else:
                        print (str(rank) + ";" + image + ";" + str(extractCategories(imageJson)) + ";" + str(extractPopularity(imageJson)) + ";" + imageOfficial)
                    rank += 1
            else:
                print ("Official image: " + image + " already seen in top based on popularity")
#        print (str(len(imageList)))
#        print (str(imageType))
        #image page url: https://hub.docker.com/api/content/v1/products/images/mysql
