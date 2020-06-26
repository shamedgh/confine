import sys
import json

sys.path.insert(0, './python-utils/')

import util

def jsonTemplate():
    return json.loads('{"enable": "false","image-name": "", "image-url": "", "category": [], "pull-count":0, "official": "true", "options": "", "args": "", "dependencies": {}}')


inputFilePath = sys.argv[1]
outputFilePath = sys.argv[2]

inputFile = open(inputFilePath, 'r')
outputFile = open(outputFilePath, 'w')

inputLine = inputFile.readline()

imageDict = dict()
while ( inputLine ):
    inputLine = inputLine.strip()
    splittedInput = inputLine.split(";")
    if ( len(splittedInput) > 5 ):
        imageId = splittedInput[0].replace("#", "")
        imageName = splittedInput[1]
        imageUrl = splittedInput[2]
        imageCategory = splittedInput[3]
        imagePullCount = int(splittedInput[4])
        imageOptions = ""
        if ( len(splittedInput) > 6 ):
            imageOptions = splittedInput[6]

        newImage = jsonTemplate()
        newImage["image-name"] = imageName
        if ( imageUrl and imageUrl != "" ):
            newImage["image-url"] = imageUrl
        else:
            newImage["image-url"] = imageName
        newImage["id"] = imageId
        if ( imageCategory != "" ):
            imageCategory = imageCategory.replace("'", "")
            imageCategory = imageCategory.replace("[", "")
            imageCategory = imageCategory.replace("]", "")
            newImage["category"] = util.convertStrListToList(imageCategory)
        else:
            newImage["category"] = ["Other"]

        newImage["pull-count"] = imagePullCount
        newImage["official"] = True if splittedInput[5] == "Official" else False
        newImage["options"] = imageOptions
        newImage["args"] = ""

        imageDict[imageName] = newImage

    inputLine = inputFile.readline()

outputFile.write(str(json.dumps(imageDict, indent=4)))
