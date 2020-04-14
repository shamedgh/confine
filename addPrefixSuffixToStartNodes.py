import sys

inputPath = sys.argv[1]
outputPath = sys.argv[2]

prefixes = ["__x64_sys_"]
suffixes = ["", "_time64", "_time32", "_time64_time32"]

inputFile = open(inputPath, 'r')
outputFile = open(outputPath, 'w')

inputLine = inputFile.readline()
while ( inputLine ):
#    outputFile.write(inputLine)
    startNode = inputLine.strip()
    for prefix in prefixes:
        for suffix in suffixes:
            outputFile.write(prefix + startNode + suffix + "\n")
            outputFile.flush()
    inputLine = inputFile.readline()
outputFile.close()
inputFile.close()
