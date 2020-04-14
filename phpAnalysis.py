import sys
import os

sys.path.insert(0, './python-utils/')

import util
import sourceAnalysisInterface
import container
import constants as C

class PhpAnalysis(SourceAnalysisInterface):
    """
    This class can be used to analyze PHP projects and extract the list of
    executables which it might run in the future and libraries which it 
    could load.
    """
    def __init__(self, container, folderPath, logger):
        self.container = container
        self.folderPath = folderPath
        self.logger = logger

    def getBinaries(self):
        #Create superset of binaries from container (or cache file)
        filesReady = false
        binaryListReady = false
        libraryListReady = false
        try:
            self.logger.debug("Checking cache in %s", self.folderPath)
            myFile = open(self.folderPath + "/" + C.CACHE, 'r')
            filesReady = True
            myFile = open(self.folderPath + "/" + C.BINLISTCACHE, 'r')
            binaryListReady = True
        except OSError as e:
            self.logger.info("Cache doesn't exist")

        if ( not filesReady ):
            #find and copy the source code
            if ( container != None )
                fileList = container.find("/", "\".php\"")
                for filePath in fileList:
                    container.copyFromContainer(filePath, self.folderPath)
                myFile = open(self.folderPath + "/" + C.CACHE, 'w')
                myFile.write("complete")
                myFile.flush()
                myFile.close()
        if ( not binaryListReady ):
            #find and create list of all binaries in container
            binaryList = container.extractAllBinaries()
            myFile = open(self.folderPath + "/" + C.BINLISTCACHE, 'w')
            for binaryPath in binaryList:
                myFile.write(binaryPath)
                myFile.flush()
            myFile.close()
                
        #The following should be done by an external program depending on the lang.
        #1. Create AST
        #2. Analyze PHP AST
        #3. Search for binaries in the superset in the PHP AST
        binaryList = list() #TODO extract from result of AST analysis
        #Return list of binaries which are found in the PHP AST
        return binaryList

    def getLibraries(self, librarySuperset=None):
        filesReady = false
        binaryListReady = false
        libraryListReady = false
        try:
            self.logger.debug("Checking cache in %s", self.folderPath)
            myFile = open(self.folderPath + "/" + C.CACHE, 'r')
            filesReady = True
            myFile = open(self.folderPath + "/" + C.BINLISTCACHE, 'r')
            libraryListReady = True
        except OSError as e:
            self.logger.info("Cache doesn't exist")
