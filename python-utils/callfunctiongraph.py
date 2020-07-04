import os, sys, subprocess, signal
import util
import graph

class CallFunctionGraph():
    """
    This class can be used to create, manipulate and extract information from a program's call function graph
    """
    def __init__(self, graph, logger, cfgfilepath=None):
        self.logger = logger
        self.graph = graph
        self.nodeDfsDict = None
        self.cfgfilepath = ""
        if ( cfgfilepath ):
            if ( "/" in cfgfilepath ):
                cfgfilepath = cfgfilepath[cfgfilepath.rfind("/")+1:]
            self.cfgfilepath = cfgfilepath

    def integrateCves(self, requiredStartNodeList, functionToCveDict):
        allStartNodes = self.graph.extractStartingNodes()
        startNodeToCveDict = dict()
        cveToStartNodeDict = dict()

        if ( not self.nodeDfsDict ):
            self.nodeDfsDict = self.createAllDfs(allStartNodes)

        for startNode, nodeSet in self.nodeDfsDict.items():
            if ( startNode.strip() != "" ):
                if ( functionToCveDict ):
                    for functionName, cveSet in functionToCveDict.items():
                        if ( functionName in nodeSet ):
                            tempSet = startNodeToCveDict.get(startNode, set())
                            tempSet.update(cveSet)
                            startNodeToCveDict[startNode] = tempSet
            else:
                self.logger.warning("Skipping empty start node from nodeDfsDict")
        for startNode, cveSet in startNodeToCveDict.items():
            for cve in cveSet:
                tempSet = cveToStartNodeDict.get(cve, set())
                tempSet.add(startNode)
                cveToStartNodeDict[cve] = tempSet

        return startNodeToCveDict, cveToStartNodeDict

    #Can be used to extract list of functions required and not required considering the passed starting nodes
    def partitionCfg(self, requiredStartNodeList):
        allStartNodes = self.graph.extractStartingNodes()
        self.logger.debug("All start nodes extracted: %s", str(allStartNodes))
        requiredNodes = set()
        unrequiredNodes = set()

        if ( not self.nodeDfsDict ):
            self.nodeDfsDict = self.createAllDfs(allStartNodes)

        for startNode, nodeSet in self.nodeDfsDict.items():
            if ( startNode.strip() != "" ):
                if ( startNode in requiredStartNodeList ):
                    #self.logger.debug("nodeDfsDict for required startNode: %s is: %s", startNode, str(nodeDfsDict.get(startNode, set())))
                    requiredNodes.update(self.nodeDfsDict.get(startNode, set()))
                else:
                    #if ( "__sys_recvmmsg" in nodeSet ):
                    #    self.logger.debug("nodeDfsDict for nonrequired startNode: %s is: %s", startNode, str(nodeDfsDict.get(startNode, set())))
                    unrequiredNodes.update(self.nodeDfsDict.get(startNode, set()))
            else:
                self.logger.warning("Skipping empty start node from nodeDfsDict")

        return requiredNodes, unrequiredNodes

    def removeSelectStartNodes(self, startNodeList, inverse=True):
        #TODO How to extract complete list of start nodes which can be removed???
        self.logger.info("Remove select start nodes called")
        allStartNodes = self.graph.extractStartingNodes()
        self.logger.info("Create all DFS called")
        if ( not self.nodeDfsDict ):
            self.nodeDfsDict = self.createAllDfs(allStartNodes)
        self.logger.info("Get DFS size called")
        origSize = self.getSize(self.nodeDfsDict)
        self.logger.info("Original Graph Size: %d", origSize)

        if ( inverse ):     #Keep selected start nodes and remove the rest
            tobeDeletedList = set(allStartNodes) - set(startNodeList)
        else:               #Remove start nodes sent as argument
            tobeDeletedList = set(startNodeList)

        for startNode in tobeDeletedList:
            self.logger.debug("Removing %s from nodeDfsDict", startNode)
            self.nodeDfsDict.pop(startNode, None)
        modifiedSize = self.getSize(self.nodeDfsDict)
        self.logger.info("Modified Graph Size: %d", modifiedSize)
        self.logger.debug("Deleted starting nodes: %s", str(tobeDeletedList))
        return self.nodeDfsDict

    def createAllDfs(self, startNodeList):
        nodeDfsDict = dict()
        cacheFileName = "." + self.cfgfilepath + ".cfgdfs.cache"
        try:
            with open(cacheFileName, 'r') as cacheFile:
                cacheAvailable = True
        except IOError as e:
                cacheAvailable = False
        if ( cacheAvailable ):
            self.logger.info("Extracting function DFS from cache file")
            nodeDfsDict = util.readDictFromFileWithPickle(cacheFileName)
        else:
            nodeDfsDict = dict()
            remainingCount = len(startNodeList)
            #remainingCount = 0
            for startNode in startNodeList:
                remainingCount -= 1
                self.logger.debug("Running DFS from starting node: %s remaining: %d", startNode, remainingCount)
                nodeDfsDict[startNode] = self.graph.dfs(startNode)
            util.writeDictToFileWithPickle(nodeDfsDict, cacheFileName)
        return nodeDfsDict

    def getSize(self, nodeDfsDict):
        allNodes = set()
        for key, nodes in nodeDfsDict.items():
            allNodes.add(key)
            allNodes.update(nodes)
        return len(allNodes)
