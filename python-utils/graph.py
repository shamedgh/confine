import os, sys, subprocess, signal
import util
import copy

class Graph():
    """
    This class can be used to create a graph and run DFS and BFS on it
    """
    INITIAL = "white"
    VISITED = "green"

    DEFAULT = "orange"    #default (direct/indirect/conditional)
    CONDITIONAL = "yellow"  #conditional
    DIRECT = "blue"   #direct
    INDIRECT = "red"   #indirect
    EXT = "purple"   #external
    
    def __init__(self, logger):
        self.logger = logger
        self.adjGraph = dict()
        self.reverseAdjGraph = dict()
        self.nodeInputs = dict()
        self.nodeOutputs = dict()
        self.startingNodes = None
        self.nodeColor = dict()
        self.edgeIdToTuple = dict()     #edgeId -> tuple(caller, callee)
        self.edgeTupleToId = dict()     #tuple(caller, callee) -> edgeId
        self.edgeColor = dict()     #edgeColor[edgeId] = self.DEFAULT
        self.edgeCondition = dict()     #edgeCondition[edgeId] = CONDITION(%10==null TRUE)
        self.allNodes = set()
        self.edgeId = 0

    def deepCopy(self):
        copyGraph = Graph(self.logger)
        copyGraph.adjGraph = copy.deepcopy(self.adjGraph)
        copyGraph.reverseAdjGraph = copy.deepcopy(self.reverseAdjGraph)
        copyGraph.nodeInputs = copy.deepcopy(self.nodeInputs)
        copyGraph.nodeOutputs = copy.deepcopy(self.nodeOutputs)
        copyGraph.startingNodes = copy.deepcopy(self.startingNodes)
        copyGraph.nodeColor = copy.deepcopy(self.nodeColor)
        copyGraph.edgeIdToTuple = copy.deepcopy(self.edgeIdToTuple)
        copyGraph.edgeTupleToId = copy.deepcopy(self.edgeTupleToId)
        copyGraph.edgeColor = copy.deepcopy(self.edgeColor)
        copyGraph.edgeCondition = copy.deepcopy(self.edgeCondition)
        copyGraph.allNodes = copy.deepcopy(self.allNodes)
        return copyGraph

    def getAllNodes(self):
        return self.allNodes

    def getNodeCount(self):
        return len(self.allNodes)

    def addNode(self, nodeName):
        if ( not self.adjGraph.get(nodeName, None) ):
            self.adjGraph[nodeName] = list()
            count = self.nodeInputs.get(nodeName, 0)
            self.nodeInputs[nodeName] = count
            count = self.nodeOutputs.get(nodeName, 0)
            self.nodeOutputs[nodeName] = count
            self.nodeColor[nodeName] = self.INITIAL
        self.allNodes.add(nodeName)

    def addEdgeWithType(self, srcNode, dstNode, edgeType):
        self.addEdge(srcNode, dstNode)
        edgeId = self.edgeTupleToId[(srcNode, dstNode)]
        self.edgeColor[edgeId] = edgeType

    def addEdge(self, srcNode, dstNode):
        self.allNodes.add(srcNode)
        self.allNodes.add(dstNode)
        #Add forward edge
        currentList = self.adjGraph.get(srcNode, list())
        currentList.append(dstNode)
        self.adjGraph[srcNode] = currentList
        #self.logger.debug("Adding edge from %s to %s", srcNode, dstNode)

        #Add reverse edge
        currentList = self.reverseAdjGraph.get(dstNode, list())
        currentList.append(srcNode)
        self.reverseAdjGraph[dstNode] = currentList

        #Update input count:
        count = self.nodeInputs.get(srcNode, 0)
        self.nodeInputs[srcNode] = count

        if ( srcNode != dstNode ):
            count = self.nodeInputs.get(dstNode, 0)
            count += 1
            self.nodeInputs[dstNode] = count

        #Update output count:
        count = self.nodeOutputs.get(dstNode, 0)
        self.nodeOutputs[dstNode] = count

        if ( srcNode != dstNode ):
            count = self.nodeOutputs.get(srcNode, 0)
            count += 1
            self.nodeOutputs[srcNode] = count

        self.edgeIdToTuple[self.edgeId] = (srcNode, dstNode)
        self.edgeTupleToId[(srcNode, dstNode)] = self.edgeId
        self.edgeColor[self.edgeId] = self.DEFAULT
        self.edgeId += 1

    def dfs(self, startNode):
        visitedNodes = set()
        myStack = list()
        myStack.append(startNode)

        if ( len(self.adjGraph.get(startNode, list())) == 0 ):
            return visitedNodes

        while ( len(myStack) != 0 ):
            currentNode = myStack.pop()
            if ( currentNode not in visitedNodes):
                #self.logger.debug("Visiting node: " + currentNode)
                visitedNodes.add(currentNode)
                for node in self.adjGraph.get(currentNode, list()):
                    #self.logger.debug("Adding node: " + node)
                    myStack.append(node)

        return visitedNodes

    def minimumRemovableEdges(self, conditionalGraphFile, cfgSeparator, start, end, maxDepth):
        self.applyConditionalGraph(conditionalGraphFile, cfgSeparator)
        clone = self.deepCopy()
        depthToEdge = dict()
        visitedNodes = set()
        clone.reverseDfs(end, start, end, visitedNodes, depthToEdge, 0, maxDepth)
        for depth, edgeIdDict in depthToEdge.items():
            for edgeId, status in edgeIdDict.items():
                if ( not status ):
                    self.logger.info("depth: %d, edgeId: %d, edge: %s", depth, edgeId, self.edgeIdToTuple[edgeId])
        return

    def reverseDfs(self, currentNode, start, end, visitedNodes, depthToEdge, currentDepth, maxDepth):
        self.logger.debug("reverseDfs: currentDepth: %d and maxDepth: %d, currentNode: %s, adjList: %s", currentDepth, maxDepth, currentNode, str(self.reverseAdjGraph.get(currentNode, list())))
        if ( currentDepth > maxDepth or currentNode in visitedNodes or len(self.reverseAdjGraph.get(currentNode, list())) == 0 ):
            return
        accessibleList = self.accessibleFromStartNode(start, [end], list())
        self.logger.debug("%s to %s isReachable? %s", start, end, str(len(accessibleList) != 0))
        if ( len(accessibleList) == 0 ):
            self.logger.info("reverseDfs: accessibleList is empty, returning...")
            return

        visitedNodes.add(currentNode)

        self.logger.debug("currentNode: %s", currentNode)
        adjList = copy.deepcopy(self.reverseAdjGraph.get(currentNode, list()))
        for node in adjList:
            self.logger.debug("node: %s", node)
            conditionalEdgeBool = self.edgeTupleToId.get((node, currentNode), None) and self.edgeColor.get(self.edgeTupleToId[(node, currentNode)], None) and self.edgeColor[self.edgeTupleToId[(node, currentNode)]] == self.CONDITIONAL
            if ( conditionalEdgeBool ):
                depthEdgeToStatus = depthToEdge.get(currentDepth, dict())
                depthEdgeStatus = depthEdgeToStatus.get(self.edgeTupleToId[node, currentNode], True)
                depthEdgeToStatus[self.edgeTupleToId[node, currentNode]] = depthEdgeStatus
                #depthEdges.add(self.edgeTupleToId[node, currentNode])
                depthToEdge[currentDepth] = depthEdgeToStatus
            self.reverseDfs(node, start, end, visitedNodes, depthToEdge, currentDepth+1, maxDepth)
            if ( conditionalEdgeBool ):
                clone = self.deepCopy()
                clone.deleteEdgeByTuple((node, currentNode))
                isReachable = len(clone.accessibleFromStartNode(start, [end], list())) != 0
                if ( not isReachable ):
                    depthToEdge[currentDepth] = depthEdgeToStatus
                    depthEdgeToStatus[self.edgeTupleToId[node, currentNode]] = False
                    depthToEdge[currentDepth] = depthEdgeToStatus
                self.logger.info("After deleting edge: %d, tuple: %s, isReachable? %s", self.edgeTupleToId[(node, currentNode)], (node, currentNode), str(isReachable))
                #self.deleteEdgeByTuple((node, currentNode))

        return

    def bfs(self):
        #TODO
        return list()

    def deleteEdgeById(self, edgeId):
        edgeTuple = self.edgeIdToTuple[edgeId]
        return deleteEdgeByTuple(edgeTuple)
        

    def deleteEdgeByTuple(self, edgeTuple):
        srcNode = edgeTuple[0]
        dstNode = edgeTuple[1]
        self.logger.debug("Deleting edge from %s to %s", srcNode, dstNode)
        #Delete forward edge
        currentList = self.adjGraph.get(srcNode, list())
        currentList.remove(dstNode)
        self.adjGraph[srcNode] = currentList

        #Add reverse edge
        currentList = self.reverseAdjGraph.get(dstNode, list())
        currentList.remove(srcNode)
        self.reverseAdjGraph[dstNode] = currentList

        #Update input count:
        if ( srcNode != dstNode ):
            count = self.nodeInputs.get(dstNode, 0)
            count -= 1
            self.nodeInputs[dstNode] = count

        #Update output count:
        if ( srcNode != dstNode ):
            count = self.nodeOutputs.get(srcNode, 0)
            count -= 1
            self.nodeOutputs[srcNode] = count

    def deleteOutboundEdges(self, node):
        dstNodes = copy.deepcopy(self.adjGraph.get(node, list()))
        self.logger.debug("dstNodes to be deleted: %s", str(dstNodes))
        for dstNode in dstNodes:
            self.deleteEdgeByTuple((node, dstNode))

    def deleteInboundEdges(self, node, edgeType=None):
        srcNodes = copy.deepcopy(self.reverseAdjGraph.get(node, list()))
        self.logger.debug("srcNodes to be deleted: %s", str(srcNodes))
        for srcNode in srcNodes:
            self.logger.debug("%s->%s edge type: %s", srcNode, node, self.getEdgeType(srcNode, node))
            if ( not edgeType or (edgeType and edgeType == self.getEdgeType(srcNode, node))):
                self.deleteEdgeByTuple((srcNode, node))

    '''
    The difference of this function compared to pruneInaccessibleFunctionPointers is that in this we consider 
    all functions used as indirect call site targets as our base and not only the function pointer file.
    After we reach a conclusion on the correctness of applying this to the main function we can merge these 
    two funtions.
    For now we won't to keep the code which generated the paper results intact
    '''
    def pruneAllFunctionPointersNotAccessibleFromChild(self, startNode, funcPointerFile, directCfgFile, separator, outputFile):
        indirectOnlyFunctions = self.extractIndirectOnlyFunctions(directCfgFile, separator)
        fpFuncToCaller = dict()

        fpFile = open(funcPointerFile, 'r')
        fpLine = fpFile.readline()
        while ( fpLine ):
            #Iterate over each fp file line
            if ( "->" in fpLine ):
                splittedLine = fpLine.split("->")
                caller = splittedLine[0].strip()
                fpFunc = splittedLine[1].strip()
                self.logger.debug("caller: %s, fp: %s", caller, fpFunc)
                fpFuncSet = fpFuncToCaller.get(fpFunc, set())
                fpFuncSet.add(caller)
                fpFuncToCaller[fpFunc] = fpFuncSet
            else:
                self.logger.warning("Skipping function pointer line: %s", fpLine)

            fpLine = fpFile.readline()

        for fpFunc in indirectOnlyFunctions:
#        for fpFunc, callerSet in fpFuncToCaller.items():
            callerSet = fpFuncToCaller.get(fpFunc, set())
            tmpClone = self.deepCopy()
            
            #Temporarily remove outbound edges from B
            tmpClone.deleteOutboundEdges(fpFunc)
            reachableSet = set()
            for caller in callerSet:
                #Check if caller is reachable from start node
                reachableSet.update(tmpClone.accessibleFromStartNode(startNode, [caller], list()))
            self.logger.debug("Reachable Set: %s", str(reachableSet))
            callerReachable = (len(reachableSet) > 0)
            self.logger.debug("caller: %s isReachable from child/worker? %s", caller, callerReachable)
            #If caller isn't reachable, permanently remove all indirect calls to B
            if ( not callerReachable ):
                self.deleteInboundEdges(fpFunc.strip(), self.DEFAULT)
        #Write final graph to file
        self.dumpToFile(outputFile)

    def extractIndirectOnlyFunctions(self, directCfgFile, separator):
        self.applyDirectGraph(directCfgFile, separator)
        indirectFunctions = set()
        
        for node, callers in self.reverseAdjGraph.items():
            directCallerSet = set()
            for caller in callers:
                if self.getEdgeType(caller, node) == self.DIRECT:
                    directCallerSet.add(caller)
                    break
            if ( len(directCallerSet) == 0 ):
                indirectFunctions.add(node)
        return indirectFunctions

    def pruneInaccessibleFunctionPointers(self, startNode, funcPointerFile, directCfgFile, separator, outputFile):
        #Apply direct CFG to current graph
        self.applyDirectGraph(directCfgFile, separator)

        #3/26/2020
        #Do we have to consider all functions only called through indirect call sites
        #which don't have their address taken at all?
        #Currently we're only removing those which have their address taken in paths unreachable 
        #from main, but it seems that there could be functions which don't have their address 
        #taken at all???
        #Won't add to keep this function in accordance with submitted version of paper!
        #Could it be that these functions would be removed by dead code elimination of the compiler??

        #Read function pointer file:
        #function (A)->function pointed to by FP (B)
        #piped_log_spawn->piped_log_maintenance

        #BUG: We have to consider ALL callers of FP before removing the edges
        #We we're previously removing all incoming edges when we identified only 
        #one caller as unreachable from start
        #FIXED
        fpFuncToCaller = dict()

        fpFile = open(funcPointerFile, 'r')
        fpLine = fpFile.readline()
        while ( fpLine ):
            #Iterate over each fp file line
            if ( "->" in fpLine ):
                splittedLine = fpLine.split("->")
                caller = splittedLine[0].strip()
                fpFunc = splittedLine[1].strip()
                self.logger.debug("caller: %s, fp: %s", caller, fpFunc)
                fpFuncSet = fpFuncToCaller.get(fpFunc, set())
                fpFuncSet.add(caller)
                fpFuncToCaller[fpFunc] = fpFuncSet
            else:
                self.logger.warning("Skipping function pointer line: %s", fpLine)

            fpLine = fpFile.readline()

        for fpFunc, callerSet in fpFuncToCaller.items():
            tmpClone = self.deepCopy()
            
            #Temporarily remove outbound edges from B
            tmpClone.deleteOutboundEdges(fpFunc)
            reachableSet = set()
            for caller in callerSet:
                #Check if caller is reachable from start node
                reachableSet.update(tmpClone.accessibleFromStartNode(startNode, [caller], list()))
            self.logger.debug("Reachable Set: %s", str(reachableSet))
            callerReachable = (len(reachableSet) > 0)
            self.logger.debug("caller: %s isReachable? %s", caller, callerReachable)
            #If caller isn't reachable, permanently remove all indirect calls to B
            if ( not callerReachable ):
                self.deleteInboundEdges(fpFunc.strip(), self.DEFAULT)
        #Write final graph to file
        self.dumpToFile(outputFile)

    def pruneConditionalTrueEdges(self):
        return True

    def isAccessible(self, startNode, targetNode, filterList=list(), exceptList=list()):
        results = set()
        visitedNodes = set()
        myStack = list()
        myStack.append(startNode)
        self.logger.debug("running isAccessible with startNode: %s, targetNode: %s", startNode, targetNode)
        if ( len(self.adjGraph.get(startNode, list())) == 0 ):
            self.logger.debug("adjGraph for %s is empty, returning False", startNode)            
            return False

        while ( len(myStack) != 0 ):
            currentNode = myStack.pop()
            if ( currentNode not in visitedNodes):
                if ( currentNode == targetNode ):
                    return True
                #self.logger.debug("Visiting node: " + currentNode)
                visitedNodes.add(currentNode)
                if ( ( len(filterList) == 0 and len(exceptList) == 0 ) or ( len(filterList) > 0 and currentNode in filterList) or ( len(exceptList) > 0 and currentNode not in exceptList ) ):
                    results.add(currentNode)
                if ( len(self.adjGraph.get(currentNode, list())) != 0 ):
                    for node in self.adjGraph.get(currentNode, list()):
                        myStack.append(node)

        return False


    def extractStartingNodes(self):
        self.startingNodes = list()
        for nodeName, inputCount in self.nodeInputs.items():
            #self.logger.debug("nodeName: %s, inputCount: %d", nodeName, inputCount)
            if ( inputCount == 0 ):
                self.startingNodes.append(nodeName)
        return self.startingNodes

    def dfsWithDominators(self, nodeName):
        #TODO
        return None

    def getLeavesFromStartNode(self, nodeName, filterList, exceptList):
        results = set()
        visitedNodes = set()
        myStack = list()
        myStack.append(nodeName)

        if ( len(self.adjGraph.get(nodeName, list())) == 0 ):
            return results

        while ( len(myStack) != 0 ):
            currentNode = myStack.pop()
            if ( currentNode not in visitedNodes):
                #self.logger.debug("Visiting node: " + currentNode)
                visitedNodes.add(currentNode)
                if ( len(self.adjGraph.get(currentNode, list())) != 0 ):
                    for node in self.adjGraph.get(currentNode, list()):
                        myStack.append(node)
                else:
                    if ( ( len(filterList) == 0 and len(exceptList) == 0 ) or ( len(filterList) > 0 and currentNode in filterList) or ( len(exceptList) > 0 and currentNode not in exceptList ) ):
                        results.add(currentNode)

        return results

    def accessibleFromStartNode(self, nodeName, filterList, exceptList):
        results = set()
        visitedNodes = set()
        myStack = list()
        myStack.append(nodeName)

        if ( len(self.adjGraph.get(nodeName, list())) == 0 ):
            return results

        while ( len(myStack) != 0 ):
            currentNode = myStack.pop()
            if ( currentNode not in visitedNodes):
                #self.logger.debug("Visiting node: " + currentNode)
                visitedNodes.add(currentNode)
                if ( ( len(filterList) == 0 and len(exceptList) == 0 ) or ( len(filterList) > 0 and currentNode in filterList) or ( len(exceptList) > 0 and currentNode not in exceptList ) ):
                    results.add(currentNode)
                if ( len(self.adjGraph.get(currentNode, list())) != 0 ):
                    for node in self.adjGraph.get(currentNode, list()):
                        myStack.append(node)

        return results


    def getSyscallFromStartNode(self, nodeName):
        results = set()
        visitedNodes = set()
        myStack = list()
        myStack.append(nodeName)

        if ( len(self.adjGraph.get(nodeName, list())) == 0 ):
            return results

        while ( len(myStack) != 0 ):
            currentNode = myStack.pop()
            if ( currentNode not in visitedNodes):
#                self.logger.debug("Visiting node: " + currentNode)
                visitedNodes.add(currentNode)
                if ( len(self.adjGraph.get(currentNode, list())) != 0 ):
                    for node in self.adjGraph.get(currentNode, list()):
                        myStack.append(node)
                else:
                    if ( currentNode.strip().startswith("syscall") ):
                        #self.logger.debug("getSyscallFromStartNode: currentNode: %s", currentNode)
                        currentNode = currentNode.replace("syscall","")
                        currentNode = currentNode.replace("(","")
                        currentNode = currentNode.replace(")","")
                        currentNode = currentNode.strip()
                        if ( not currentNode.startswith("%") ):
                            results.add(int(currentNode))

        return results

    def getSyscallFromStartNodeWithVisitedNodes(self, nodeName):
        results = set()
        visitedNodes = set()
        myStack = list()
        myStack.append(nodeName)

        if ( len(self.adjGraph.get(nodeName, list())) == 0 ):
            return results, visitedNodes

        while ( len(myStack) != 0 ):
            currentNode = myStack.pop()
            if ( currentNode not in visitedNodes):
#                self.logger.debug("Visiting node: " + currentNode)
                visitedNodes.add(currentNode)
                if ( len(self.adjGraph.get(currentNode, list())) != 0 ):
                    for node in self.adjGraph.get(currentNode, list()):
                        myStack.append(node)
                else:
                    if ( currentNode.strip().startswith("syscall") ):
                        #self.logger.debug("getSyscallFromStartNode: currentNode: %s", currentNode)
                        currentNode = currentNode.replace("syscall","")
                        currentNode = currentNode.replace("(","")
                        currentNode = currentNode.replace(")","")
                        currentNode = currentNode.strip()
                        if ( not currentNode.startswith("%") ):
                            results.add(int(currentNode))

        return results, visitedNodes

    def createGraphFromInput(self, inputFilePath, separator="->"):
        self.logger.debug("Running createGraphFromInput...")
        try:
            if ( os.path.isfile(inputFilePath) ):
                inputFile = open(inputFilePath, 'r')
                inputLine = inputFile.readline()
                while ( inputLine ):
                    if ( not inputLine.startswith("#") ):
                        splittedInput = inputLine.split(separator)
                        if ( len(splittedInput) == 2 ):
                            func1 = splittedInput[0].strip()
                            func2 = splittedInput[1].strip()
                            if ( func2.startswith("@") ):
                                func2 = func2[1:]
                            #self.logger.debug("Adding %s->%s", func1, func2)
                            self.addEdge(func1, func2)
                    else:
                        self.logger.warning("Graph: Skipping line starting with #: %s", inputLine)
                    inputLine = inputFile.readline()
                inputFile.close()
            else:
                self.logger.error("File doesn't exist: %s", inputFilePath)
                return -1                
        except Exception as e:
            self.logger.error("File doesn't exist: %s", inputFilePath)
            return -1
        return 0
    
    def createGraphFromInputWithFilter(self, inputFilePath, separator, calleeNameList):
        inputFile = open(inputFilePath, 'r')
        inputLine = inputFile.readline()
        while ( inputLine ):
            if ( not inputLine.startswith("#") ):
                splittedInput = inputLine.split(separator)
                if ( len(splittedInput) == 2 ):
                    func1 = splittedInput[0].strip()
                    func2 = splittedInput[1].strip()
                    if ( func2.startswith("@") ):
                        func2 = func2[1:]
                    #self.logger.debug("Adding %s->%s", func1, func2)
                    if ( func2 not in calleeNameList ):
                        self.addEdge(func1, func2)
                    else:
                        self.logger.warning("Skipping filter: %s->%s", func1, func2)
            else:
                self.logger.warning("Graph: Skipping line starting with #: %s", inputLine)
            inputLine = inputFile.readline()
        inputFile.close()

    def createConditionalControlFlowGraph(self, inputFilePath, keepConditionalEdges=True, separatorMap=None):
        #separatorMap: ["default":"->", "conditional":"-C->", "directfunc":"-F->", "indirectfunc": "-INDF->", "extfunc": "-ExtF->"]
        #In next iterations we might add the specific config option in the -C-> edge type
        '''
        currently our file has the following type of lines:
        F1|BB1->F1|BB2
        F1|BB2-C->F1|BB3
        F1|BB2-C->F1|BB4
        F1|BB4->F1|BB3
        F1|BB4-INDF->F3|BB1
        F1|BB4-F->F4|BB1
        F1|BB4-ExtF->strcmp
        '''
        #TODOs:
        #1. read and parse file and add nodes and edges corresponding to the file
        #2. 
        self.logger.info("Running createConditionalControlFlowGraph function...")
        if ( not separatorMap ):
            separatorMap = {"DEFAULT":"->", "CONDITIONAL":"-C->", "DIRECT":"-F->", "INDIRECT": "-INDF->", "EXT": "-ExtF->"}
        try:
            if ( os.path.isfile(inputFilePath) ):
                inputFile = open(inputFilePath, 'r')
                inputLine = inputFile.readline()
                while ( inputLine ):
                    inputLine = inputLine.strip()
                    self.logger.debug("adding line: %s", inputLine)
                    if ( inputLine.startswith("main") ):
                        self.logger.debug("adding line: %s", inputLine)
                    if ( not inputLine.startswith("#") ):
                        for separatorName, separator in separatorMap.items():
                            if ( separator in inputLine ):
                                splittedInput = inputLine.split(separator)
                                callerBB = splittedInput[0]
                                calleeBB = splittedInput[1]
                                if ( separatorName == "CONDITIONAL" ):
                                    if ( "true" in calleeBB or "then" in calleeBB ):
                                        if ( keepConditionalEdges ):
                                            self.addEdgeWithType(callerBB, calleeBB, separatorName + "-TRUE")
                                            #self.logger.debug("Skipping input line since it's probably the TRUE branch:\n%s", inputLine)
                                    else:
                                        self.addEdgeWithType(callerBB, calleeBB, separatorName + "-FALSE")
                                else:
                                    self.addEdgeWithType(callerBB, calleeBB, separatorName)
                    inputLine = inputFile.readline()
                inputFile.close()
            else:
                self.logger.error("File doesn't exist: %s", inputFilePath)
                return -1
        except Exception as e:
            self.logger.error("File doesn't exist: %s", inputFilePath)
            return -1

                
        

    #Deprecated
    def applyConditionalGraph(self, inputFilePath, separator):
        inputFile = open(inputFilePath, 'r')
        inputLine = inputFile.readline()
        while ( inputLine ):
            if ( not inputLine.startswith("#") ):
                splittedInput = inputLine.split(separator)
                if ( len(splittedInput) == 2 ):
                    caller = splittedInput[0].strip()
                    callee = splittedInput[1].strip()
                    if ( callee.startswith("@") ):
                        callee = callee[1:]
                    if ( not self.edgeTupleToId.get((caller, callee), None) ):
                        #self.logger.warning("Trying to change color of non-existent edge in initial graph, adding new edge")
                        self.addEdge(caller, callee)                        
                    self.edgeColor[self.edgeTupleToId[(caller, callee)]] = self.DIRECT
                elif ( len(splittedInput) == 3 ):
                    caller = splittedInput[0].strip()
                    condition = splittedInput[1].strip()
                    callee = splittedInput[2].strip()
                    if ( callee.startswith("@") ):
                        callee = callee[1:]
                    if ( not self.edgeTupleToId.get((caller, callee), None) ):
                        #self.logger.warning("Trying to change color of non-existent edge in initial graph, adding new edge")
                        self.addEdge(caller, callee)                        
                    self.edgeColor[self.edgeTupleToId[(caller, callee)]] = self.CONDITIONAL
                    self.edgeCondition[self.edgeTupleToId[(caller, callee)]] = condition
            else:
                self.logger.warning("Graph: Skipping line starting with #: %s", inputLine)
            inputLine = inputFile.readline()
        inputFile.close()

    def applyDirectGraph(self, inputFilePath, separator):
        inputFile = open(inputFilePath, 'r')
        inputLine = inputFile.readline()
        while ( inputLine ):
            if ( not inputLine.startswith("#") ):
                splittedInput = inputLine.split(separator)
                if ( len(splittedInput) == 2 ):
                    caller = splittedInput[0].strip()
                    callee = splittedInput[1].strip()
                    if ( callee.startswith("@") ):
                        callee = callee[1:]
                    if ( not self.edgeTupleToId.get((caller, callee), None) ):
                        #self.logger.warning("Trying to change color of non-existent edge in initial graph, adding new edge")
                        self.addEdge(caller, callee)                        
                    self.edgeColor[self.edgeTupleToId[(caller, callee)]] = self.DIRECT
                elif ( len(splittedInput) == 3 ):
                    caller = splittedInput[0].strip()
                    condition = splittedInput[1].strip()
                    callee = splittedInput[2].strip()
                    if ( callee.startswith("@") ):
                        callee = callee[1:]
                    if ( not self.edgeTupleToId.get((caller, callee), None) ):
                        #self.logger.warning("Trying to change color of non-existent edge in initial graph, adding new edge")
                        self.addEdge(caller, callee)                        
                    self.edgeColor[self.edgeTupleToId[(caller, callee)]] = self.DIRECT
                    self.edgeCondition[self.edgeTupleToId[(caller, callee)]] = condition
            else:
                self.logger.warning("Graph: Skipping line starting with #: %s", inputLine)
            inputLine = inputFile.readline()
        inputFile.close()

    def printAllPaths(self, startNode, endNode, limit=True):
        visitedNodes = dict()
        allPaths = set()
        tmpSet = set()
        startNode = startNode.strip()
        endNode = endNode.strip()
        for node in self.allNodes:
            if ( node == endNode ):
                self.logger.debug("node == endnode")
            node = node.strip()
            visitedNodes[node] = False
        visitedNodes[startNode] = True

        if ( limit ):
            self.printPath(startNode, endNode, "", visitedNodes, tmpSet, allPaths)
            self.logger.info("3nd level paths: %s", str(tmpSet))
        else:
            self.printPath(startNode, endNode, "", visitedNodes, None, allPaths)
        return allPaths

    def printPath(self, startNode, endNode, path, visitedNodes, limitedPaths=None, allPaths=None):
        newPath = path + "->" + startNode
        tmpStr = newPath
        secondDepthIndex = util.findNthOccurence(tmpStr, "->", 3)
        if ( limitedPaths != None and tmpStr[:secondDepthIndex] in limitedPaths ):
            return
        visitedNodes[startNode] = True
        currentNodeList = self.adjGraph.get(startNode, list())
        self.logger.debug("%s->", startNode)
        for node in currentNodeList:
            self.logger.debug("      %s", node)
            node = node.strip()
            if ( not visitedNodes[node] and node != endNode ):
                self.printPath(node, endNode, newPath, visitedNodes, limitedPaths, allPaths)
            elif ( node == endNode ):
                if ( limitedPaths != None):
                    tmpStr = newPath + "->" + node
                    secondDepthIndex = util.findNthOccurence(tmpStr, "->", 3)
                    limitedPaths.add(tmpStr[:secondDepthIndex])
                    self.logger.info("Adding %s to set", tmpStr[:secondDepthIndex])
                    print ( newPath + "->" + node )
                    allPaths.add(newPath + "->" + node)
                else:
                    print ( newPath + "->" + node )
                    allPaths.add(newPath + "->" + node)

#        visitedNodes[startNode] = False

    def toDotCfg(self, outputPath, nodes=None):
        dotFileStr = "digraph \"Call Graph\" {    label=\"Call Graph\"; \n"
        nodeStr = "{} [style=filled,color={},shape=record,shape=circle,label=\"{}\"];\n"
        edgeStr = "{} -> {}[color=black];\n"
        outputFile = open(outputPath, 'w')
        outputFile.write(dotFileStr)        

        if ( nodes == None ):
            self.extractStartingNodes()
            nodes = self.startingNodes

        for node in nodes:
            node = node.strip()
            if ( node != "" ):
                nodeFinalStr = nodeStr.format(node, self.nodeColor.get(node, self.INITIAL), node)
                outputFile.write(nodeFinalStr)
                for callee in self.adjGraph.get(node, list()):
                    if ( callee in nodes and self.nodeColor.get(callee, self.INITIAL) == self.VISITED):
                        edgeFinalStr = edgeStr.format(node, callee)
                        outputFile.write(edgeFinalStr)
        outputFile.write("}\n")
        outputFile.close()

    def setNodeColorToVisited(self, node):
        self.nodeColor[node] = self.VISITED

    def getNodeColor(self, node):
        return self.nodeColor.get(node, "")

    def getEdgeColor(self, caller, callee):
        if ( not self.edgeTupleToId.get((caller, callee), None) ):
            self.logger.error("Requested edge: %s -> %s doesn't exist!", caller, callee)
            return None
        return self.getEdgeColorById(self.edgeTupleToId[(caller, callee)])

    def getEdgeColorById(self, edgeId):
        return self.edgeColor[edgeId]
    
    def getEdgeType(self, caller, callee):
        if ( not self.edgeTupleToId.get((caller, callee), None) ):
            self.logger.error("Requested edge: %s -> %s doesn't exist!", caller, callee)
            return None
        return self.getEdgeTypeById(self.edgeTupleToId[(caller, callee)])

    def getEdgeTypeById(self, edgeId):
        return self.edgeColor[edgeId]

    def dumpToFile(self, filePath):
        outputFile = open(filePath, 'w')
        for srcNode, nodeList in self.adjGraph.items():
            for dstNode in nodeList:
                outputFile.write(srcNode + "->" + dstNode + "\n")
                outputFile.flush()
        outputFile.close()
        
