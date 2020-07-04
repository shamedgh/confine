import os, sys
import subprocess
import signal
import time
import logging
from datetime import datetime
import shutil
from enum import Enum
import pickle

# http://stackoverflow.com/questions/3173320/text-progress-bar-in-the-console/27871113
class ProgressBar(object):
    DEFAULT_BAR_LENGTH = 50
    DEFAULT_CHAR_ON  = '>'
    DEFAULT_CHAR_OFF = ' '

    def __init__(self, end, start=0):
        self.end    = end
        self.start  = start
        self._barLength = self.__class__.DEFAULT_BAR_LENGTH

        self.setLevel(self.start)
        self._plotted = False

    def setLevel(self, level):
        self._level = level
        if level < self.start:  self._level = self.start
        if level > self.end:    self._level = self.end

        self._ratio = float(self._level - self.start) / float(self.end - self.start)
        self._levelChars = int(self._ratio * self._barLength)

    def plotProgress(self):
        tab = '\t'
        sys.stdout.write("\r%s%3i%% [%s%s]" %(
            tab*5, int(self._ratio * 100.0),
            self.__class__.DEFAULT_CHAR_ON  * int(self._levelChars),
            self.__class__.DEFAULT_CHAR_OFF * int(self._barLength - self._levelChars),
        ))
        sys.stdout.flush()
        self._plotted = True

    def setAndPlot(self, level):
        oldChars = self._levelChars
        self.setLevel(level)
        if (not self._plotted) or (oldChars != self._levelChars):
            self.plotProgress()

    def __add__(self, other):
        assert type(other) in [float, int], "can only add a number"
        self.setAndPlot(self._level + other)
        return self

    def __sub__(self, other):
        return self.__add__(-other)

    def __iadd__(self, other):
        return self.__add__(other)

    def __isub__(self, other):
        return self.__add__(-other)

    def finish(self):
        sys.stdout.write("\n")

# http://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
class ColorFormatter(logging.Formatter):
    FORMAT = ("%(asctime)s [%(levelname)-18s] %(message)s "
              "($BOLD%(filename)s$RESET:%(lineno)d)")

    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

    RESET_SEQ = "\033[0m"
    COLOR_SEQ = "\033[1;%dm"
    BOLD_SEQ = "\033[1m"

    COLORS = {
      'WARNING': GREEN,
      'INFO': YELLOW,
      'DEBUG': BLUE,
      'CRITICAL': RED,
      'ERROR': RED
    }

    def formatter_msg(self, msg, use_color = True):
        if use_color:
            msg = msg.replace("$RESET", self.RESET_SEQ).replace("$BOLD", self.BOLD_SEQ)
        else:
            msg = msg.replace("$RESET", "").replace("$BOLD", "")
        return msg

    def __init__(self, use_color=True):
        msg = self.formatter_msg(self.FORMAT, use_color)
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in self.COLORS:
            fore_color = 30 + self.COLORS[levelname]
            levelname_color = self.COLOR_SEQ % fore_color + levelname + self.RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)

class BinaryLang(Enum):
    CCPP = ".note.gnu.build-i"
    Go  = ".note.go.buildid"

def buildLookupTbl(cntInfo):
    '''
    Build the mapping table
        The location of cntInfo itself represents the index of the parent
        Relax the mappings to contain which child corresponds to which parent
    Example
        cntInfo [2,3] -> {0:0, 1:0, 2:1, 3:1, 4:1}
        The first two children map to the parent index 0,
          and the next three map to the parent index 1
        Say 'cntInfo' contains how many function each object contains;
          The first object has two functions and the second has three.
    :param cntInfo: list()
    :return:
    '''

    lookup_t = dict()
    child_idx = 0
    for parent_idx, child_cnt in enumerate(cntInfo):
        while child_cnt > 0:
            lookup_t[child_idx] = parent_idx
            child_idx += 1
            child_cnt -= 1

    return lookup_t

def getOffsetFrom(targetCnt, sizeLayout):
    '''
    Compute relative addresses from corresponding layout
    Example:
        targetCnt  : [3, 1]                   # num of funcs in each obj
        sizeLayout : [0x60, 0x40, 0x20, 0x20] # sizes of each func
        offsetsFrom: [0x0, 0x60, 0xa0, 0xc0]  # returns func offsets from the objs
    :param targetCnt:
    :param sizeLayout:
    :return:
    '''

    offsetsFrom = list()
    assert sum(targetCnt) == len(sizeLayout), "Size does NOT match!"

    layoutIdx = 0
    for tc in targetCnt:
        for targetIdx in range(tc):
            # The beginning offset from the layout
            if targetIdx == 0:
                offsetsFrom.append(0x0)
            # The offset has to be the sum of the previous object sizes
            else:
                offsetsFrom.append(offsetsFrom[-1] + sizeLayout[layoutIdx - 1])
            layoutIdx += 1

    return offsetsFrom

def getOffset(sizeLayout):
    '''
    Assume all size distributions are from the first reorder object to the end
        Object / Functions / Basic Blocks
        sizes of all objs = sizes of all funcs = sizes of all BBs
    :param sizeLayout:
    :return:
    '''

    offset = [0x0]
    for i in range(1, len(sizeLayout)):
        offset.append(offset[-1] + sizeLayout[i-1])
    return offset

def computeRelaOffset(offset, relaOffset):
    ''' Return relative offsets from the given offset '''
    return [x + relaOffset for x in offset]

def toSigned32(n):
    ''' Return a 32-bit signed number for n '''
    n = n & 0xffffffff
    return n | (-(n & 0x80000000))

def hexPrint(target):
    ''' Help the output with a simple hex format '''
    return [hex(x) for x in target]

def toHex(val, bits=32):
    ''' Help the output for the two's complement representation '''
    return hex((val + (1 << bits)) % (1 << bits))

def _show_elapsed(start, end):
    elapsed = end - start
    time_format = ''
    if elapsed > 86400:
        time_format += str(int(elapsed // 86400)) + ' day(s) '
        elapsed = elapsed % 86400
    if elapsed > 3600:
        time_format += str(int(elapsed // 3600)) + ' hour(s) '
        elapsed = elapsed % 3600
    if elapsed > 60:
        time_format += str(int(elapsed // 60)) + ' min(s) '
        elapsed = elapsed % 60
    time_format += str(round(elapsed, 3)) + ' sec(s)'
    return time_format

def isExe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def readLibrariesWithLdd(elfPath):
    """
    Read the output from ldd command, which are all libraries employed by the given elf file
    $ ldd /bin/ls
        linux-vdso.so.1 =>  (0x00007ffda6fb7000)
        libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f74f0e15000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f74f0a4b000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f74f07db000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f74f05d7000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f74f1037000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f74f03ba000)
    :param elfPath:
    :return:
    """
    cmd = "ldd " + elfPath
    (returncode, out, err) = runCommand(cmd)
    if ( returncode != 0 ):
        print("ldd error: " + err)
        return dict()

    #proc = subprocess.Popen(["ldd", elfPath], stdout=subprocess.PIPE)
    #stdout = proc.communicate()[0]
    loadings = dict()

    # Read all imports and exports per each library
    for lib in out.split('\n\t'):
        # Exclude a virtual dynamically linked shared object(VDSO) and a dynamic loader(DL)
        if 'linux-vdso' not in lib and 'ld-linux' not in lib:
            try:
                libname, libpath = lib.split(" => ")
                libname = libname.split(".")[0]         # Library name only w/o version
                libpath = libpath.split("(")[0].strip() # Discard the address
                loadings[libname] = libpath

            except:
                logging.critical("Parsing Error with %s outcome!" % ("ldd"))
                logging.critical("Trying to extract libraries with objdump!")
                loadings = readLibrariesWithObjdump(elfPath)

    return loadings

def readLibrariesWithObjdump(elfPath):
    """
    Read the output from objdump -p temp/nginx | grep NEEDED command, which are all libraries employed by the given elf file
    $ objdump -p vsftpd | grep NEEDED
        NEEDED               libwrap.so.0
        NEEDED               libcrypt.so.1
        NEEDED               libcap.so.2
        NEEDED               libssl.so.1.0.0
        NEEDED               libcrypto.so.1.0.0
        NEEDED               libpam.so.0
        NEEDED               libc.so.6
    :param elfPath:
    :return:
    """
    proc1 = subprocess.Popen([C.OBJDUMP, C.OBJDUMP_OPT, elfPath], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(["grep", "NEEDED"], stdin=proc1.stdout, stdout=subprocess.PIPE)
    proc1.stdout.close()
    stdout = proc2.communicate()[0]
    loadings = dict()

    # Read all imports and exports per each library
    for lib in stdout.split('\n'):
        libname = lib.replace("NEEDED","").strip()
        libname = libname.split(".")[0]
        # Exclude a virtual dynamically linked shared object(VDSO) and a dynamic loader(DL)
        if 'linux-vdso' not in libname and 'ld-linux' not in libname and not libname == '':
            try:
                loadings[libname] = libname

            except:
                logging.critical("Parsing Error with %s outcome!" % (C.OBJDUMP))

    return loadings

def readLibrariesWithObjdumpComplete(elfPath):
    """
    Read the output from objdump -p temp/nginx | grep NEEDED command, which are all libraries employed by the given elf file
    $ objdump -p vsftpd | grep NEEDED
        NEEDED               libwrap.so.0
        NEEDED               libcrypt.so.1
        NEEDED               libcap.so.2
        NEEDED               libssl.so.1.0.0
        NEEDED               libcrypto.so.1.0.0
        NEEDED               libpam.so.0
        NEEDED               libc.so.6
    :param elfPath:
    :return:
    """
    proc1 = subprocess.Popen([C.OBJDUMP, C.OBJDUMP_OPT, elfPath], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(["grep", "NEEDED"], stdin=proc1.stdout, stdout=subprocess.PIPE)
    proc1.stdout.close()
    stdout = proc2.communicate()[0]
    libSet = set()

    # Read all imports and exports per each library
    stdout = str(stdout.decode("utf-8"))
    for lib in stdout.split('\n'):
        libname = lib.replace("NEEDED","").strip()
        #libname = libname.split(".")[0]
        libname = libname.strip()
        # Exclude a virtual dynamically linked shared object(VDSO) and a dynamic loader(DL)
        if 'linux-vdso' not in libname and 'ld-linux' not in libname and not libname == '':
            try:
                libSet.add(libname)
            except:
                logging.critical("Parsing Error with %s outcome!" % (C.OBJDUMP))

    return libSet

def extractDynamicHeader(filePath):
    cmd = "objdump -p {} | grep NEEDED"
    cmd = cmd.format(filePath)
    returncode, out, err = runCommand(cmd)
    return out

def extractHeaderSection(filePath, logger):
    cmd = "readelf -S " + filePath
    returncode, out, err = runCommand(cmd)
#    if ( returncode != 0 ):
#        if ( logger ):
#            logger.error("Error running cmd: %s error: %s", cmd, err)
#        else:
#            print("Error running cmd: %s error: %s", cmd, err)
    return out

def isElf(filePath):
    return extractHeaderSection(filePath, None) != ""

def getUtilPath(util):
    proc = subprocess.Popen([C.WHICH, util], stdout=subprocess.PIPE)
    stdout = proc.communicate()[0]
    return stdout.strip()

def getNameFromPath(path):
    return os.path.split(path)[1].split('.')[0]

def getNameWithExtFromPath(path):
    return os.path.split(path)[1]

def countRefToNops(sectionData, fixupInfo):
    nops = [
            '\x90',
            '\x66\x90',
            '\x0f\x1f\x00',
            '\x0f\x1f\x40\x00',
            '\x0f\x1f\x44\x00\x00',
            '\x66\x0f\x1f\x44\x00\x00',
            '\x0f\x1f\x80\x00\x00\x00\x00',
            '\x0f\x1f\x84\x00\x00\x00\x00\x00',
            '\x66\x0f\x1f\x84\x00\x00\x00\x00\x00',
            '\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00',
            '\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00',
            '\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00',
            '\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00',
            '\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00',
            '\x66\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00',
            ]

    refToOffset = fixupInfo.refTo - (fixupInfo.VA - fixupInfo.offset)

    # Intel processor could have up to 15 bytes multibyte nop.
    for i in range(len(nops)):
        if sectionData[refToOffset:refToOffset + i + 1] == nops[i]:
            return i + 1

    return -1

'''def getBBLsFromIDA():
    import idautils, idaapi
    BBLs = []
    sizes = []
    for func in idautils.Functions():
        blocks_in_func = idaapi.FlowChart(idaapi.get_func(func))
        BBLs.append([BBL.startEA for BBL in blocks_in_func])
        sizes.append([BBL.endEA - BBL.startEA for BBL in blocks_in_func])
    print [hex(x) for x in sorted(reduce(lambda x,y: x+y, BBLs))]
    print sum(reduce(lambda x,y: x+y, sizes))'''

def getLibNameFromDpkgOutput(dpkgOutput):
    """
    Read file with each library mapped to it's source (this should be provided by the user in the following format:
    libxau6:amd64: /usr/lib/x86_64-linux-gnu/libXau.so.6.0.0
    libxau6:amd64: /usr/lib/x86_64-linux-gnu/libXau.so.6
    :return:
    """
    outline = dpkgOutput.splitlines()[0]
    print (outline)
    if ( ": " in outline ):
        libname, path = outline.split(": ")
    else:
        libname = ""
    return libname

def readLibrarySourcePathFromFile(libMapFilePath, ignoreList):
    """
    Read file with each library mapped to it's source (this should be provided by the user in the following format:
    libaprutil-1.so.0=>/home/hamed/Documents/StonyBrookUniversity/Hexlab/auto-instrumentation/intel-mpk/openssl-1.0.1f.pdomversion
    :return:
    """
    libMap = dict()
    with open(libMapFilePath, "r") as libMapFile:
        for libline in libMapFile:
            if "=>" in libline:
                libname, libsrcpath = libline.split(" => ")
                if ( libname.strip() not in ignoreList ):
                    libMap[libname.strip()] = libsrcpath.strip()
    return libMap

def uncommentLine(inputLine):
    return inputLine[inputLine.rfind("#")+1:]

def makeFileBackup(filePath):
    os.rename(os.path.realpath(filePath), os.path.realpath(filePath) + ".configmapbak")
    return filePath + ".configmapbak"

def makeFileBackupWithExt(filePath, extensionStr):
    os.rename(os.path.realpath(filePath), os.path.realpath(filePath) + extensionStr)
    return filePath + extensionStr

def retrieveFileBackup(backupFilePath, originalFilePath):
    os.rename(os.path.realpath(backupFilePath), os.path.realpath(originalFilePath))

def writeConfigToFile(configFilePath, configString):
    f = open(configFilePath, "w")
    f.write(configString)
    f.close()

def pkillProcess(pid, exeName):
    os.kill(pid, signal.SIGINT)
    exeCmd = "pkill " + exeName
    (returncode, out, err) = runCommand(exeCmd)
    if ( returncode != 0 ):
        print("pkillProcess error: " + err)
        return False
    return True

def getSrcFileNames(diffOutput):
#    print ("diff: " + diffOutput)
    splittedDiff = diffOutput.splitlines()
    srcFileNameSet = set()
    for diffLine in splittedDiff:
        if ( diffLine.startswith("<") and not diffLine.startswith("< TOTAL") ):
            srcFileName = diffLine.split()[1]
#            print ("srcFileName: " + srcFileName)
            srcFileNameSet.add(srcFileName)
    return srcFileNameSet

def getIncludesFromSrcFile(includeSet, srcCodePath, srcFileName):
    for line in open(srcCodePath + srcFileName):
        if "#include" in line:
            fileName = line.split()[1]
            fileName = fileName.replace("<", "")
            fileName = fileName.replace(">", "")
#            print ("line: " + line + " fileName: " + fileName)
            includeSet.add(fileName)
    return includeSet

def writeDictToFile(inputDict, filePath):
    myFile = open(filePath, 'w')
    myFile.write(str(inputDict))
    myFile.close()

def writeDictToFileWithPickle(inputDict, filePath):
    myFile = open(filePath, 'wb')
    pickle.dump(inputDict, myFile, pickle.HIGHEST_PROTOCOL)
    myFile.close()

def readDictFromFileWithPickle(filePath):
    myFile = open(filePath, 'rb')
    myDict = pickle.load(myFile)
    return myDict

def readDictFromFile(filePath):
    myFile = open(filePath, 'r')
    dictStr = myFile.read()
    myDict = eval(dictStr)
    myFile.close()
    return myDict

def runCommand(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #print("running cmd: " + cmd)
    #proc.wait()
    (out, err) = proc.communicate()
    outStr = str(out.decode("utf-8"))
    errStr = str(err.decode("utf-8"))
    #print("finished running cmd: " + cmd)
    return (proc.returncode, outStr, errStr)
    #return (proc.returncode, out, err)

def runCommandWithoutWait(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc

def extractImportedFunctionsFromLibc(fileName, logger):
    return extractImportedFunctions(fileName, logger, True)

def extractImportedFunctions(fileName, logger, libcOnly=False):
    if ( libcOnly ):
        cmd = "objdump -T " + fileName + " | grep \"UND\" | grep -i libc | awk '{print $5,$6}'"
    else:
        cmd = "objdump -T " + fileName + " | grep \"UND\" | awk '{print $5,$6}'"
    if ( logger ):
        logger.debug("Running command: %s", cmd)
    returncode, out, err = runCommand(cmd)
    if ( returncode != 0 ):
        if logger:
            logger.error("Error in extracting imported functions: %s", err)
        return None
#    out = str(out.decode("utf-8"))
#    err = str(err.decode("utf-8"))
    functionList = []
    splittedOut = out.splitlines()
    for line in splittedOut:
        if ( len(line.split()) > 1 ):
            line = line.split()[1]
        functionList.append(line.strip())
    return functionList

def extractExportedFunctions(fileName, logger):
    cmd = "objdump -T " + fileName + " | grep \"DF\" | grep -v \"UND\" | awk '{print $6,$7}'"
    if ( logger ):
        logger.debug("Running command: %s", cmd)
    returncode, out, err = runCommand(cmd)
    if ( returncode != 0 ):
        if logger:
            logger.error("Error in extracting imported functions: %s", err)
        return None
#    out = str(out.decode("utf-8"))
#    err = str(err.decode("utf-8"))
    functionList = []
    splittedOut = out.splitlines()
    for line in splittedOut:
        if ( len(line.split()) > 1 ):
            line = line.split()[1]
        functionList.append(line.strip())
    return functionList

def extractAllFunctions(fileName, logger):
    cmd = "objdump -T " + fileName + " | awk '{print $6,$7}'"
    if ( logger ):
        logger.debug("Running command: %s", cmd)
    returncode, out, err = runCommand(cmd)
    if ( returncode != 0 ):
        if logger:
            logger.error("Error in extracting imported functions: %s", err)
        return None
#    out = str(out.decode("utf-8"))
#    err = str(err.decode("utf-8"))
    functionList = []
    splittedOut = out.splitlines()
    for line in splittedOut:
        if ( len(line.split()) > 1 ):
            line = line.split()[1]
        functionList.append(line.strip())
    return functionList

def extractLibcSyscalls(fileName, logger):
    cmd = "objdump -d " + fileName + " | grep \"syscall@plt\" | wc -l"
    returncode, out, err = runCommand(cmd)
    if ( returncode != 0 ):
        if logger:
            logger.error("Error in extracting libc syscalls: %s", err)
        return 0
    return int(out)

def extractDirectSyscalls(fileName, logger):
    cmd = "objdump -d " + fileName + " | grep syscall | grep -v \"syscall@plt\" | wc -l"
    returncode, out, err = runCommand(cmd)
    if ( returncode != 0 ):
        if logger:
            logger.error("Error in extracting direct syscalls: %s", err)
        return 0
    return int(out)

def getCmdRetrieveAllShellScripts(folder):
    return "/bin/bash -c \"find " + folder + " | xargs file | grep shell\""

def getCmdRetrieveAllBinaries(folder):
    #The one with grep x-executable left out some of the binaries which had x-shared even though they were binaries
    #return "/bin/bash -c \"find " + folder + " -type f -executable -exec file -i '{}' \; | grep 'x-executable; charset=binary'\""
    return "/bin/bash -c \"find " + folder + " -type f -executable -exec file -i '{}' \; | grep 'application'\""

def getStrTime(nowTime):
    timeStr = str(nowTime.month) + "/" + str(nowTime.day) + "/" + str(nowTime.year) + " " + str(nowTime.hour) + ":" + str(nowTime.minute) + ":" + str(nowTime.second)
    return timeStr

def deleteAllFilesInFolder(folder, logger):
    for the_file in os.listdir(folder):
        file_path = os.path.join(folder, the_file)
        try:
            if os.path.isfile(file_path):
                logger.debug("deleting %s", file_path)
                os.unlink(file_path)
            #elif os.path.isdir(file_path): shutil.rmtree(file_path)
        except Exception as e:
            if ( logger ):
                logger.error("Error deleting file: %s", e)
            return False
    return True

def deleteFolder(folder, logger):
    if ( logger ):
        logger.warning("Deleting %s", folder)
    else:
        print("Deleting " + folder)
    return shutil.rmtree(folder)

def isFolder(filePath):
    return os.path.isdir(filePath)

def repeatColumn(filePath, separator, fieldNumber):
    myFile = open(filePath, 'r')
    line = myFile.readline()
    while ( line ):
        splittedLine = line.split(";")
        outputLine = ""
        index = 0
        while ( index < len(splittedLine) ):
            outputLine += splittedLine[index].strip()+ ";"
            if ( index == fieldNumber ):
                outputLine += splittedLine[index].strip() + ";"
            index += 1
        print (outputLine)
        line = myFile.readline()

def isGo(filePath, logger):
    headerSection = extractHeaderSection(filePath, logger)
    if ( headerSection.strip() != "" ):
        if ( BinaryLang.Go.value in headerSection ):
            return True
    return False

def extractCommandArgument(command, argument):
    splittedCommand = command.split()
    forIndex = 0
    while ( forIndex < len(splittedCommand) ):
        if ( splittedCommand[forIndex] == argument and forIndex < len(splittedCommand) - 1 ):
            return splittedCommand[forIndex+1]
        forIndex += 1
    return None

def htmlParseExtractFirstTagWithAttr(soup, tag, attrDict):
    if ( soup ):
        attrComplete = soup.find(tag, attrDict)
    return attrComplete

def htmlParseExtractTagWithAttr(soup, tag, attrDict):
    if ( soup ):
        attrList = soup.find_all(tag, attrDict)
    return attrList

def htmlParseExtractLinks(soup, websiteUrl, urlFilterList=None):
    urlList = list()
    if ( soup ):
        allLinks = soup.find_all('a')
        for aLink in allLinks:
            link = aLink.get('href', None)
            if ( link ):
                if ( urlFilterList ):
                    for urlFilter in urlFilterList:
                        if ( urlFilter in link ):
                            if ( not link.startswith("http") ):
                                link = websiteUrl + link
                            urlList.append(link)
                else:
                    if ( not link.startswith("http") ):
                        link = websiteUrl + link
                    urlList.append(link)
    return urlList

def findNthOccurence(inputStr, searchStr, n):
    parts= inputStr.split(searchStr, n+1)
    if len(parts)<=n+1:
        return -1
    return len(inputStr)-len(parts[-1])-len(searchStr)

def usesMusl(folder):
    #return True
    for fileName in os.listdir(folder):
        if ( "musl" in fileName ):
            return True
    return False

def convertBytes(num):
    """
    this function will convert bytes to MB.... GB... etc
    """
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0

def convertStrListToList(listStr):
    listStr = listStr.replace("{", "")
    listStr = listStr.replace("}", "")
    listStr = listStr.replace(" ", "")
    return listStr.split(",")

def cleanStrList(listStr):
    listStr = str(listStr)
    listStr = listStr.replace("{", "")
    listStr = listStr.replace("}", "")
    listStr = listStr.replace("'", "")
    listStr = listStr.replace('"', '')
    return listStr

def getAvailableSystemMemory():
    from psutil import virtual_memory
    mem = virtual_memory()
    return mem.available

def getTotalSystemMemory():
    from psutil import virtual_memory
    mem = virtual_memory()
    return mem.total

def getAvailableSystemMemoryInMB():
    return getAvailableSystemMemory()/(1000000)

def getTotalSystemMemoryInMB():
    return getTotalSystemMemory()/(1000000)

if __name__ == '__main__':
    # Use this util inside IDA Pro only (alt+F7 -> script file)
    getBBLsFromIDA()

