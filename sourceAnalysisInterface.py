from abc import ABC, abstractmethod

class SourceAnalysisInterface(ABC):

    @abstractmethod
    def getBinaries(self, binarySuperset=None):
        pass

    @abstractmethod
    def getLibraries(self, librarySuperset=None):
        pass
