from typing import Type
from .library.process import Process, CurrentProcess
from .library.process_memory import ProcessMemory
from .library.process_modules import ProcessModules
from .library.hooks import Hooks


class _CurrentProcessAPI:
    """
    pywhal API for the current process.
    """
    def __init__(self):
        self._process = CurrentProcess
        self._memory = ProcessMemory(CurrentProcess)
        self._modules = ProcessModules(CurrentProcess)
        self._hooks = Hooks
    
    @property
    def process(self) -> Process:
        return self._process
    
    @property
    def memory(self) -> ProcessMemory:
        return self._memory
    
    @property
    def modules(self) -> ProcessModules:
        return self._modules
    
    @property
    def hooks(self) -> Type[Hooks]:
        return self._hooks


CurrentProcessAPI = _CurrentProcessAPI()
