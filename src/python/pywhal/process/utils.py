import os
import re
from .modules import Modules, Module
from .processes import Processes
from .._internal.windows_definitions import *


PYTHON_DLL_PATTERN = re.compile(r'^python3\d+\.dll$')


class Utils:
    """
    Class contianing various utilities for processes.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """
    def __new__(cls):
        raise TypeError('The Utils class cannot be instantiated.')
    
    @staticmethod
    def get_python_dll() -> Module:
        """
        Returns the python3.x.dll module currently being used by the process.
        If there are multiple Python DLLs loaded into the process, returns the first one.
        """
        for module in Modules:
            if PYTHON_DLL_PATTERN.match(module.name):
                return module
        
        raise LookupError('Could not find a loaded python DLL (wtf).')

    @staticmethod
    def inject_dll_into_process(pid: int, dll_path: str) -> None:
        """
        Injects the DLL at the given path into the process.
        """
        _inject_dll_into_process(pid, dll_path)


INJECTION_PROCESS_ACCESS_RIGHTS = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE

        
def _inject_dll_into_process(pid: int, dll_path: str) -> None:
    if not os.path.exists(dll_path):
        raise FileNotFoundError(f'Could not find file at \'{dll_path}\'.')
    
    dll_path = os.path.abspath(dll_path)
    
    process = Processes.get_process(pid, INJECTION_PROCESS_ACCESS_RIGHTS)
    kernel32 = Modules.get_module()

    import pefile

