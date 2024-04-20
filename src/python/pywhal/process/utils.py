import re
from .modules import Modules, Module


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

