import ctypes
import ctypes.wintypes
import sys
from encodings import utf_8
from typing import TypeAlias, Union


if sys.platform == 'win32':
    FRIENDLY_MODULE_NAME: TypeAlias = Union[bytes, str]
    MODULE_NAME: TypeAlias = ctypes.wintypes.LPCSTR
    MODULE_HANDLE: TypeAlias = ctypes.wintypes.HMODULE
    FRIENDLY_SYMBOL_NAME: TypeAlias = Union[int, bytes, str]
    SYMBOL_NAME: TypeAlias = ctypes.wintypes.LPCSTR
    SYMBOL_ADDRESS: TypeAlias = ctypes.wintypes.LPVOID  # This should be a function pointer, but it isn't necessary
    
    GetProcAddress = ctypes.windll.kernel32.GetProcAddress
    GetProcAddress.restype = SYMBOL_ADDRESS
    GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, SYMBOL_NAME]

    GetModuleHandleA = ctypes.windll.kernel32.GetModuleHandleA
    GetModuleHandleA.restype = ctypes.wintypes.HMODULE
    GetModuleHandleA.argtypes = [ctypes.wintypes.LPCSTR]

    LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
    LoadLibraryA.restype = ctypes.wintypes.HMODULE
    LoadLibraryA.argtypes = [ctypes.wintypes.LPCSTR]

    FreeLibrary = ctypes.windll.kernel32.FreeLibrary
    FreeLibrary.restype = ctypes.wintypes.BOOL
    FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]


    def _parse_symbol_name(symbol_name: FRIENDLY_SYMBOL_NAME) -> SYMBOL_NAME:
        if isinstance(symbol_name, str):
            symbol_name = utf_8.encode(symbol_name)[0]

        return SYMBOL_NAME(symbol_name)


    def _get_symbol(module_handle: MODULE_HANDLE, symbol_name: SYMBOL_NAME) -> SYMBOL_ADDRESS:
        symbol_address = GetProcAddress(module_handle, symbol_name)
        if not symbol_address:
            raise WindowsError(f'Could not get the address of the symbol \'{module_name}\'.')

        return symbol_address


    def _parse_module_name(module_name: FRIENDLY_MODULE_NAME) -> MODULE_NAME:
        if isinstance(module_name, str):
            module_name = utf_8.encode(module_name)[0]

        return MODULE_NAME(module_name)
    

    def _get_module(module_name: MODULE_NAME) -> MODULE_HANDLE:
        module_handle = GetModuleHandleA(module_name)
        if module_handle == 0:
            raise WindowsError(f'Could not find module \'{module_name}\'.')

        return module_handle


    def _load_module(module_name: MODULE_NAME) -> MODULE_HANDLE:
        module_handle = LoadLibraryA(module_name)
        if not module_handle:
            raise WindowsError(f'Could not load module \'{module_name}\'.')

        return module_handle


    def _unload_module(module_handle: MODULE_HANDLE) -> None:
        FreeLibrary(module_handle)


else:
    raise NotImplementedError(f'Modules are not implemented for the \'{sys.platform}\' platform.')


class Module:
    def __init__(self, _module_handle: MODULE_HANDLE):
        self._module_handle = _module_handle

    def get_symbol(self, symbol_name: FRIENDLY_SYMBOL_NAME) -> int:
        symbol_name = _parse_symbol_name(symbol_name)
        symbol_address = _get_symbol(self._module_handle, symbol_name)
        return int(symbol_address) if symbol_address else 0

    def __enter__(self):
        return self
         
    def __exit__(self, exc_type, exc_value, exc_traceback):
        Modules.unload_module(self._module_handle)

    def __getitem__(self, symbol_name: FRIENDLY_SYMBOL_NAME) -> int:
        return self.get_symbol(symbol_name)



class ModulesMeta(type):
    """
    Convenience metaclass to allow accessing Modules's functionality
    via square brackets syntax (Modules['kernel32']).
    """
    def __getitem__(cls, module_name: str) -> bytes:
        return Modules.get_module(module_name)


class Modules(metaclass=ModulesMeta):
    """
    Class for accessing and manipulating the modules of the process.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """
    def __new__(cls):
        raise TypeError('The Modules class cannot be instantiated')

    @classmethod
    def get_module(cls, module_name: FRIENDLY_MODULE_NAME) -> Module:
        module_name = _parse_module_name(module_name)
        return Module(_get_module(module_name))

    @classmethod
    def load_module(cls, module_name: FRIENDLY_MODULE_NAME) -> Module:
        module_name = _parse_module_name(module_name)
        return Module(_load_module(module_name))

    @classmethod
    def unload_module(cls, module: Union[FRIENDLY_MODULE_NAME, Module, MODULE_HANDLE]) -> None:
        if isinstance(module, FRIENDLY_MODULE_NAME):
            module = cls.get_module(module)
        
        if isinstance(module, Module):
            module = module._module_handle

        _unload_module(module)
