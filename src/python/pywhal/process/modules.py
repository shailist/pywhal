import ctypes
import ctypes.wintypes
import os
from encodings import utf_8
from typing import Generator, TypeAlias, Union


FRIENDLY_MODULE_NAME: TypeAlias = Union[bytes, str]
MODULE_NAME: TypeAlias = ctypes.wintypes.LPCSTR
MODULE_HANDLE: TypeAlias = ctypes.wintypes.HMODULE
FRIENDLY_SYMBOL_NAME: TypeAlias = Union[int, bytes, str]
SYMBOL_NAME: TypeAlias = ctypes.wintypes.LPCSTR
SYMBOL_ADDRESS: TypeAlias = ctypes.wintypes.LPVOID  # This should be a function pointer, but it isn't necessary


class Module:
    def __init__(self, _module_handle: MODULE_HANDLE):
        self._module_handle = _module_handle
        self._module_path = None
        self._module_name = None

    def get_symbol(self, symbol_name: FRIENDLY_SYMBOL_NAME) -> int:
        symbol_name = _parse_symbol_name(symbol_name)
        symbol_address = _get_symbol(self._module_handle, symbol_name)
        return int(symbol_address) if symbol_address else 0

    @property
    def path(self) -> str:
        if self._module_path is None:
            module_name = _get_module_name(self._module_handle)
            self._module_path = utf_8.decode(module_name)[0]
        
        return self._module_path

    @property
    def name(self) -> str:
        if self._module_name is None:
            self._module_name = os.path.basename(self.path)
        
        return self._module_name

    @property
    def address(self) -> int:
        return self._module_handle.value or 0

    def __enter__(self):
        return self
         
    def __exit__(self, exc_type, exc_value, exc_traceback):
        Modules.unload_module(self._module_handle)

    def __getitem__(self, symbol_name: FRIENDLY_SYMBOL_NAME) -> int:
        return self.get_symbol(symbol_name)
    
    def __repr__(self) -> str:
        return f'<Module \'{self.name}\' @ {hex(self.address)}>'


class ModulesMeta(type):
    """
    Convenience metaclass to allow accessing Modules's functionality
    via square brackets syntax (Modules['kernel32']).
    """
    def __getitem__(cls, module_name: str) -> bytes:
        return Modules.get_module(module_name)
    
    def __iter__(self) -> Generator[Module, None, None]:
        yield from _iterate_modules()


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


TH32CS_SNAPMODULE = 0x00000008
ERROR_NO_MORE_FILES = 18
ERROR_INSUFFICIENT_BUFFER = 122
MAX_MODULE_NAME32 = 255
MAX_PATH = 260

MAX_LONG_PATH_LENGTH = 32767

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.wintypes.DWORD),
        ('th32ModuleID', ctypes.wintypes.DWORD),
        ('th32ProcessID', ctypes.wintypes.DWORD),
        ('GlblcntUsage', ctypes.wintypes.DWORD),
        ('ProccntUsage', ctypes.wintypes.DWORD),
        ('modBaseAddr', ctypes.wintypes.PBYTE),
        ('modBaseSize', ctypes.wintypes.DWORD ),
        ('hModule', ctypes.wintypes.HMODULE),
        ('szModule', ctypes.c_char * (MAX_MODULE_NAME32 + 1)),
        ('szExePath', ctypes.c_char * MAX_PATH)
    ]

LPMODULEENTRY32 = ctypes.POINTER(MODULEENTRY32)

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.restype = SYMBOL_ADDRESS
GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, SYMBOL_NAME]

GetModuleHandleA = ctypes.windll.kernel32.GetModuleHandleA
GetModuleHandleA.restype = ctypes.wintypes.HMODULE
GetModuleHandleA.argtypes = [ctypes.wintypes.LPCSTR]

GetModuleFileNameA = ctypes.windll.kernel32.GetModuleFileNameA
GetModuleFileNameA.restype = ctypes.wintypes.DWORD
GetModuleFileNameA.argtypes = [ctypes.wintypes.HMODULE, ctypes.wintypes.LPSTR, ctypes.wintypes.DWORD]

LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
LoadLibraryA.restype = ctypes.wintypes.HMODULE
LoadLibraryA.argtypes = [ctypes.wintypes.LPCSTR]

FreeLibrary = ctypes.windll.kernel32.FreeLibrary
FreeLibrary.restype = ctypes.wintypes.BOOL
FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]

CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]

Module32First = ctypes.windll.kernel32.Module32First
Module32First.restype = ctypes.wintypes.BOOL
Module32First.argtypes = [ctypes.wintypes.HANDLE, LPMODULEENTRY32]

Module32Next = ctypes.windll.kernel32.Module32Next
Module32Next.restype = ctypes.wintypes.BOOL
Module32Next.argtypes = [ctypes.wintypes.HANDLE, LPMODULEENTRY32]

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.restype = ctypes.wintypes.BOOL
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.restype = ctypes.wintypes.DWORD
GetLastError.argtypes = []


def _parse_symbol_name(symbol_name: FRIENDLY_SYMBOL_NAME) -> SYMBOL_NAME:
    if isinstance(symbol_name, str):
        symbol_name = utf_8.encode(symbol_name)[0]

    return SYMBOL_NAME(symbol_name)


def _get_symbol(module_handle: MODULE_HANDLE, symbol_name: SYMBOL_NAME) -> SYMBOL_ADDRESS:
    symbol_address = GetProcAddress(module_handle, symbol_name)
    if not symbol_address:
        raise WindowsError(f'Could not get the address of the symbol \'{symbol_name}\'.')

    return SYMBOL_ADDRESS(symbol_address)


def _get_module_name(module_handle: MODULE_HANDLE) -> bytes:
    name_buffer = bytes(MAX_PATH)
    
    while (name_length := GetModuleFileNameA(module_handle, name_buffer, len(name_buffer))) >= len(name_buffer):
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER:
            raise WindowsError('Failed getting module name.')
        
        name_buffer = bytes(min(len(name_buffer) * 2, MAX_LONG_PATH_LENGTH))
    
    return name_buffer[:name_length]


def _parse_module_name(module_name: FRIENDLY_MODULE_NAME) -> MODULE_NAME:
    if isinstance(module_name, str):
        module_name = utf_8.encode(module_name)[0]

    return MODULE_NAME(module_name)
    

def _get_module(module_name: MODULE_NAME) -> MODULE_HANDLE:
    module_handle = GetModuleHandleA(module_name)
    if module_handle == 0:
        raise WindowsError(f'Could not find module \'{module_name}\'.')

    return MODULE_HANDLE(module_handle)


def _load_module(module_name: MODULE_NAME) -> MODULE_HANDLE:
    module_handle = LoadLibraryA(module_name)
    if not module_handle:
        raise WindowsError(f'Could not load module \'{module_name}\'.')

    return MODULE_HANDLE(module_handle)


def _unload_module(module_handle: MODULE_HANDLE) -> None:
    FreeLibrary(module_handle)


def _iterate_modules() -> Generator[Module, None, None]:
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)
    if not snapshot:
        raise WindowsError('Could not create modules snapshot.')
    
    try:
        module = MODULEENTRY32()
        module.dwSize = ctypes.sizeof(MODULEENTRY32)
        
        module_ptr = ctypes.pointer(module)
        
        if not Module32First(snapshot, module_ptr):
            raise WindowsError('Could not get first module.')
        
        yield Module(MODULE_HANDLE(module.hModule))
        
        while Module32Next(snapshot, module_ptr):
            yield Module(MODULE_HANDLE(module.hModule))
        
        if GetLastError() != ERROR_NO_MORE_FILES:
            raise WindowsError('Could not get next module.')
        
    finally:
        CloseHandle(snapshot)
