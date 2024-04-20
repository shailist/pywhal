import ctypes
import ctypes.wintypes
import os
from encodings import utf_8
from typing import Generator, Optional, Union
from .._internal.windows_definitions import *


class Module:
    def __init__(self, process_handle: ctypes.wintypes.HANDLE, module_handle: ctypes.wintypes.HMODULE,
                 module_path: Optional[str] = None, module_name: Optional[str] = None):
        self._process_handle = process_handle
        self._module_handle = module_handle
        self._module_path = module_path
        self._module_name = module_name

    def get_symbol(self, symbol_name: Union[int, bytes, str]) -> int:
        symbol_name = _parse_symbol_name(symbol_name)
        symbol_address = _get_symbol(self._process_handle, self._module_handle, symbol_name)
        return int(symbol_address) if symbol_address else 0

    @property
    def path(self) -> str:
        if self._module_path is None:
            module_name = _get_module_name(self._process_handle, self._module_handle)
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
        _unload_module(self._process_handle, self._module_handle)

    def __getitem__(self, symbol_name: Union[int, bytes, str]) -> int:
        return self.get_symbol(symbol_name)
    
    def __repr__(self) -> str:
        return f'<Module \'{self.name}\' @ {hex(self.address)}>'


class ModulesMeta(type):
    """
    Convenience metaclass to allow accessing Modules's functionality
    via square brackets syntax (Modules['kernel32']).
    """
    def __getitem__(cls, module_name: str) -> Module:
        return Modules.get_module(module_name)
    
    def __iter__(cls) -> Generator[Module, None, None]:
        yield from Modules.iterate_modules()


class Modules(metaclass=ModulesMeta):
    """
    Class for accessing and manipulating the modules of the process.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """
    def __new__(cls):
        raise TypeError('The Modules class cannot be instantiated.')

    @classmethod
    def get_module(cls, module_name: Union[bytes, str]) -> Module:
        module_name = _parse_module_name(module_name)
        return Module(_get_module(module_name))

    @classmethod
    def load_module(cls, module_name: Union[bytes, str]) -> Module:
        module_name = _parse_module_name(module_name)
        return Module(CurrentProcess, _load_module(module_name))

    @classmethod
    def unload_module(cls, module: Union[Union[bytes, str], Module, ctypes.wintypes.HMODULE]) -> None:
        if isinstance(module, Union[bytes, str]):
            module = cls.get_module(module)
        
        if isinstance(module, Module):
            module = module._module_handle

        _unload_module(module)
    
    @classmethod
    def iterate_modules(cls, process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> Generator[Module, None, None]:
        yield from _iterate_modules(process_handle)


def _parse_symbol_name(symbol_name: Union[int, bytes, str]) -> ctypes.wintypes.LPCSTR:
    if isinstance(symbol_name, str):
        symbol_name = utf_8.encode(symbol_name)[0]

    return ctypes.wintypes.LPCSTR(symbol_name)


def _get_symbol(process_handle: ctypes.wintypes.HANDLE, module_handle: ctypes.wintypes.HMODULE, symbol_name: ctypes.wintypes.LPCSTR) -> FARPROC:
    if GetProcessId(process_handle) != CurrentProcessId:
        # TODO: Implement
        raise NotImplementedError('Getting symbols from another processes is not supported')
    
    symbol_address = GetProcAddress(module_handle, symbol_name)
    if not symbol_address:
        raise WindowsError(f'Could not get the address of the symbol \'{symbol_name}\'.')

    return FARPROC(symbol_address)


def _get_module_name(process_handle: ctypes.wintypes.HANDLE, module_handle: ctypes.wintypes.HMODULE) -> bytes:
    name_buffer = bytes(MAX_PATH)
    
    while (name_length := GetModuleFileNameExA(process_handle, module_handle, name_buffer, len(name_buffer))) >= len(name_buffer):
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER:
            raise WindowsError('Failed getting module name.')
        
        name_buffer = bytes(min(len(name_buffer) * 2, MAX_LONG_PATH_LENGTH))
    
    if name_length == 0:
        raise WindowsError('Failed getting module name.')
    
    return name_buffer[:name_length]


def _parse_module_name(module_name: Union[bytes, str]) -> ctypes.wintypes.LPCSTR:
    if isinstance(module_name, str):
        module_name = utf_8.encode(module_name)[0]

    return ctypes.wintypes.LPCSTR(module_name)
    

def _get_module(module_name: ctypes.wintypes.LPCSTR) -> ctypes.wintypes.HMODULE:
    module_handle = GetModuleHandleA(module_name)
    if module_handle == 0:
        raise WindowsError(f'Could not find module \'{module_name}\'.')

    return ctypes.wintypes.HMODULE(module_handle)


def _load_module(module_name: ctypes.wintypes.LPCSTR) -> ctypes.wintypes.HMODULE:
    module_handle = LoadLibraryA(module_name)
    if not module_handle:
        raise WindowsError(f'Could not load module \'{module_name}\'.')

    return ctypes.wintypes.HMODULE(module_handle)


def _unload_module(process_handle: ctypes.wintypes.HANDLE, module_handle: ctypes.wintypes.HMODULE) -> None:
    if GetProcessId(process_handle) != CurrentProcessId:
        # TODO: Implement
        raise NotImplementedError('Unloading modules from another processes is not supported')
    
    FreeLibrary(module_handle)


def _iterate_modules(process_handle: ctypes.wintypes.HANDLE) -> Generator[Module, None, None]:
    pid = GetProcessId(process_handle)
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if not snapshot:
        raise WindowsError('Could not create modules snapshot.')
    
    try:
        module = MODULEENTRY32()
        module.dwSize = ctypes.sizeof(MODULEENTRY32)
        
        module_ptr = ctypes.pointer(module)
        
        if not Module32First(snapshot, module_ptr):
            raise WindowsError('Could not get first module.')
        
        yield Module(process_handle, ctypes.wintypes.HMODULE(module.hModule), module_name=os.path.basename(utf_8.decode(module.szExePath)[0]))
        
        while Module32Next(snapshot, module_ptr):
            yield Module(process_handle, ctypes.wintypes.HMODULE(module.hModule), module_name=os.path.basename(utf_8.decode(module.szExePath)[0]))
        
        if GetLastError() != ERROR_NO_MORE_FILES:
            raise WindowsError('Could not get next module.')
        
    finally:
        CloseHandle(snapshot)
