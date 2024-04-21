import ctypes
import ctypes.wintypes
import os
from encodings import utf_8
from typing import Dict, Generator, Optional, Tuple, Union
from .memory import Memory
from .._internal.windows_definitions import *


class Module:
    def __init__(self, process_handle: ctypes.wintypes.HANDLE, module_handle: ctypes.wintypes.HMODULE,
                 module_path: Optional[str] = None, module_name: Optional[str] = None):
        self._process_handle = process_handle
        self._module_handle = module_handle
        self._module_path = module_path
        self._module_name = module_name
        
        self._nt_headers = None
        self._virtual_size = None
        self._exports = None

    def get_symbol(self, symbol_name: Union[int, str]) -> int:
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

    @property
    def nt_headers(self) -> IMAGE_NT_HEADERS_ANY:
        if self._nt_headers is None:
            self._nt_headers = _get_module_nt_headers(self._process_handle, self.address)
        
        return self._nt_headers[1]

    @property
    def virtual_size(self) -> int:
        if self._virtual_size is None:
            self._virtual_size = _get_module_virtual_size(self.nt_headers)
        
        return self._virtual_size
    
    @property
    def exports(self) -> Dict[Union[int, str], int]:
        if self._exports is None:
            self._exports = _get_module_exports(self._process_handle, self.address, self.nt_headers)
        
        return self._exports

    def __enter__(self):
        return self
         
    def __exit__(self, exc_type, exc_value, exc_traceback):
        _unload_module(self._process_handle, self._module_handle)

    def __getitem__(self, symbol_name: Union[int, str]) -> int:
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
    def get_module(cls, module_name: str, process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> Module:
        if process_handle == CurrentProcess:
            return Module(CurrentProcess, _get_module(module_name))
        
        module_name_lower = module_name.lower()
        for module in cls.iterate_modules(process_handle):
            if module.name.lower() == module_name_lower:
                return module
        
        raise LookupError(f'Could not find remote module \'{module_name}\'')

    @classmethod
    def load_module(cls, module_name: str) -> Module:
        return Module(CurrentProcess, _load_module(module_name))

    @classmethod
    def unload_module(cls, module: Union[str, Module, ctypes.wintypes.HMODULE]) -> None:
        if isinstance(module, str):
            module = cls.get_module(module)
        
        if isinstance(module, Module):
            module = module._module_handle

        _unload_module(module)
    
    @classmethod
    def iterate_modules(cls, process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> Generator[Module, None, None]:
        yield from _iterate_modules(process_handle)


def _parse_symbol_name(symbol_name: Union[int, str]) -> ctypes.wintypes.LPCSTR:
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


def _get_module_nt_headers(process_handle: ctypes.wintypes.HANDLE, module_address: int) -> Tuple[int, IMAGE_NT_HEADERS_ANY]:
    from .processes import _is_process_32bit
    
    dos_header_start = module_address
    dos_header_end = dos_header_start + ctypes.sizeof(IMAGE_DOS_HEADER)
    dos_header_data = Memory.read(slice(dos_header_start, dos_header_end), process_handle)
    dos_header = IMAGE_DOS_HEADER.from_buffer_copy(dos_header_data)
    
    if _is_process_32bit(process_handle):
        IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32
    else:
        IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64
    
    nt_headers_start = dos_header_start + dos_header.e_lfanew
    nt_headers_end = nt_headers_start + ctypes.sizeof(IMAGE_NT_HEADERS)
    nt_headers_data = Memory.read(slice(nt_headers_start, nt_headers_end), process_handle)
    nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(nt_headers_data)
    
    return nt_headers_start, nt_headers


def _get_module_virtual_size(nt_headers: IMAGE_NT_HEADERS_ANY) -> int:
    return nt_headers.OptionalHeader.SizeOfImage


def _get_module_exports(process_handle: ctypes.wintypes.HANDLE, module_address: int, nt_headers: IMAGE_NT_HEADERS_ANY) -> Dict[Union[int, str], int]:
    export_directory_start = module_address + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    export_directory_end = export_directory_start + ctypes.sizeof(IMAGE_EXPORT_DIRECTORY)
    export_directory_data = Memory.read(slice(export_directory_start, export_directory_end), process_handle)
    export_directory = IMAGE_EXPORT_DIRECTORY.from_buffer_copy(export_directory_data)
    
    base_ordinal = export_directory.Base
    
    functions_table_length = export_directory.NumberOfFunctions
    functions_table_type = ctypes.wintypes.DWORD * functions_table_length
    functions_table_start = module_address + export_directory.AddressOfFunctions
    functions_table_end = functions_table_start + ctypes.sizeof(functions_table_type)
    functions_table_data = Memory.read(slice(functions_table_start, functions_table_end), process_handle)
    functions_table = functions_table_type.from_buffer_copy(functions_table_data)
    
    exported_functions: Dict[Union[int, str], int] = {}
    for function_ordinal, function_rva in enumerate(functions_table, start=base_ordinal):
        if function_rva == 0:
            continue
        
        function_address = module_address + function_rva
        exported_functions[function_ordinal] = function_address
    
    names_table_length = export_directory.NumberOfNames
    names_table_type = ctypes.wintypes.DWORD * names_table_length
    names_table_start = module_address + export_directory.AddressOfNames
    names_table_end = names_table_start + ctypes.sizeof(names_table_type)
    names_table_data = Memory.read(slice(names_table_start, names_table_end), process_handle)
    names_table = names_table_type.from_buffer_copy(names_table_data)
    
    name_ordinals_table_length = export_directory.NumberOfNames
    name_ordinals_table_type = ctypes.wintypes.WORD * name_ordinals_table_length
    name_ordinals_table_start = module_address + export_directory.AddressOfNameOrdinals
    name_ordinals_table_end = name_ordinals_table_start + ctypes.sizeof(name_ordinals_table_type)
    name_ordinals_table_data = Memory.read(slice(name_ordinals_table_start, name_ordinals_table_end), process_handle)
    name_ordinals_table = name_ordinals_table_type.from_buffer_copy(name_ordinals_table_data)
    
    ordinals_to_remove = []
    for name_ordinal, name_rva in enumerate(names_table):
        name_address = module_address + name_rva
        function_name_data = Memory.read_null_terminated_array(name_address, ctypes.sizeof(ctypes.wintypes.CHAR), process_handle)
        function_name = utf_8.decode(function_name_data)[0]
        function_ordinal = base_ordinal + name_ordinals_table[name_ordinal]
        function_address = exported_functions[function_ordinal]
        
        exported_functions[function_name] = function_address
        ordinals_to_remove.append(function_ordinal)
    
    for ordinal in ordinals_to_remove:
        exported_functions.pop(ordinal)
    
    return exported_functions


def _get_module(module_name: str) -> ctypes.wintypes.HMODULE:
    module_handle = GetModuleHandleA(utf_8.encode(module_name)[0])
    if not module_handle:
        raise WindowsError(f'Could not find module \'{module_name}\'.')

    return ctypes.wintypes.HMODULE(module_handle)


def _load_module(module_name: ctypes.wintypes.LPCSTR) -> ctypes.wintypes.HMODULE:
    module_handle = LoadLibraryA(utf_8.encode(module_name)[0])
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
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
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
