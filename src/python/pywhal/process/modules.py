import ctypes
import ctypes.wintypes
import os
from encodings import utf_8
from typing import Dict, Generator, Optional, Tuple, Union
from .processes import Process, CurrentProcess
from .._internal.safe_resource import SafeResource
from .._internal.safe_module_handle import SafeModuleHandle
from .._internal.windows_definitions import *


class Module(SafeResource):
    def __init__(self, process: Process, module_handle: SafeModuleHandle,
                 module_path: Optional[str] = None, module_name: Optional[str] = None):
        from .memory import PROCESS_MEMORY_ACCESS
        super().__init__((process.with_access(PROCESS_MEMORY_ACCESS), module_handle),
                         _unload_module if module_handle.is_managed else None)
        self._module_path = module_path
        self._module_name = module_name
        
        self._nt_headers = None
        self._virtual_size = None
        self._exports = None

    def get_export(self, export_name: Union[int, str]) -> int:
        return self.exports[export_name]

    @property
    def _process(self) -> Process:
        return self.resource[0]

    @property
    def _module_handle(self) -> SafeModuleHandle:
        return self.resource[1]

    @property
    def path(self) -> str:
        if self._module_path is None:
            module_name = _get_module_name(self._process, self._module_handle)
            self._module_path = utf_8.decode(module_name)[0]
        
        return self._module_path

    @property
    def name(self) -> str:
        if self._module_name is None:
            self._module_name = os.path.basename(self.path)
        
        return self._module_name

    @property
    def address(self) -> int:
        return self._module_handle.handle.value or 0

    @property
    def nt_headers(self) -> IMAGE_NT_HEADERS_ANY:
        if self._nt_headers is None:
            self._nt_headers = _get_module_nt_headers(self._process, self.address)
        
        return self._nt_headers[1]

    @property
    def virtual_size(self) -> int:
        if self._virtual_size is None:
            self._virtual_size = _get_module_virtual_size(self.nt_headers)
        
        return self._virtual_size
    
    @property
    def exports(self) -> Dict[Union[int, str], int]:
        if self._exports is None:
            self._exports = _get_module_exports(self._process, self.address, self.nt_headers)
        
        return self._exports

    def __getitem__(self, export_name: Union[int, str]) -> int:
        return self.get_export(export_name)
    
    def __repr__(self) -> str:
        return f'<Module \'{self.name}\' @ {hex(self.address)}>'


class ProcessModules:
    """
    Class for accessing and manipulating the modules of a process.
    """
    def __init__(self, process: Process):
        from .memory import PROCESS_MEMORY_ACCESS
        self._process = process.with_access(PROCESS_MEMORY_ACCESS)

    def get_module(self, module_name: str, ) -> Module:
        return _get_module(self._process, module_name)

    def load_module(self, module_name: str) -> Module:
        return _load_module(self._process, module_name)

    def unload_module(self, module: Union[str, Module, ctypes.wintypes.HMODULE]) -> None:
        if isinstance(module, str):
            module = self.get_module(module)
        
        if isinstance(module, Module):
            module = module._module_handle

        _unload_module(module)
    
    def iterate_modules(self) -> Generator[Module, None, None]:
        yield from _iterate_modules(self._process)
    
    def __getitem__(self, module_name: str) -> Module:
        return self.get_module(module_name)
    
    def __iter__(self) -> Generator[Module, None, None]:
        yield from self.iterate_modules()


CurrentProcessModules = ProcessModules(CurrentProcess)


def _get_module_name(process: Process, module_handle: SafeModuleHandle) -> bytes:
    name_buffer = bytes(MAX_PATH)
    
    while (name_length := GetModuleFileNameExA(process.process_handle.handle, module_handle.handle, name_buffer, len(name_buffer))) >= len(name_buffer):
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER:
            raise WindowsError('Failed getting module name.')
        
        name_buffer = bytes(min(len(name_buffer) * 2, MAX_LONG_PATH_LENGTH))
    
    if name_length == 0:
        raise WindowsError('Failed getting module name.')
    
    return name_buffer[:name_length]


def _get_module_nt_headers(process: Process, module_address: int) -> Tuple[int, IMAGE_NT_HEADERS_ANY]:
    from .memory import _read_memory
    
    dos_header_start = module_address
    dos_header_end = dos_header_start + ctypes.sizeof(IMAGE_DOS_HEADER)
    dos_header_data = _read_memory(process, slice(dos_header_start, dos_header_end))
    dos_header = IMAGE_DOS_HEADER.from_buffer_copy(dos_header_data)
    
    if process.is_32bit:
        IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32
    else:
        IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64
    
    nt_headers_start = dos_header_start + dos_header.e_lfanew
    nt_headers_end = nt_headers_start + ctypes.sizeof(IMAGE_NT_HEADERS)
    nt_headers_data = _read_memory(process, slice(nt_headers_start, nt_headers_end))
    nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(nt_headers_data)
    
    return nt_headers_start, nt_headers


def _get_module_virtual_size(nt_headers: IMAGE_NT_HEADERS_ANY) -> int:
    return nt_headers.OptionalHeader.SizeOfImage


def _get_module_exports(process: Process, module_address: int, nt_headers: IMAGE_NT_HEADERS_ANY) -> Dict[Union[int, str], int]:
    from .memory import _read_memory, _read_null_terminated_array
    
    export_directory_start = module_address + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    export_directory_end = export_directory_start + ctypes.sizeof(IMAGE_EXPORT_DIRECTORY)
    export_directory_data = _read_memory(process, slice(export_directory_start, export_directory_end))
    export_directory = IMAGE_EXPORT_DIRECTORY.from_buffer_copy(export_directory_data)
    
    base_ordinal = export_directory.Base
    
    functions_table_length = export_directory.NumberOfFunctions
    functions_table_type = ctypes.wintypes.DWORD * functions_table_length
    functions_table_start = module_address + export_directory.AddressOfFunctions
    functions_table_end = functions_table_start + ctypes.sizeof(functions_table_type)
    functions_table_data = _read_memory(process, slice(functions_table_start, functions_table_end))
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
    names_table_data = _read_memory(process, slice(names_table_start, names_table_end))
    names_table = names_table_type.from_buffer_copy(names_table_data)
    
    name_ordinals_table_length = export_directory.NumberOfNames
    name_ordinals_table_type = ctypes.wintypes.WORD * name_ordinals_table_length
    name_ordinals_table_start = module_address + export_directory.AddressOfNameOrdinals
    name_ordinals_table_end = name_ordinals_table_start + ctypes.sizeof(name_ordinals_table_type)
    name_ordinals_table_data = _read_memory(process, slice(name_ordinals_table_start, name_ordinals_table_end))
    name_ordinals_table = name_ordinals_table_type.from_buffer_copy(name_ordinals_table_data)
    
    ordinals_to_remove = []
    for name_ordinal, name_rva in enumerate(names_table):
        name_address = module_address + name_rva
        function_name_data = _read_null_terminated_array(process, name_address, ctypes.sizeof(ctypes.wintypes.CHAR))
        function_name = utf_8.decode(function_name_data)[0]
        function_ordinal = base_ordinal + name_ordinals_table[name_ordinal]
        function_address = exported_functions[function_ordinal]
        
        exported_functions[function_name] = function_address
        ordinals_to_remove.append(function_ordinal)
    
    for ordinal in ordinals_to_remove:
        exported_functions.pop(ordinal)
    
    return exported_functions


def _get_module(process: Process, module_name: str) -> Module:
    if process.is_current_process:
        module_handle = GetModuleHandleA(utf_8.encode(module_name)[0])
        if not module_handle:
            raise WindowsError(f'Could not find module \'{module_name}\'.')
    
        return Module(process, SafeModuleHandle(ctypes.wintypes.HMODULE(module_handle)), False)
    
    module_name_lower = module_name.lower()
    if '.' not in module_name_lower:
        module_name_lower += '.dll'
    
    for module in _iterate_modules(process):
        if module.name.lower() == module_name_lower:
            return module
    
    raise LookupError(f'Could not find remote module \'{module_name}\'')


def _load_module(process: Process, module_name: str) -> Module:
    from .processes import _get_process_pid
    from .utils import _inject_dll_into_process
    
    if process.is_current_process:
        module_handle = LoadLibraryA(utf_8.encode(module_name)[0])
        if not module_handle:
            raise WindowsError(f'Could not load module \'{module_name}\'.')

        return Module(process, SafeModuleHandle(ctypes.wintypes.HMODULE(module_handle), managed=True))
    
    _inject_dll_into_process(process)


def _unload_module(process: Process, module_handle: SafeModuleHandle) -> None:
    if not process.is_current_process:
        # TODO: Maybe implement? Doesn't seem really important
        raise NotImplementedError('Unloading modules from another processes is not supported')
    
    module_handle.release()


def _iterate_modules(process: Union[int, Process]) -> Generator[Module, None, None]:
    from .memory import PROCESS_MEMORY_ACCESS
    process = process.with_access(PROCESS_MEMORY_ACCESS)
    
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process.pid)
    if not snapshot:
        raise WindowsError('Could not create modules snapshot.')
    
    try:
        module = MODULEENTRY32()
        module.dwSize = ctypes.sizeof(MODULEENTRY32)
        
        module_ptr = ctypes.pointer(module)
        
        parse_module = lambda: Module(process, SafeModuleHandle(ctypes.wintypes.HMODULE(module.hModule), False),
                                      module_name=os.path.basename(utf_8.decode(module.szExePath)[0]))
        
        if not Module32First(snapshot, module_ptr):
            raise WindowsError('Could not get first module.')
        
        yield parse_module()
        
        while Module32Next(snapshot, module_ptr):
            yield parse_module()
        
        if GetLastError() != ERROR_NO_MORE_FILES:
            raise WindowsError('Could not get next module.')
        
    finally:
        CloseHandle(snapshot)
