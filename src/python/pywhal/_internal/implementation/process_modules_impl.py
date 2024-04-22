import ctypes
import ctypes.wintypes
import os
from encodings import utf_8
from typing import Generator, Union
from ..safe_module_handle import SafeModuleHandle
from ..windows_definitions import *
from ...library.process import Process
from ...library.module import Module


def get_module(process: Process, module_name: str) -> Module:
    if process.is_current_process:
        module_handle = GetModuleHandleA(utf_8.encode(module_name)[0])
        if not module_handle:
            raise WindowsError(f'Could not find module \'{module_name}\'.')
    
        return Module(process, SafeModuleHandle(ctypes.wintypes.HMODULE(module_handle)), False)
    
    module_name_lower = module_name.lower()
    if '.' not in module_name_lower:
        module_name_lower += '.dll'
    
    for module in iterate_modules(process):
        if module.name.lower() == module_name_lower:
            return module
    
    raise LookupError(f'Could not find remote module \'{module_name}\'')


def load_module(process: Process, module_name: str) -> Module:
    from .utils_impl import inject_dll_into_process
    
    if process.is_current_process:
        module_handle = LoadLibraryA(utf_8.encode(module_name)[0])
        if not module_handle:
            raise WindowsError(f'Could not load module \'{module_name}\'.')

        return Module(process, SafeModuleHandle(ctypes.wintypes.HMODULE(module_handle), managed=True))
    
    inject_dll_into_process(process)


def unload_module(process: Process, module_handle: SafeModuleHandle) -> None:
    if not process.is_current_process:
        from .utils_impl import wrap_remote_function, PROCESS_INJECTION_ACCESS_RIGHTS
        process = process.with_access(PROCESS_INJECTION_ACCESS_RIGHTS)
        
        FreeLibrary_address = get_module(process, 'kernel32.dll')['FreeLibrary']
        FreeLibrary = wrap_remote_function(process, FreeLibrary_address)
    
        FreeLibrary(module_handle.address)
    
    module_handle.release()


def iterate_modules(process: Union[int, Process]) -> Generator[Module, None, None]:
    from .process_memory_impl import PROCESS_MEMORY_ACCESS_RIGHTS
    process = process.with_access(PROCESS_MEMORY_ACCESS_RIGHTS)
    
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
