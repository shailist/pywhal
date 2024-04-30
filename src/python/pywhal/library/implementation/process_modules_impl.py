import ctypes
import ctypes.wintypes
import os
from encodings import utf_8, utf_16_le
from typing import Generator, Union
from .safe_module_handle import SafeModuleHandle
from .windows_definitions import *
from ..module import Module
from ..process import Process, CurrentProcess


def get_module(process: Process, module_name: str) -> Module:
    if process.is_current_process:
        module_handle = GetModuleHandleA(utf_8.encode(module_name)[0])
        if not module_handle:
            raise WindowsError(f'Could not find module \'{module_name}\'.')
    
        return Module(process, SafeModuleHandle(module_handle, False))
    
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

        return Module(process, SafeModuleHandle(module_handle, managed=True))
    
    inject_dll_into_process(process)


def unload_module(process: Process, module_handle: SafeModuleHandle) -> None:
    if not process.is_current_process:
        from .utils_impl import wrap_remote_function, PROCESS_INJECTION_ACCESS_RIGHTS
        process = process.with_access(PROCESS_INJECTION_ACCESS_RIGHTS)
        
        FreeLibrary_address = get_module(process, 'kernel32.dll')['FreeLibrary']
        FreeLibrary = wrap_remote_function(process, FreeLibrary_address)
    
        FreeLibrary(module_handle.address)
    
    module_handle.release()


def query_process_basic_information(process: Process) -> Union[winternl32.PROCESS_BASIC_INFORMATION | winternl64.PROCESS_BASIC_INFORMATION]:
    process = process.with_access(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    
    if process.is_32bit:
        query_function = NtQueryInformationProcess
        process_basic_information = (winternl32 if CurrentProcess.is_32bit else winternl64).PROCESS_BASIC_INFORMATION()
    
    else:
        # If current process is 32 bit and target process is 64 bit
        if CurrentProcess.is_32bit:
            global NtWow64QueryInformationProcess64
            if NtWow64QueryInformationProcess64 is None:
                NtWow64QueryInformationProcess64 = PfnNtWow64QueryInformationProcess64(ctypes.windll.ntdll.NtWow64QueryInformationProcess64)
            
            query_function = NtWow64QueryInformationProcess64
        
        else:
            query_function = NtQueryInformationProcess
            
        process_basic_information = winternl64.PROCESS_BASIC_INFORMATION()
    
    bytes_written = ctypes.wintypes.ULONG()
    status = query_function(process.process_handle.handle, ProcessBasicInformation, ctypes.pointer(process_basic_information),
                            ctypes.sizeof(process_basic_information), ctypes.pointer(bytes_written))
    if status != 0:
        import ipdb; ipdb.set_trace()
        raise WindowsError('Could not query process\' basic information')
    
    return process_basic_information


def iterate_modules(process: Union[int, Process]) -> Generator[Module, None, None]:
    from . import process_memory_impl
    
    process = process.with_access(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    winternl = winternl32 if process.is_32bit else winternl64
    process_information = query_process_basic_information(process)
    peb_address: int = process_information.PebBaseAddress
    
    PEB: Type[ctypes.Structure] = winternl.PEB
    peb_end = peb_address + ctypes.sizeof(PEB)
    peb_data = process_memory_impl.read_memory(process, slice(peb_address, peb_end))
    peb = PEB.from_buffer_copy(peb_data)
    
    peb_ldr_data_address: int = peb.Ldr
    
    PEB_LDR_DATA: Type[ctypes.Structure] = winternl.PEB_LDR_DATA
    peb_ldr_data_end = peb_ldr_data_address + ctypes.sizeof(PEB_LDR_DATA)
    peb_ldr_data_data = process_memory_impl.read_memory(process, slice(peb_ldr_data_address, peb_ldr_data_end))
    peb_ldr_data = PEB_LDR_DATA.from_buffer_copy(peb_ldr_data_data)
    
    module_list_head_address: int = peb_ldr_data_address + PEB_LDR_DATA.InMemoryOrderModuleList.offset
    
    LIST_ENTRY: Type[ctypes.Structure] = winternl.LIST_ENTRY 
    
    module_list_head_end = module_list_head_address + ctypes.sizeof(LIST_ENTRY)
    module_list_head_data = process_memory_impl.read_memory(process, slice(module_list_head_address, module_list_head_end))
    module_list_head = LIST_ENTRY.from_buffer_copy(module_list_head_data)
    
    LDR_DATA_TABLE_ENTRY: Type[ctypes.Structure] = winternl.LDR_DATA_TABLE_ENTRY
    
    current_module_list_entry = module_list_head
    while True:
        module_list_entry_address: int = current_module_list_entry.Flink
        if module_list_entry_address == module_list_head_address:
            break
        
        module_table_entry_address: int = module_list_entry_address - LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks.offset
        module_table_entry_end = module_table_entry_address + ctypes.sizeof(LDR_DATA_TABLE_ENTRY)
        module_table_entry_data = process_memory_impl.read_memory(process, slice(module_table_entry_address, module_table_entry_end))
        module_table_entry = LDR_DATA_TABLE_ENTRY.from_buffer_copy(module_table_entry_data)
        
        current_module_list_entry = module_table_entry.InMemoryOrderLinks
        
        module_base_address: int = module_table_entry.DllBase
        module_handle = SafeModuleHandle(module_base_address, False)
        
        module_dll_name_length_bytes: int = module_table_entry.FullDllName.Length
        if module_dll_name_length_bytes == 0:
            module_dll_name = ''
        else:
            module_dll_name_address = module_table_entry.FullDllName.Buffer
            module_dll_name_end = module_dll_name_address + module_dll_name_length_bytes
            module_dll_name_bytes = process_memory_impl.read_memory(process, slice(module_dll_name_address, module_dll_name_end))
            module_dll_name: str = utf_16_le.decode(module_dll_name_bytes)[0]
        
        yield Module(process, module_handle, module_dll_name, os.path.basename(module_dll_name))
