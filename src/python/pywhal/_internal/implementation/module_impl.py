import ctypes
import ctypes.wintypes
from encodings import utf_8
from typing import Dict, Tuple, Union
from . import process_memory_impl
from ..safe_module_handle import SafeModuleHandle
from ..windows_definitions import *
from ...library.process import Process


def get_module_name(process: Process, module_handle: SafeModuleHandle) -> bytes:
    name_buffer = bytes(MAX_PATH)
    
    while (name_length := GetModuleFileNameExA(process.process_handle.handle, module_handle.handle, name_buffer, len(name_buffer))) >= len(name_buffer):
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER:
            raise WindowsError('Failed getting module name.')
        
        name_buffer = bytes(min(len(name_buffer) * 2, MAX_LONG_PATH_LENGTH))
    
    if name_length == 0:
        raise WindowsError('Failed getting module name.')
    
    return name_buffer[:name_length]


def get_module_nt_headers(process: Process, module_address: int) -> Tuple[int, IMAGE_NT_HEADERS_ANY]:
    dos_header_start = module_address
    dos_header_end = dos_header_start + ctypes.sizeof(IMAGE_DOS_HEADER)
    dos_header_data = process_memory_impl.read_memory(process, slice(dos_header_start, dos_header_end))
    dos_header = IMAGE_DOS_HEADER.from_buffer_copy(dos_header_data)
    
    if process.is_32bit:
        IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32
    else:
        IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64
    
    nt_headers_start = dos_header_start + dos_header.e_lfanew
    nt_headers_end = nt_headers_start + ctypes.sizeof(IMAGE_NT_HEADERS)
    nt_headers_data = process_memory_impl.read_memory(process, slice(nt_headers_start, nt_headers_end))
    nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(nt_headers_data)
    
    return nt_headers_start, nt_headers


def get_module_virtual_size(nt_headers: IMAGE_NT_HEADERS_ANY) -> int:
    return nt_headers.OptionalHeader.SizeOfImage


def get_module_exports(process: Process, module_address: int, nt_headers: IMAGE_NT_HEADERS_ANY) -> Dict[Union[int, str], int]:
    export_directory_start = module_address + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    export_directory_end = export_directory_start + ctypes.sizeof(IMAGE_EXPORT_DIRECTORY)
    export_directory_data = process_memory_impl.read_memory(process, slice(export_directory_start, export_directory_end))
    export_directory = IMAGE_EXPORT_DIRECTORY.from_buffer_copy(export_directory_data)
    
    base_ordinal = export_directory.Base
    
    functions_table_length = export_directory.NumberOfFunctions
    functions_table_type = ctypes.wintypes.DWORD * functions_table_length
    functions_table_start = module_address + export_directory.AddressOfFunctions
    functions_table_end = functions_table_start + ctypes.sizeof(functions_table_type)
    functions_table_data = process_memory_impl.read_memory(process, slice(functions_table_start, functions_table_end))
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
    names_table_data = process_memory_impl.read_memory(process, slice(names_table_start, names_table_end))
    names_table = names_table_type.from_buffer_copy(names_table_data)
    
    name_ordinals_table_length = export_directory.NumberOfNames
    name_ordinals_table_type = ctypes.wintypes.WORD * name_ordinals_table_length
    name_ordinals_table_start = module_address + export_directory.AddressOfNameOrdinals
    name_ordinals_table_end = name_ordinals_table_start + ctypes.sizeof(name_ordinals_table_type)
    name_ordinals_table_data = process_memory_impl.read_memory(process, slice(name_ordinals_table_start, name_ordinals_table_end))
    name_ordinals_table = name_ordinals_table_type.from_buffer_copy(name_ordinals_table_data)
    
    ordinals_to_remove = []
    for name_ordinal, name_rva in enumerate(names_table):
        name_address = module_address + name_rva
        function_name_data = process_memory_impl.read_null_terminated_array(process, name_address, ctypes.sizeof(ctypes.wintypes.CHAR))
        function_name = utf_8.decode(function_name_data)[0]
        function_ordinal = base_ordinal + name_ordinals_table[name_ordinal]
        function_address = exported_functions[function_ordinal]
        
        exported_functions[function_name] = function_address
        ordinals_to_remove.append(function_ordinal)
    
    for ordinal in ordinals_to_remove:
        exported_functions.pop(ordinal)
    
    return exported_functions
