import ctypes.wintypes
import functools
from typing import Union
from ..windows_definitions import *
from ...library.memory_block import MemoryBlock
from ...library.process import Process


PROCESS_MEMORY_ACCESS_RIGHTS = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE

_executable_heap: SafeHandle = None


def normalize_address_range(address_range: Union[int, slice], size: int = 1) -> slice:
    """
    Converts an address/address range to a slice, verifying it has no step
    value. Optionaly can set the slice's size.
    """
    if isinstance(address_range, int):
        address_range = slice(address_range, None)
        
    if address_range.step is not None:
        raise ValueError('Address ranges do not support steps.')
            
    if address_range.stop is None:
        address_range = slice(address_range.start, address_range.start + size)
    
    return address_range


def read_memory(process: Process, address_range: Union[int, slice]) -> bytes:
    address_range = normalize_address_range(address_range)
    
    size = address_range.stop - address_range.start
    data = bytes(size)
    if not ReadProcessMemory(process.process_handle.handle, address_range.start, data, size, None):
        raise WindowsError('Could not read remote memory.')
    
    return data


def write_memory(process: Process, address_range: Union[int, slice], data: bytes) -> None:
    address_range = normalize_address_range(address_range, len(data))
    
    size = address_range.stop - address_range.start
    if not WriteProcessMemory(process.process_handle.handle, address_range.start, data, size, None):
        raise WindowsError('Could not write remote memory.')


def initialize_executable_heap():
    global _executable_heap
    
    if _executable_heap is None:
        _executable_heap_handle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
        if not _executable_heap_handle:
            raise WindowsError('Clound not create executable heap.')
        
        _executable_heap_handle = ctypes.wintypes.HANDLE(_executable_heap_handle)
        _executable_heap = SafeHandle(_executable_heap_handle)


def allocate_memory(process: Process, size: int, executable: bool = False) -> MemoryBlock:
    if process.is_current_process:
        return allocate_local_memory(size, executable)
    
    else:
        return allocate_remote_memory(process, size, executable)


def allocate_local_memory(size: int, executable: bool) -> int:
    if executable:
        initialize_executable_heap()
        heap_handle = _executable_heap
    else:
        heap_handle = ProcessHeap
    
    address = HeapAlloc(heap_handle.handle, HEAP_ZERO_MEMORY, size)
    if not address:
        raise WindowsError('Could not allocate memory.')
    
    deallocator = functools.partial(deallocate_local_memory, heap_handle)
    return MemoryBlock(address, size, deallocator)
    

def deallocate_local_memory(heap_handle: SafeHandle, address: int, size: int) -> None:
    HeapFree(heap_handle.handle, 0, address)


def allocate_remote_memory(process: Process, size: int, executable: bool) -> MemoryBlock:
    if executable:
        protection = PAGE_EXECUTE_READWRITE
    else:
        protection = PAGE_READWRITE
    
    remote_address = VirtualAllocEx(process.process_handle.handle, None, size, MEM_RESERVE | MEM_COMMIT, protection)
    if not remote_address:
        raise WindowsError('Could not allocate remote memory.')
    
    deallocator = functools.partial(deallocate_remote_memory, process)
    return MemoryBlock(remote_address, size, deallocator)


def deallocate_remote_memory(process: Process, address: int, size: int) -> None:
    if not VirtualFreeEx(process.process_handle.handle, address, 0, MEM_RELEASE):
        print(GetLastError())
        raise WindowsError('Could not deallocate remote memory.')


def read_null_terminated_array(process: Process, address: int, element_size: int) -> bytes:
    if element_size == 0:
        raise ValueError('Element size must be greater than 0.')
    
    data = b''
    while (current_entry := read_memory(process, slice(address, address + element_size))).count(0) != element_size:
        data += current_entry
        address += element_size
    
    return data
