import ctypes
import ctypes.wintypes
import functools
from typing import Callable, Optional, Union
from .processes import Process, CurrentProcess
from .._internal.safe_resource import SafeResource
from .._internal.windows_definitions import *


class MemoryBlock(SafeResource):
    def __init__(self, address: int, size: int, deallocator: Optional[Callable[[int, int], None]] = None):
        super().__init__((address, size), deallocator)
    
    @property
    def address(self):
        return self.resource[0]
    
    @property
    def size(self):
        return self.resource[1]


PROCESS_MEMORY_ACCESS = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE


class ProcessMemory:
    """
    Class for accessing and manipulating the memory of a process.
    """
    def __init__(self, process: Process):
        self._process = process.with_access(PROCESS_MEMORY_ACCESS)
    
    def read(self, address_range: Union[int, slice]) -> bytes:
        address_range = _normalize_address_range(address_range)
        return _read_memory(self._process, address_range)

    def write(self, address_range: Union[int, slice], data: bytes) -> None:
        address_range = _normalize_address_range(address_range, len(data))
        _write_memory(self._process, address_range, data)
    
    def allocate(self, size: int, executable: bool = False) -> MemoryBlock:
        return _allocate_memory(size, executable, self._process)
    
    def read_null_terminated_array(self, address: int, element_size: int) -> bytes:
        """
        Reads an array that is terminated by a null entry.
        The array is of elements of size element_size.
        Returns the raw bytes of the array.
        """
        return _read_null_terminated_array(self._process, address, element_size)
    
    def __getitem__(self, address_range: Union[int, slice]) -> bytes:
        return self.read(address_range)

    def __setitem__(self, address_range: Union[int, slice], data: bytes) -> None:
        return self.write(address_range, data)


CurrentProcessMemory = ProcessMemory(CurrentProcess)


_executable_heap: SafeHandle = None


def _normalize_address_range(address_range: Union[int, slice], size: int = 1) -> slice:
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


def _read_memory(process: Process, address_range: slice) -> bytes:
    size = address_range.stop - address_range.start
    data = bytes(size)
    if not ReadProcessMemory(process.process_handle.handle, address_range.start, data, size, None):
        raise WindowsError('Could not read remote memory.')
    
    return data


def _write_memory(process: Process, address_range: slice, data: bytes) -> None:
    size = address_range.stop - address_range.start
    if not WriteProcessMemory(process.process_handle.handle, address_range.start, data, size, None):
        raise WindowsError('Could not write remote memory.')


def _initialize_executable_heap():
    global _executable_heap
    
    if _executable_heap is None:
        _executable_heap_handle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
        if not _executable_heap_handle:
            raise WindowsError('Clound not create executable heap.')
        
        _executable_heap_handle = ctypes.wintypes.HANDLE(_executable_heap_handle)
        _executable_heap = SafeHandle(_executable_heap_handle)


def _allocate_memory(size: int, executable: bool, process: Process) -> MemoryBlock:
    if process.is_current_process:
        return _allocate_local_memory(size, executable)
    
    else:
        return _allocate_remote_memory(process, size, executable)


def _allocate_local_memory(size: int, executable: bool) -> int:
    if executable:
        _initialize_executable_heap()
        heap_handle = _executable_heap
    else:
        heap_handle = ProcessHeap
    
    address = HeapAlloc(heap_handle.handle, HEAP_ZERO_MEMORY, size)
    if not address:
        raise WindowsError('Could not allocate memory.')
    
    deallocator = functools.partial(_deallocate_local_memory, heap_handle)
    return MemoryBlock(address, size, deallocator)
    

def _deallocate_local_memory(heap_handle: SafeHandle, address: int, size: int) -> None:
    HeapFree(heap_handle.handle, 0, address)


def _allocate_remote_memory(process: Process, size: int, executable: bool) -> MemoryBlock:
    if executable:
        protection = PAGE_EXECUTE_READWRITE
    else:
        protection = PAGE_READWRITE
    
    remote_address = VirtualAllocEx(process.process_handle.handle, None, size, MEM_RESERVE | MEM_COMMIT, protection)
    if not remote_address:
        raise WindowsError('Could not allocate remote memory.')
    
    deallocator = functools.partial(_deallocate_remote_memory, process)
    return MemoryBlock(remote_address, size, deallocator)


def _deallocate_remote_memory(process: Process, address: int, size: int) -> None:
    if not VirtualFreeEx(process.process_handle.handle, address, 0, MEM_RELEASE):
        print(GetLastError())
        raise WindowsError('Could not deallocate remote memory.')


def _read_null_terminated_array(process: Process, address: int, element_size: int) -> bytes:
    if element_size == 0:
        raise ValueError('Element size must be greater than 0.')
    
    data = b''
    while (current_entry := _read_memory(process, slice(address, address + element_size))).count(0) != element_size:
        data += current_entry
        address += element_size
    
    return data
