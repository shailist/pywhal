import ctypes
import ctypes.wintypes
import functools
from typing import Callable, Optional, Union
from .._internal.windows_definitions import *


class MemoryBlock:
    def __init__(self, address: int, size: int, deallocator: Optional[Callable[[int, int], None]] = None):
        self.address = address
        self.size = size
        self.deallocator = deallocator
    
    def detach(self):
        """
        The memory block won't be released when the object is destroyed.
        """
        self.deallocator = None
    
    def __del__(self):
        self._delete()
    
    def __enter__(self):
        return self
         
    def __exit__(self, exc_type, exc_value, exc_traceback):
        self._delete()
    
    def _delete(self):
        if self.deallocator is not None:
            self.deallocator(self.address, self.size)
            self.deallocator = None


class MemoryMeta(type):
    """
    Convenience metaclass to allow accessing Memory's functionality
    via square brackets syntax (Memory[0x1234] = 0xFF).
    """
    def __getitem__(cls, address_range: Union[int, slice]) -> bytes:
        return cls.read(address_range)

    def __setitem__(cls, address_range: Union[int, slice], data: bytes):
        return cls.write(address_range, data)


class Memory(metaclass=MemoryMeta):
    """
    Class for accessing and manipulating the memory of the process.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """    
    def __new__(cls):
        raise TypeError('The Memory class cannot be instantiated.')

    @classmethod
    def read(cls, address_range: Union[int, slice], process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> bytes:
        address_range = _normalize_address_range(address_range)
        return _read_memory(process_handle, address_range)

    @classmethod
    def write(cls, address_range: Union[int, slice], data: bytes, process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> None:
        address_range = _normalize_address_range(address_range, len(data))
        _write_memory(process_handle, address_range, data)
    
    @classmethod
    def allocate(cls, size: int, executable: bool = False, process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> MemoryBlock:
        return _allocate_memory(size, executable, process_handle)
    
    @classmethod
    def read_null_terminated_array(cls, address: int, element_size: int, process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> bytes:
        """
        Reads an array that is terminated by a null entry.
        The array is of elements of size element_size.
        Returns the raw bytes of the array.
        """
        return _read_null_terminated_array(address, element_size, process_handle)


_executable_heap: ctypes.wintypes.HANDLE = None


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


def _read_memory(process_handle: ctypes.wintypes.HANDLE, address_range: slice) -> bytes:
    size = address_range.stop - address_range.start
    data = bytes(size)
    if not ReadProcessMemory(process_handle, address_range.start, data, size, None):
        raise WindowsError('Could not read remote memory.')
    
    return data


def _write_memory(process_handle: ctypes.wintypes.HANDLE, address_range: slice, data: bytes) -> None:
    size = address_range.stop - address_range.start
    if not WriteProcessMemory(process_handle, address_range.start, data, size, None):
        raise WindowsError('Could not write remote memory.')


def _initialize_executable_heap():
    global _executable_heap
    
    if _executable_heap is None:
        _executable_heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
        if not _executable_heap:
            raise WindowsError('Clound not create executable heap.')
        
        _executable_heap = ctypes.wintypes.HANDLE(_executable_heap)


def _allocate_memory(size: int, executable: bool = False, process_handle: ctypes.wintypes.HANDLE = CurrentProcess) -> MemoryBlock:
    if process_handle == CurrentProcess:
        return _allocate_local_memory(size, executable)
    
    else:
        return _allocate_remote_memory(size, executable, process_handle)


def _allocate_local_memory(size: int, executable: bool) -> int:
    if executable:
        _initialize_executable_heap()
        heap = _executable_heap
    else:
        heap = ProcessHeap
    
    address = HeapAlloc(heap, HEAP_ZERO_MEMORY, size)
    if not address:
        raise WindowsError('Could not allocate memory.')
    
    deallocator = functools.partial(_deallocate_local_memory, heap)
    return MemoryBlock(address, size, deallocator)
    

def _deallocate_local_memory(heap: ctypes.wintypes.HANDLE, address: int, size: int) -> None:
    HeapFree(heap, 0, address)


def _allocate_remote_memory(process_handle: ctypes.wintypes.HANDLE, size: int, executable: bool) -> MemoryBlock:
    if executable:
        protection = PAGE_EXECUTE_READWRITE
    else:
        protection = PAGE_READWRITE
    
    remote_address = VirtualAllocEx(process_handle, None, size, MEM_RESERVE | MEM_COMMIT, protection)
    if not remote_address:
        raise WindowsError('Could not allocate remote memory.')
    
    deallocator = functools.partial(_deallocate_remote_memory, process_handle)
    return MemoryBlock(remote_address, size, deallocator)


def _deallocate_remote_memory(process_handle: ctypes.wintypes.HANDLE, address: int, size: int) -> None:
    if not VirtualFreeEx(process_handle, address, 0, MEM_DECOMMIT | MEM_RELEASE):
        raise WindowsError('Could not deallocate remote memory.')


def _read_null_terminated_array(address: int, element_size: int, process_handle: ctypes.wintypes.HANDLE) -> bytes:
    if element_size == 0:
        raise ValueError('Element size must be greater than 0.')
    
    data = b''
    while (current_entry := _read_memory(process_handle, slice(address, address + element_size))).count(0) != element_size:
        data += current_entry
        address += element_size
    
    return data
