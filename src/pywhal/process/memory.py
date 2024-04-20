import ctypes
import ctypes.wintypes
import functools
from typing import Callable, Optional, Union


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

    def __setitem__(cls, address_range: Union[int, slice], data: Union[bytes, bytearray]):
        return cls.write(address_range, data)


class Memory(metaclass=MemoryMeta):
    """
    Class for accessing and manipulating the memory of the process.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """    
    def __new__(cls):
        raise TypeError('The Memory class cannot be instantiated')

    @classmethod
    def get_memory(cls, address_range: Union[int, slice]) -> ctypes.Array:
        """
        Returns the memory span pointed by the address range as a ctypes
        buffer object.
        """
        address_range = _normalize_address_range(address_range)
        
        address = address_range.start
        size = address_range.stop - address_range.start
        
        buffer_type = ctypes.c_char * size
        
        return buffer_type.from_address(address)

    @classmethod
    def read(cls, address_range: Union[int, slice]) -> bytes:
        return cls.get_memory(address_range).raw

    @classmethod
    def write(cls, address_range: Union[int, slice], data: Union[bytes, bytearray]) -> None:
        address_range = _normalize_address_range(address_range, len(data))
        cls.get_memory(address_range)[:] = data
    
    @classmethod
    def allocate(cls, size: int, executable: bool = False) -> MemoryBlock:
        if executable:
            _initialize_executable_heap()
            heap = _executable_heap
        else:
            heap = _process_heap
        
        address = _allocate_memory(heap, size)
        deallocator = functools.partial(_deallocate_memory, heap)
        return MemoryBlock(address, size, deallocator)
        
        

HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
HEAP_ZERO_MEMORY = 0x00000008

GetProcessHeap = ctypes.windll.kernel32.GetProcessHeap
GetProcessHeap.restype = ctypes.wintypes.HANDLE
GetProcessHeap.argtypes = []

HeapCreate = ctypes.windll.kernel32.HeapCreate
HeapCreate.restype = ctypes.wintypes.HANDLE
HeapCreate.argtypes = [ctypes.wintypes.DWORD, ctypes.c_size_t, ctypes.c_size_t]

HeapAlloc = ctypes.windll.kernel32.HeapAlloc
HeapAlloc.restype = ctypes.wintypes.LPVOID
HeapAlloc.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.c_size_t]

HeapFree = ctypes.windll.kernel32.HeapFree
HeapFree.restype = ctypes.wintypes.BOOL
HeapFree.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID]

_process_heap: ctypes.wintypes.HANDLE = ctypes.wintypes.HANDLE(GetProcessHeap())
_executable_heap: ctypes.wintypes.HANDLE = None


def _normalize_address_range(address_range: Union[int, slice], size: int = 1) -> slice:
    """
    Converts an address/address range to a slice, verifying it has no step
    value. Optionaly can set the slice's size.
    """
    if isinstance(address_range, int):
        address_range = slice(address_range, None)
        
    if address_range.step is not None:
        raise ValueError('Address ranges do not support steps')
            
    if address_range.stop is None:
        address_range = slice(address_range.start, address_range.start + size)
    
    return address_range


def _initialize_executable_heap():
    global _executable_heap
    
    if _executable_heap is None:
        _executable_heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
        if not _executable_heap:
            raise WindowsError('Failed to create executable heap')
        
        _executable_heap = ctypes.wintypes.HANDLE(_executable_heap)


def _allocate_memory(heap: ctypes.wintypes.HANDLE, size: int) -> int:
    address = HeapAlloc(heap, HEAP_ZERO_MEMORY, size)
    if not address:
        raise WindowsError('Failed to allocate memory')
    
    return address


def _deallocate_memory(heap: ctypes.wintypes.HANDLE, address: int, size: int):
    HeapFree(heap, 0, address)
