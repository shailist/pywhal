from typing import Union
from .memory_block import MemoryBlock
from .process import Process, CurrentProcess
from .._internal.implementation import process_memory_impl


class ProcessMemory:
    """
    Class for accessing and manipulating the memory of a process.
    """
    def __init__(self, process: Process):
        self._process = process.with_access(process_memory_impl.PROCESS_MEMORY_ACCESS_RIGHTS)
    
    def read(self, address_range: Union[int, slice]) -> bytes:
        return process_memory_impl.read_memory(self._process, address_range)

    def write(self, address_range: Union[int, slice], data: bytes) -> None:
        process_memory_impl.write_memory(self._process, address_range, data)
    
    def allocate(self, size: int, executable: bool = False) -> MemoryBlock:
        return process_memory_impl.allocate_memory(self._process, size, executable)
    
    def read_null_terminated_array(self, address: int, element_size: int) -> bytes:
        """
        Reads an array that is terminated by a null entry.
        The array is of elements of size element_size.
        Returns the raw bytes of the array.
        """
        return process_memory_impl.read_null_terminated_array(self._process, address, element_size)
    
    def __getitem__(self, address_range: Union[int, slice]) -> bytes:
        return self.read(address_range)

    def __setitem__(self, address_range: Union[int, slice], data: bytes) -> None:
        return self.write(address_range, data)


CurrentProcessMemory = ProcessMemory(CurrentProcess)
