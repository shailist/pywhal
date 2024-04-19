import ctypes
from typing import Optional, Union


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
        address_range = cls._normalize_address_range(address_range)
        
        address = address_range.start
        size = address_range.stop - address_range.start
        
        buffer_type = ctypes.c_char * size
        
        return buffer_type.from_address(address)

    @classmethod
    def read(cls, address_range: Union[int, slice]) -> bytes:
        return cls.get_memory(address_range).raw

    @classmethod
    def write(cls, address_range: Union[int, slice], data: Union[bytes, bytearray]) -> None:
        address_range = cls._normalize_address_range(address_range, len(data))
        cls.get_memory(address_range)[:] = data
    
    @staticmethod
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
