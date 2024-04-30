from typing import Callable, Optional
from .implementation.safe_resource import SafeResource


class MemoryBlock(SafeResource):
    def __init__(self, address: int, size: int, deallocator: Optional[Callable[[int, int], None]] = None):
        super().__init__((address, size), deallocator)
    
    @property
    def address(self) -> int:
        return self.resource[0]
    
    @property
    def size(self) -> int:
        return self.resource[1]
