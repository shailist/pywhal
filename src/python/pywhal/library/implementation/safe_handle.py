import ctypes.wintypes
from .safe_resource import SafeResource


class SafeHandle(SafeResource):
    def __init__(self, handle: ctypes.wintypes.HANDLE, managed: bool = True):
        from .windows_definitions import CloseHandle
        
        super().__init__(handle, CloseHandle if managed else None)
    
    @property
    def handle(self) -> ctypes.wintypes.HANDLE:
        return self.resource
