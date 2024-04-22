import ctypes.wintypes
from .safe_resource import SafeResource


class SafeModuleHandle(SafeResource):
    def __init__(self, handle: ctypes.wintypes.HMODULE, managed: bool = False):
        from .windows_definitions import FreeLibrary
        super().__init__(handle, FreeLibrary if managed else None)
    
    @property
    def handle(self) -> ctypes.wintypes.HMODULE:
        return self.resource
