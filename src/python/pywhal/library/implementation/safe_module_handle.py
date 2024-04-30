from .safe_resource import SafeResource


class SafeModuleHandle(SafeResource):
    def __init__(self, base_address, managed: bool = False):
        from .windows_definitions import FreeLibrary
        super().__init__(base_address, FreeLibrary if managed else None)
    
    @property
    def handle(self) -> int:
        return self.resource
    
    @property
    def address(self) -> int:
        return self.handle
