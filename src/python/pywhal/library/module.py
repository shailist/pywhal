import os
from encodings import utf_8
from typing import Dict, Optional, Union
from .process import Process
from .._internal.implementation import module_impl
from .._internal.implementation.process_memory_impl import PROCESS_MEMORY_ACCESS_RIGHTS
from .._internal.safe_module_handle import SafeModuleHandle
from .._internal.safe_resource import SafeResource
from .._internal.windows_definitions import IMAGE_NT_HEADERS_ANY


class Module(SafeResource):
    def __init__(self, process: Process, module_handle: SafeModuleHandle,
                 module_path: Optional[str] = None, module_name: Optional[str] = None):
        from .._internal.implementation.process_modules_impl import unload_module
        super().__init__((process.with_access(PROCESS_MEMORY_ACCESS_RIGHTS), module_handle),
                         unload_module if module_handle.is_managed else None)
        self._module_path = module_path
        self._module_name = module_name
        
        self._nt_headers = None
        self._virtual_size = None
        self._exports = None

    def get_export(self, export_name: Union[int, str]) -> int:
        return self.exports[export_name]

    @property
    def _process(self) -> Process:
        return self.resource[0]

    @property
    def _module_handle(self) -> SafeModuleHandle:
        return self.resource[1]

    @property
    def path(self) -> str:
        if self._module_path is None:
            module_name = module_impl.get_module_name(self._process, self._module_handle)
            self._module_path = utf_8.decode(module_name)[0]
        
        return self._module_path

    @property
    def name(self) -> str:
        if self._module_name is None:
            self._module_name = os.path.basename(self.path)
        
        return self._module_name

    @property
    def address(self) -> int:
        return self._module_handle.address

    @property
    def nt_headers(self) -> IMAGE_NT_HEADERS_ANY:
        if self._nt_headers is None:
            self._nt_headers = module_impl.get_module_nt_headers(self._process, self.address)
        
        return self._nt_headers[1]

    @property
    def virtual_size(self) -> int:
        if self._virtual_size is None:
            self._virtual_size = module_impl.get_module_virtual_size(self.nt_headers)
        
        return self._virtual_size
    
    @property
    def exports(self) -> Dict[Union[int, str], int]:
        if self._exports is None:
            self._exports = module_impl.get_module_exports(self._process, self.address, self.nt_headers)
        
        return self._exports

    def __getitem__(self, export_name: Union[int, str]) -> int:
        return self.get_export(export_name)
    
    def __repr__(self) -> str:
        return f'<Module \'{self.name}\' @ {hex(self.address)}>'
