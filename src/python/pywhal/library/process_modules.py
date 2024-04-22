import ctypes.wintypes
from typing import Generator, Union
from .process import Process, CurrentProcess
from .module import Module
from .._internal.implementation import process_modules_impl
from .._internal.implementation.process_memory_impl import PROCESS_MEMORY_ACCESS_RIGHTS


class ProcessModules:
    """
    Class for accessing and manipulating the modules of a process.
    """
    def __init__(self, process: Process):
        self._process = process.with_access(PROCESS_MEMORY_ACCESS_RIGHTS)

    def get_module(self, module_name: str, ) -> Module:
        return process_modules_impl.get_module(self._process, module_name)

    def load_module(self, module_name: str) -> Module:
        return process_modules_impl.load_module(self._process, module_name)

    def unload_module(self, module: Union[str, Module, ctypes.wintypes.HMODULE]) -> None:
        if isinstance(module, str):
            module = self.get_module(module)
        
        if isinstance(module, Module):
            module = module._module_handle

        process_modules_impl.unload_module(module)
    
    def iterate_modules(self) -> Generator[Module, None, None]:
        yield from process_modules_impl.iterate_modules(self._process)
    
    def __getitem__(self, module_name: str) -> Module:
        return self.get_module(module_name)
    
    def __iter__(self) -> Generator[Module, None, None]:
        yield from self.iterate_modules()


CurrentProcessModules = ProcessModules(CurrentProcess)
