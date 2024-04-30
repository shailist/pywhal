from typing import Optional
from .process_handle_impl import ProcessHandle
from .safe_resource import SafeResource
from .windows_definitions import *


class ProcessBase(SafeResource):
    def __init__(self,
                 pid: Optional[int] = None,
                 process_handle: Optional[ProcessHandle] = None,
                 desired_access: int = PROCESS_QUERY_INFORMATION):
        assert (pid is not None) or (process_handle is not None), 'You must supply either a PID or a process handle.'
        
        super().__init__(self, ProcessBase._release)
        
        self._pid = pid
        self._process_handle = process_handle
        self._desired_access = desired_access

    @property
    def pid(self) -> int:
        if self._pid is None:
            self._pid = self.process_handle.pid
        
        return self._pid

    @property
    def process_handle(self) -> ProcessHandle:
        if self._process_handle is None:
            self._process_handle = open_process(self.pid, self._desired_access)
        
        return self._process_handle
    
    def _release(self) -> None:
        if self._process_handle is not None:
            self._process_handle.release()


def open_process(pid: int, desired_access: int) -> ProcessHandle:
    process_handle = OpenProcess(desired_access, False, pid)
    if not process_handle:
        raise WindowsError('Could not open process.')

    return ProcessHandle(ctypes.wintypes.HANDLE(process_handle), pid=pid)


def get_process_image_path(process: ProcessBase) -> str:
    from .process_modules_impl import Module, SafeModuleHandle
    
    executable_module = Module(process, SafeModuleHandle(0))
    return executable_module.path


def is_process_32bit(process: ProcessBase) -> bool:
    is_32bit = ctypes.wintypes.BOOL()
    if not IsWow64Process(process.process_handle.handle, ctypes.pointer(is_32bit)):
        raise WindowsError('Could not determine if process is 32bit.')
    
    return bool(is_32bit)
