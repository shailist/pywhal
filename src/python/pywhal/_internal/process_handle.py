import ctypes.wintypes
from typing import Optional
from .safe_handle import SafeHandle


class ProcessHandle(SafeHandle):
    def __init__(self, handle: ctypes.wintypes.HANDLE, managed: bool = True, pid: Optional[int] = None):
        super().__init__(handle, managed)
        self._pid = pid
        self._is_current_process = None
    
    @property
    def pid(self):
        if self._pid is None:
            self._pid = _get_process_pid(self.handle)
        
        return self._pid
    
    @property
    def is_current_process(self):
        from .windows_definitions import CurrentProcessId
        
        if self._is_current_process is None:
            self._is_current_process = (self.pid == CurrentProcessId)
        
        return self._is_current_process
        
    
    def reopen(self, desired_access: int):
        return _open_process(self.pid, desired_access)


def _get_process_pid(process_handle: ProcessHandle) -> int:
    from .windows_definitions import GetProcessId
    
    pid = GetProcessId(process_handle.handle)
    if not pid:
        raise WindowsError('Could not get process id.')
    
    return pid


def _open_process(pid: int, desired_access: int) -> ProcessHandle:
    from .windows_definitions import OpenProcess
    
    process_handle = OpenProcess(desired_access, False, pid)
    if not process_handle:
        raise WindowsError('Could not open process.')

    return ProcessHandle(ctypes.wintypes.HANDLE(process_handle), pid=pid)
