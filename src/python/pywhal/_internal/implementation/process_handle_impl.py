import ctypes.wintypes
from typing import Optional
from ..safe_handle import SafeHandle


class ProcessHandle(SafeHandle):
    def __init__(self, handle: ctypes.wintypes.HANDLE, managed: bool = True, pid: Optional[int] = None):
        super().__init__(handle, managed)
        self._pid = pid
        self._is_current_process = None
    
    @property
    def pid(self):
        if self._pid is None:
            self._pid = get_process_pid(self.handle)
        
        return self._pid
    
    @property
    def is_current_process(self):
        if self._is_current_process is None:
            from ..windows_definitions import CurrentProcessId
            self._is_current_process = (self.pid == CurrentProcessId)
        
        return self._is_current_process


def get_process_pid(process_handle: ProcessHandle) -> int:
    from ..windows_definitions import GetProcessId
    
    pid = GetProcessId(process_handle.handle)
    if not pid:
        raise WindowsError('Could not get process id.')
    
    return pid
