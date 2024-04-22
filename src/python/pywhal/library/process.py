import os
from typing import Optional
from .._internal.implementation import process_impl
from .._internal.implementation.process_handle_impl import ProcessHandle
from .._internal.windows_definitions import CurrentProcessId, CurrentProcessHandle, PROCESS_QUERY_INFORMATION, PROCESS_ALL_ACCESS


class Process(process_impl.ProcessBase):
    def __init__(self,
                 pid: Optional[int] = None,
                 process_handle: Optional[ProcessHandle] = None,
                 desired_access: int = PROCESS_QUERY_INFORMATION,
                 image_path: Optional[str] = None,
                 image_name: Optional[str] = None):
        super().__init__(pid, process_handle ,desired_access)
        
        self._image_path = image_path
        self._image_name = image_name
        self._is_32bit = None
        self._is_current_process = None

    @property
    def image_path(self) -> str:
        if self._image_path is None:
            self._image_path = process_impl.get_process_image_path(self)
        
        return self._image_path
    
    @property
    def image_name(self) -> str:
        if self._image_name is None:
            self._image_name = os.path.basename(self.image_path)
        
        return self._image_name

    @property
    def is_32bit(self) -> bool:
        if self._is_32bit is None:
            self._is_32bit = process_impl.is_process_32bit(self)
        
        return self._is_32bit

    @property
    def is_current_process(self) -> bool:
        if self._is_current_process is None:
            self._is_current_process = (self.pid == CurrentProcessId)
        
        return self._is_current_process

    def with_access(self, desired_access: int):
        if (self._desired_access & desired_access) == desired_access:
            return self
        
        return Process(self.pid, None, desired_access, self._image_path, self._image_name)

    def __repr__(self) -> str:
        return f'<Process   {self.pid:>5} / 0x{self.pid:<4x}   \'{self.image_name}\'>'


CurrentProcess = Process(CurrentProcessId, CurrentProcessHandle, PROCESS_ALL_ACCESS)
