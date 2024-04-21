import ctypes
import os
from encodings import utf_8
from typing import Generator, Union, Optional
from .._internal.windows_definitions import *


class Process:
    def __init__(self,
                 pid: Optional[int] = None,
                 process_handle: Optional[ctypes.wintypes.HANDLE] = None,
                 desired_access: int = PROCESS_QUERY_INFORMATION,
                 image_path: Optional[str] = None,
                 image_name: Optional[str] = None):
        assert (pid is not None) or (process_handle is not None), 'You must supply either a PID or a process handle.'
        
        self._pid = pid
        self._process_handle = process_handle
        self._desired_access = desired_access
        
        self._image_path = image_path
        self._image_name = image_name
        self._is_32bit = None

    @property
    def pid(self) -> int:
        if self._pid is None:
            self._pid = _get_process_pid(self.process_handle)
        
        return self._pid

    @property
    def image_path(self) -> str:
        if self._image_path is None:
            self._image_path = _get_process_image_path(self.process_handle)
        
        return self._image_path
    
    @property
    def image_name(self) -> str:
        if self._image_name is None:
            self._image_name = os.path.basename(self.image_path)
        
        return self._image_name

    @property
    def is_32bit(self) -> bool:
        if self._is_32bit is None:
            self._is_32bit = _is_process_32bit(self.process_handle)
        
        return self._is_32bit

    @property
    def process_handle(self) -> ctypes.wintypes.HANDLE:
        if self._process_handle is None:
            self._process_handle = _open_process(self.pid, self._desired_access)
        
        return self._process_handle

    def __repr__(self) -> str:
        return f'<Process   {self.pid:>5} / 0x{self.pid:<4x}   \'{self.image_name}\'>'


class ProcessesMeta(type):
    """
    Convenience metaclass to allow accessing Processes's functionality
    via square brackets syntax (Processes['kernel32']).
    """
    def __getitem__(cls, process_identifier: Union[str, int]) -> Process:
        return Processes.get_process(process_identifier)
    
    def __iter__(self) -> Generator[Process, None, None]:
        yield from _iterate_processes()


class Processes(metaclass=ProcessesMeta):
    """
    Class for accessing and manipulating processes.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """
    def __new__(cls):
        raise TypeError('The Processes class cannot be instantiated.')

    @classmethod
    def get_process(cls, process_identifier: Union[str, int], desired_access: int = PROCESS_QUERY_INFORMATION) -> Process:
        if isinstance(process_identifier, str):
            process_identifier = process_identifier.lower()
            get_identifier = lambda process: process.image_name.lower()
        else:
            get_identifier = lambda process: process.pid
            
        for process in Processes:
            if get_identifier(process) == process_identifier:
                process._desired_access = desired_access
                return process
            
        raise WindowsError(f'Could not find process \'{process_identifier}\'.')
    
    @classmethod
    def get_current_process(cls) -> Process:
        return Process(process_handle=GetCurrentProcess())


def _get_process_pid(process_handle: ctypes.wintypes.HANDLE) -> int:
    pid = GetProcessId(process_handle)
    if not pid:
        raise WindowsError('Could not get process id.')
    
    return pid

def _get_process_image_path(process_handle: ctypes.wintypes.HANDLE) -> str:
    from .modules import Module
    
    executable_module = Module(process_handle, ctypes.wintypes.HMODULE(None))
    return executable_module.path


def _is_process_32bit(process_handle: ctypes.wintypes.HANDLE) -> bool:
    is_32bit = ctypes.wintypes.BOOL()
    if not IsWow64Process(process_handle, ctypes.pointer(is_32bit)):
        raise WindowsError('Could not determine if process is 32bit.')
    
    return bool(is_32bit)


def _open_process(pid: int, desired_access: int) -> ctypes.wintypes.HANDLE:
    process_handle = OpenProcess(desired_access, False, pid)
    if not process_handle:
        raise WindowsError('Could not open process.')

    return ctypes.wintypes.HANDLE(process_handle)


def _iterate_processes() -> Generator[Process, None, None]:
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot:
        raise WindowsError('Could not create processes snapshot.')
    
    try:
        process = PROCESSENTRY32()
        process.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        process_ptr = ctypes.pointer(process)
        
        if not Process32First(snapshot, process_ptr):
            raise WindowsError('Could not get first process.')
        
        yield Process(process.th32ProcessID, image_name=utf_8.decode(process.szExeFile)[0])
        
        while Process32Next(snapshot, process_ptr):
            yield Process(process.th32ProcessID, image_name=utf_8.decode(process.szExeFile)[0])
        
        if GetLastError() != ERROR_NO_MORE_FILES:
            raise WindowsError('Could not get next process.')
        
    finally:
        CloseHandle(snapshot)
