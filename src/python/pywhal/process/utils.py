import os
import re
import time
from encodings import utf_8
from typing import Sequence
from .memory import ProcessMemory, PROCESS_MEMORY_ACCESS
from .modules import Module, ProcessModules
from .processes import Process, CurrentProcess
from .._internal.windows_definitions import *


class Utils:
    """
    Class contianing various utilities for processes.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """
    def __new__(cls):
        raise TypeError('The Utils class cannot be instantiated.')
    
    @staticmethod
    def get_python_dll(process: Process = CurrentProcess) -> Module:
        """
        Returns the python3.x.dll module currently being used by a process.
        If there are multiple Python DLLs loaded into the process, returns the first one.
        """
        return _get_python_dll(process)

    @staticmethod
    def create_thread(start_address: int, parameter: int = 0, process: Process = CurrentProcess) -> SafeHandle:
        """
        Creates a thread in the specified process and returns a handle to it.
        """
        return _create_thread(process, start_address, parameter)

    @staticmethod
    def wait_for_handles(handles: Sequence[SafeHandle], wait_all: bool, timeout: int = INFINITE) -> int:
        """
        Waits on all of the given handles.
        If NOT waiting for all of them, returns the index of the signaled handled.
        Otherwise returns zero.
        """
        return _wait_for_multiple_objects(handles, wait_all, timeout)

    @staticmethod
    def inject_thread(start_address: int, parameter: int = 0, process: Process = CurrentProcess) -> int:
        """
        Creates a thread in the specified process and waits for it to finish.
        Returns the exit code of the thread.
        """
        return _inject_thread(process, start_address, parameter)

    @staticmethod
    def inject_dll_into_process(process: Process, dll_path: str) -> Module:
        """
        Injects the DLL at the given path into the given process.
        """
        return _inject_dll_into_process(process, dll_path)
    
    @staticmethod
    def inject_python_into_process(process: Process, code: str) -> None:
        """
        Injects the Python interpreter into the given process and executes the given code.
        """
        return _inject_python_into_process(process, code)


PYTHON_DLL_PATTERN = re.compile(r'^python3\d+\.dll$')
INJECTION_PROCESS_ACCESS_RIGHTS = PROCESS_MEMORY_ACCESS | PROCESS_CREATE_THREAD


def _get_python_dll(process: Process = CurrentProcess) -> Module:
    process = process.with_access(PROCESS_MEMORY_ACCESS)
    process_modules = ProcessModules(process)
    
    for module in process_modules:
        if PYTHON_DLL_PATTERN.match(module.name):
            return module
    
    raise LookupError('Could not find a loaded python DLL.')


def _create_thread(process: Process, start_address: int, parameter: int) -> SafeHandle:
    process = process.with_access(PROCESS_CREATE_THREAD)
    
    thread = CreateRemoteThread(process.process_handle.handle, None, 0, LPTHREAD_START_ROUTINE(start_address), parameter, 0, None)
    if not thread:
        raise WindowsError('Could not create remote thread.')

    return SafeHandle(ctypes.wintypes.HANDLE(thread))


def _get_thread_exit_code(thread_handle: SafeHandle):
    try:
        _wait_for_multiple_objects([thread_handle], True, 0)
    except TimeoutError:
        return None
    
    exit_code = ctypes.wintypes.DWORD()
    if not GetExitCodeThread(thread_handle.handle, ctypes.pointer(exit_code)):
        raise WindowsError('Could not get thread exit code.')
    
    return exit_code


def _wait_for_multiple_objects(handles: Sequence[SafeHandle], wait_all: bool, timeout: int) -> int:
    raw_handles = [safe_handle.handle for safe_handle in handles]
    
    handles_array_type = ctypes.wintypes.HANDLE * len(handles)
    handles_array = handles_array_type(*raw_handles)

    result = WaitForMultipleObjects(len(handles), handles_array, wait_all, timeout)
    
    if WAIT_OBJECT_0 <= result < (WAIT_OBJECT_0 + len(handles)):
        return result - WAIT_OBJECT_0
    
    if WAIT_ABANDONED_0 <= result < (WAIT_ABANDONED_0 + len(handles)):
        return result - WAIT_ABANDONED_0
    
    if WAIT_TIMEOUT == result:
        raise TimeoutError('WaitForMultipleObjects timed out.')
    
    raise WindowsError('Could not wait for multiple objects.')


def _inject_thread(start_address: int, parameter: int = 0, process: Process = CurrentProcess) -> int:
    with _create_thread(process, start_address, parameter) as thread_handle:
        _wait_for_multiple_objects([thread_handle], True, INFINITE)
        
        return _get_thread_exit_code(thread_handle)


def _inject_dll_into_process(process: Process, dll_path: str) -> Module:
    if not os.path.exists(dll_path):
        raise FileNotFoundError(f'Could not find file at \'{dll_path}\'.')
    
    dll_path = os.path.abspath(dll_path)
    encoded_dll_path = utf_8.encode(dll_path + '\0')[0]
    
    process = process.with_access(INJECTION_PROCESS_ACCESS_RIGHTS)
    
    process_memory = ProcessMemory(process)
    process_modules = ProcessModules(process)
    
    kernel32 = process_modules["kernel32.dll"]
    
    LoadLibraryA_address = kernel32.exports['LoadLibraryA']

    with process_memory.allocate(len(encoded_dll_path)) as remote_memory:
        process_memory.write(remote_memory.address, encoded_dll_path)
        
        if 0 == _inject_thread(process, LoadLibraryA_address, remote_memory.address):
            raise WindowsError('Could not load DLL in remote process.')

    return process_modules[os.path.basename(dll_path)]


def _inject_python_into_process(process: Process, code: str) -> None:
    process = process.with_access(INJECTION_PROCESS_ACCESS_RIGHTS)
    process_memory = ProcessMemory(process)
    
    try:
        python_dll = _get_python_dll(process)
        
    except LookupError:
        python_dll = _inject_dll_into_process(process, _get_python_dll(CurrentProcess))
    
    remote_function = lambda function_address: lambda parameter = 0: _inject_thread(function_address, parameter, process)
    
    Py_IsInitialized = remote_function(python_dll['Py_IsInitialized'])
    Py_InitializeEx = remote_function(python_dll['Py_InitializeEx'])
    PyRun_SimpleString = remote_function(python_dll['PyRun_SimpleString'])
    
    if not Py_IsInitialized():
        Py_InitializeEx(0)
    
    encoded_code = utf_8.encode(code + '\0')[0]
    with process_memory.allocate(len(encoded_code)) as remote_memory:
        process_memory.write(remote_memory.address, encoded_code)
        
        PyRun_SimpleString(remote_memory.address)
