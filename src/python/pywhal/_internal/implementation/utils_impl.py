import os
import re
from encodings import utf_8
from typing import Callable, Optional, Sequence
from . import process_memory_impl
from . import process_modules_impl
from ..windows_definitions import *
from ...library.process_modules import Module
from ...library.process import Process, CurrentProcess


PYTHON_DLL_PATTERN = re.compile(r'^python3\d+\.dll$')
PROCESS_INJECTION_ACCESS_RIGHTS = process_memory_impl.PROCESS_MEMORY_ACCESS_RIGHTS | PROCESS_CREATE_THREAD


def get_python_dll(process: Process = CurrentProcess) -> Module:
    process = process.with_access(process_memory_impl.PROCESS_MEMORY_ACCESS_RIGHTS)
    
    for module in process_modules_impl.iterate_modules(process):
        if PYTHON_DLL_PATTERN.match(module.name):
            return module
    
    raise LookupError('Could not find a loaded python DLL.')


def create_thread(process: Process, start_address: int, parameter: int) -> SafeHandle:
    process = process.with_access(PROCESS_CREATE_THREAD)
    
    thread = CreateRemoteThread(process.process_handle.handle, None, 0, LPTHREAD_START_ROUTINE(start_address), parameter, 0, None)
    if not thread:
        raise WindowsError('Could not create remote thread.')

    return SafeHandle(ctypes.wintypes.HANDLE(thread))


def get_thread_exit_code(thread_handle: SafeHandle):
    try:
        wait_for_multiple_objects([thread_handle], True, 0)
    except TimeoutError:
        return None
    
    exit_code = ctypes.wintypes.DWORD()
    if not GetExitCodeThread(thread_handle.handle, ctypes.pointer(exit_code)):
        raise WindowsError('Could not get thread exit code.')
    
    return exit_code


def wait_for_multiple_objects(handles: Sequence[SafeHandle], wait_all: bool, timeout: int) -> int:
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


def inject_thread(process: Process, start_address: int, parameter: int) -> int:
    with create_thread(process, start_address, parameter) as thread_handle:
        wait_for_multiple_objects([thread_handle], True, INFINITE)
        
        return get_thread_exit_code(thread_handle)


def wrap_remote_function(process: Process, remote_function_address: int) -> Callable[[Optional[int]], int]:
    process = process.with_access(PROCESS_INJECTION_ACCESS_RIGHTS)
    
    def _remote_function_wrapper(parameter: int = 0) -> int:
        return inject_thread(process, remote_function_address, parameter)
    
    return _remote_function_wrapper


def inject_dll_into_process(process: Process, dll_path: str) -> Module:
    if not os.path.exists(dll_path):
        raise FileNotFoundError(f'Could not find file at \'{dll_path}\'.')
    
    dll_path = os.path.abspath(dll_path)
    encoded_dll_path = utf_8.encode(dll_path + '\0')[0]
    
    process = process.with_access(PROCESS_INJECTION_ACCESS_RIGHTS)
    
    kernel32 = process_modules_impl.get_module(process, "kernel32.dll")
    
    LoadLibraryA_address = kernel32.exports['LoadLibraryA']

    with process_memory_impl.allocate_memory(process, len(encoded_dll_path)) as remote_memory:
        process_memory_impl.write_memory(process, remote_memory.address, encoded_dll_path)
        
        if 0 == inject_thread(process, LoadLibraryA_address, remote_memory.address):
            raise WindowsError('Could not load DLL in remote process.')

    return process_modules_impl.get_module(process, os.path.basename(dll_path))


def inject_python_into_process(process: Process, code: str) -> None:
    process = process.with_access(PROCESS_INJECTION_ACCESS_RIGHTS)
    
    try:
        python_dll = get_python_dll(process)
        
    except LookupError:
        local_python_dll = get_python_dll(CurrentProcess)
        python_dll = inject_dll_into_process(process, local_python_dll.path)
    
    Py_IsInitialized = wrap_remote_function(process, python_dll['Py_IsInitialized'])
    Py_InitializeEx = wrap_remote_function(process, python_dll['Py_InitializeEx'])
    PyRun_SimpleString = wrap_remote_function(process, python_dll['PyRun_SimpleString'])
    
    if not Py_IsInitialized():
        Py_InitializeEx(0)
    
    encoded_code = utf_8.encode(code + '\0')[0]
    with process_memory_impl.allocate_memory(process, len(encoded_code)) as remote_memory:
        process_memory_impl.write_memory(process, remote_memory.address, encoded_code)
        
        PyRun_SimpleString(remote_memory.address)
