import os
import sys
from encodings import utf_8
from typing import Callable, Optional, Sequence
from . import process_memory_impl
from . import process_modules_impl
from .windows_definitions import *
from ..process import Process, CurrentProcess
from ..process_modules import Module
from ... import rpyc_service


PROCESS_INJECTION_ACCESS_RIGHTS = process_memory_impl.PROCESS_MEMORY_ACCESS_RIGHTS | PROCESS_CREATE_THREAD


def get_python_dll_name() -> str:
    version = sys.version_info
    return f'python{version.major}{version.minor}.dll'


def get_python_dll(process: Process = CurrentProcess) -> Module:
    process = process.with_access(process_memory_impl.PROCESS_MEMORY_ACCESS_RIGHTS)
    
    python_dll_name = get_python_dll_name()
    return process_modules_impl.get_module(process, python_dll_name)


def create_thread(process: Process, start_address: int, parameter: int) -> SafeHandle:
    process = process.with_access(PROCESS_CREATE_THREAD)
    
    thread = CreateRemoteThread(process.process_handle.handle, None, 0, LPTHREAD_START_ROUTINE(start_address), parameter, 0, None)
    if not thread:
        raise WindowsError('Could not create remote thread.')

    return SafeHandle(ctypes.wintypes.HANDLE(thread))


def get_thread_exit_code(thread_handle: SafeHandle) -> int:
    try:
        wait_for_multiple_objects([thread_handle], True, 0)
    except TimeoutError:
        return None
    
    exit_code = ctypes.wintypes.DWORD()
    if not GetExitCodeThread(thread_handle.handle, ctypes.pointer(exit_code)):
        raise WindowsError('Could not get thread exit code.')
    
    return exit_code.value


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


def inject_thread(process: Process, start_address: int, parameter: int, wait: bool = True) -> int:
    with create_thread(process, start_address, parameter) as thread_handle:
        if wait:
            wait_for_multiple_objects([thread_handle], True, INFINITE)
        
        return get_thread_exit_code(thread_handle)


def wrap_remote_function(process: Process, remote_function_address: int, wait: bool = True) -> Callable[[Optional[int]], int]:
    process = process.with_access(PROCESS_INJECTION_ACCESS_RIGHTS)
    
    def _remote_function_wrapper(parameter: int = 0) -> int:
        return inject_thread(process, remote_function_address, parameter, wait)
    
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


def find_python_dll_for_injection(process: Process) -> str:
    """
    Finds a python dll for injection into the given process.
    Returns its path.
    """
    if process.is_32bit == CurrentProcess.is_32bit:
        local_python_dll = get_python_dll(CurrentProcess)
        return local_python_dll.path
    


def inject_python_into_process(process: Process, code: str, wait: bool = True) -> None:
    process = process.with_access(PROCESS_INJECTION_ACCESS_RIGHTS)
    
    try:
        python_dll = get_python_dll(process)
        python_dll_path = python_dll.path
        
    except (LookupError, WindowsError):
        local_python_dll = get_python_dll(CurrentProcess)
        python_dll_path = local_python_dll.path
        vcruntime_140_dll_path = os.path.join(os.path.dirname(python_dll_path), 'vcruntime140.dll')
        inject_dll_into_process(process, vcruntime_140_dll_path)
        python_dll = inject_dll_into_process(process, python_dll_path)
    
    Py_IsInitialized = python_dll['Py_IsInitialized']
    Py_Initialize = python_dll['Py_Initialize']
    PyGILState_Ensure = python_dll['PyGILState_Ensure']
    PyRun_SimpleString = python_dll['PyRun_SimpleString']
    PyGILState_Release = python_dll['PyGILState_Release']
    
    encoded_code = utf_8.encode(code + '\0')[0]
    with process_memory_impl.allocate_memory(process, len(encoded_code)) as remote_python_code:
        process_memory_impl.write_memory(process, remote_python_code.address, encoded_code)
        
        if not wait:
            remote_python_code.detach()
    
        import keystone
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        shellcode, _ = ks.asm(f"""
            # Prepare stack space, for some reason
            push rcx
            push rcx
            push rcx
            push rcx
            push rcx
            
            # Back up registers
            push rcx
            push r15

            # Check if Python is initialized
            mov  rax, {Py_IsInitialized}
            call rax
            cmp  rax, 0
            jnz  SKIP_INITIALIZATION

            # Initialize Python
            mov  rax, {Py_Initialize}
            call rax

            SKIP_INITIALIZATION:

            # Ensure GIL state
            mov  rax, {PyGILState_Ensure}
            call rax
            mov  r15, rax  # r15 = gil_state

            # Execute Python code
            mov  rcx, {remote_python_code.address}
            mov  rax, {PyRun_SimpleString}
            call rax
            mov  rcx, rax  # rcx = exec_result

            # Release GIL state
            mov  rax, r15  # swap rcx and r15
            mov  r15, rcx  # - rcx = gil_state
            mov  rcx, rax  # - r15 = exec_result
            mov  rax, {PyGILState_Release}
            call rax
            
            # Restore registers and return
            mov  rax, r15
            pop  r15
            pop  rcx
            
            pop  rcx
            pop  rcx
            pop  rcx
            pop  rcx
            pop  rcx
            
            ret
        """, as_bytes=True)
        
        with process_memory_impl.allocate_memory(process, len(shellcode), executable=True) as remote_shellcode:
            process_memory_impl.write_memory(process, remote_shellcode.address + 0x20, shellcode)
            
            if not wait:
                remote_shellcode.detach()
            
            if inject_thread(process, remote_shellcode.address, 0, wait=wait) != 0 and wait:
                raise Exception('Could not execute python code')


def inject_pywhal_into_process(process: Process) -> rpyc_service.API:
    code = """
import pywhal.rpyc_service
pywhal.rpyc_service.run_server()
"""
    inject_python_into_process(process, code, wait=False)
    return rpyc_service.connect_client()
