from typing import Sequence
from .implementation import utils_impl
from .implementation.safe_handle import SafeHandle
from .implementation.windows_definitions import INFINITE
from .process_modules import Module
from .process import Process, CurrentProcess
from .. import rpyc_service


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
        return utils_impl.get_python_dll(process)

    @staticmethod
    def create_thread(start_address: int, parameter: int = 0, process: Process = CurrentProcess) -> SafeHandle:
        """
        Creates a thread in the specified process and returns a handle to it.
        """
        return utils_impl.create_thread(process, start_address, parameter)

    @staticmethod
    def wait_for_handles(handles: Sequence[SafeHandle], wait_all: bool, timeout: int = INFINITE) -> int:
        """
        Waits on all of the given handles.
        If NOT waiting for all of them, returns the index of the signaled handled.
        Otherwise returns zero.
        """
        return utils_impl.wait_for_multiple_objects(handles, wait_all, timeout)

    @staticmethod
    def inject_thread(start_address: int, parameter: int = 0, process: Process = CurrentProcess, wait: bool = True) -> int:
        """
        Creates a thread in the specified process and waits for it to finish.
        Returns the exit code of the thread.
        """
        return utils_impl.inject_thread(process, start_address, parameter, wait)

    @staticmethod
    def inject_dll_into_process(process: Process, dll_path: str) -> Module:
        """
        Injects the DLL at the given path into the given process.
        """
        return utils_impl.inject_dll_into_process(process, dll_path)
    
    @staticmethod
    def inject_python_into_process(process: Process, code: str, wait: bool = True) -> None:
        """
        Injects the Python interpreter into the given process and executes the given code.
        """
        return utils_impl.inject_python_into_process(process, code, wait)

    @staticmethod
    def inject_pywhal_into_process(process: Process) -> rpyc_service.API:
        return utils_impl.inject_pywhal_into_process(process)
