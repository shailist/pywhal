from typing import Generator, Union
from .process import Process
from .._internal.implementation import processes_impl
from .._internal.windows_definitions import PROCESS_QUERY_INFORMATION


class ProcessesMeta(type):
    """
    Convenience metaclass to allow accessing Processes's functionality
    via square brackets syntax (Processes['kernel32']).
    """
    def __getitem__(cls, process_identifier: Union[str, int]) -> Process:
        return Processes.get_process(process_identifier)
    
    def __iter__(self) -> Generator[Process, None, None]:
        yield from processes_impl.iterate_processes()


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
