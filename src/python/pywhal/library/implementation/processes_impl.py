import ctypes
from encodings import utf_8
from typing import Generator
from .windows_definitions import *
from ..process import Process


def iterate_processes() -> Generator[Process, None, None]:
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot:
        raise WindowsError('Could not create processes snapshot.')
    
    try:
        process_entry = PROCESSENTRY32()
        process_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        process_ptr = ctypes.pointer(process_entry)
        
        if not Process32First(snapshot, process_ptr):
            raise WindowsError('Could not get first process.')
        
        yield Process(process_entry.th32ProcessID, image_name=utf_8.decode(process_entry.szExeFile)[0])
        
        while Process32Next(snapshot, process_ptr):
            yield Process(process_entry.th32ProcessID, image_name=utf_8.decode(process_entry.szExeFile)[0])
        
        if GetLastError() != ERROR_NO_MORE_FILES:
            raise WindowsError('Could not get next process.')
        
    finally:
        CloseHandle(snapshot)
