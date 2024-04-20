import ctypes
import ctypes.wintypes
from typing import TypeAlias

ERROR_NO_MORE_FILES = 18
ERROR_INSUFFICIENT_BUFFER = 122

MAX_MODULE_NAME32 = 255
MAX_PATH = 260
MAX_LONG_PATH_LENGTH = 32767

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008

STANDARD_RIGHTS_REQUIRED = 0x000F0000

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.wintypes.DWORD),
        ('th32ModuleID', ctypes.wintypes.DWORD),
        ('th32ProcessID', ctypes.wintypes.DWORD),
        ('GlblcntUsage', ctypes.wintypes.DWORD),
        ('ProccntUsage', ctypes.wintypes.DWORD),
        ('modBaseAddr', ctypes.wintypes.PBYTE),
        ('modBaseSize', ctypes.wintypes.DWORD ),
        ('hModule', ctypes.wintypes.HMODULE),
        ('szModule', ctypes.wintypes.CHAR * (MAX_MODULE_NAME32 + 1)),
        ('szExePath', ctypes.wintypes.CHAR * MAX_PATH)
    ]
    
LPMODULEENTRY32 = ctypes.POINTER(MODULEENTRY32)

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', ctypes.wintypes.DWORD),
        ('cntUsage', ctypes.wintypes.DWORD),
        ('th32ProcessID', ctypes.wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', ctypes.wintypes.DWORD),
        ('cntThreads', ctypes.wintypes.DWORD),
        ('th32ParentProcessID', ctypes.wintypes.DWORD),
        ('pcPriClassBase', ctypes.wintypes.LONG),
        ('dwFlags', ctypes.wintypes.DWORD),
        ('szExeFile', ctypes.wintypes.CHAR * MAX_PATH)
    ]

LPPROCESSENTRY32 = ctypes.POINTER(PROCESSENTRY32)

FARPROC = ctypes.WINFUNCTYPE(ctypes.c_size_t)

GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = ctypes.wintypes.HANDLE
GetCurrentProcess.argtypes = []

GetCurrentProcessId = ctypes.windll.kernel32.GetCurrentProcessId
GetCurrentProcessId.restype = ctypes.wintypes.DWORD
GetCurrentProcessId.argtypes = []

CurrentProcess = ctypes.wintypes.HANDLE(GetCurrentProcess())
CurrentProcessId = GetCurrentProcessId()



GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, ctypes.wintypes.LPCSTR]

GetModuleHandleA = ctypes.windll.kernel32.GetModuleHandleA
GetModuleHandleA.restype = ctypes.wintypes.HMODULE
GetModuleHandleA.argtypes = [ctypes.wintypes.LPCSTR]

GetModuleFileNameExA = ctypes.windll.kernel32.K32GetModuleFileNameExA
GetModuleFileNameExA.restype = ctypes.wintypes.DWORD
GetModuleFileNameExA.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HMODULE, ctypes.wintypes.LPSTR, ctypes.wintypes.DWORD]

LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
LoadLibraryA.restype = ctypes.wintypes.HMODULE
LoadLibraryA.argtypes = [ctypes.wintypes.LPCSTR]

FreeLibrary = ctypes.windll.kernel32.FreeLibrary
FreeLibrary.restype = ctypes.wintypes.BOOL
FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]

CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
CreateToolhelp32Snapshot.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]

Module32First = ctypes.windll.kernel32.Module32First
Module32First.restype = ctypes.wintypes.BOOL
Module32First.argtypes = [ctypes.wintypes.HANDLE, LPMODULEENTRY32]

Module32Next = ctypes.windll.kernel32.Module32Next
Module32Next.restype = ctypes.wintypes.BOOL
Module32Next.argtypes = [ctypes.wintypes.HANDLE, LPMODULEENTRY32]

Process32First = ctypes.windll.kernel32.Process32First
Process32First.restype = ctypes.wintypes.BOOL
Process32First.argtypes = [ctypes.wintypes.HANDLE, LPPROCESSENTRY32]

Process32Next = ctypes.windll.kernel32.Process32Next
Process32Next.restype = ctypes.wintypes.BOOL
Process32Next.argtypes = [ctypes.wintypes.HANDLE, LPPROCESSENTRY32]

CloseHandle = ctypes.windll.kernel32.CloseHandle
CloseHandle.restype = ctypes.wintypes.BOOL
CloseHandle.argtypes = [ctypes.wintypes.HANDLE]

GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.restype = ctypes.wintypes.DWORD
GetLastError.argtypes = []

GetProcessId = ctypes.windll.kernel32.GetProcessId
GetProcessId.restype = ctypes.wintypes.DWORD
GetProcessId.argtypes = [ctypes.wintypes.HANDLE]

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.restype = ctypes.wintypes.HANDLE
OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
