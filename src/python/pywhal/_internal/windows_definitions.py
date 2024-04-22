import ctypes
import ctypes.wintypes
from typing import Union
from .process_handle import ProcessHandle
from .safe_handle import SafeHandle


#############
# Constants #
#############

ERROR_NO_MORE_FILES = 18
ERROR_INSUFFICIENT_BUFFER = 122

MAX_MODULE_NAME32 = 255
MAX_PATH = 260
MAX_LONG_PATH_LENGTH = 32767

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

SYNCHRONIZE = 0x00100000
STANDARD_RIGHTS_REQUIRED = 0x000F0000

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000  

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
HEAP_ZERO_MEMORY = 0x00000008

IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_DIRECTORY_ENTRY_EXPORT = 0

INFINITE = 0xFFFFFFFF

WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED_0 = 0x00000080
WAIT_TIMEOUT = 0x00000102


#########
# Types #
#########

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

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ('nLength', ctypes.wintypes.DWORD),
        ('lpSecurityDescriptor', ctypes.wintypes.LPVOID),
        ('bInheritHandle', ctypes.wintypes.BOOL)
    ]

LPSECURITY_ATTRIBUTES = ctypes.POINTER(SECURITY_ATTRIBUTES)

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic', ctypes.wintypes.WORD),
        ('e_cblp', ctypes.wintypes.WORD),
        ('e_cp', ctypes.wintypes.WORD),
        ('e_crlc', ctypes.wintypes.WORD),
        ('e_cparhdr', ctypes.wintypes.WORD),
        ('e_minalloc', ctypes.wintypes.WORD),
        ('e_maxalloc', ctypes.wintypes.WORD),
        ('e_ss', ctypes.wintypes.WORD),
        ('e_sp', ctypes.wintypes.WORD),
        ('e_csum', ctypes.wintypes.WORD),
        ('e_ip', ctypes.wintypes.WORD),
        ('e_cs', ctypes.wintypes.WORD),
        ('e_lfarlc', ctypes.wintypes.WORD),
        ('e_ovno', ctypes.wintypes.WORD),
        ('e_res', ctypes.wintypes.WORD * 4),
        ('e_oemid', ctypes.wintypes.WORD),
        ('e_oeminfo', ctypes.wintypes.WORD),
        ('e_res2', ctypes.wintypes.WORD * 10),
        ('e_lfanew', ctypes.wintypes.LONG)
    ]

PIMAGE_DOS_HEADER = ctypes.POINTER(IMAGE_DOS_HEADER)


class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ('Machine', ctypes.wintypes.WORD),
        ('NumberOfSections', ctypes.wintypes.WORD),
        ('TimeDateStamp', ctypes.wintypes.DWORD),
        ('PointerToSymbolTable', ctypes.wintypes.DWORD),
        ('NumberOfSymbols', ctypes.wintypes.DWORD),
        ('SizeOfOptionalHeader', ctypes.wintypes.WORD),
        ('Characteristics', ctypes.wintypes.WORD)
    ]

PIMAGE_FILE_HEADER = ctypes.POINTER(IMAGE_FILE_HEADER)


class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('VirtualAddress', ctypes.wintypes.DWORD),
        ('Size', ctypes.wintypes.DWORD)
    ]


class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ('Magic', ctypes.wintypes.WORD),
        ('MajorLinkerVersion', ctypes.wintypes.BYTE),
        ('MinorLinkerVersion', ctypes.wintypes.BYTE),
        ('SizeOfCode', ctypes.wintypes.DWORD),
        ('SizeOfInitializedData', ctypes.wintypes.DWORD),
        ('SizeOfUninitializedData', ctypes.wintypes.DWORD),
        ('AddressOfEntryPoint', ctypes.wintypes.DWORD),
        ('BaseOfCode', ctypes.wintypes.DWORD),
        ('BaseOfData', ctypes.wintypes.DWORD),
        ('ImageBase', ctypes.wintypes.DWORD),
        ('SectionAlignment', ctypes.wintypes.DWORD),
        ('FileAlignment', ctypes.wintypes.DWORD),
        ('MajorOperatingSystemVersion', ctypes.wintypes.WORD),
        ('MinorOperatingSystemVersion', ctypes.wintypes.WORD),
        ('MajorImageVersion', ctypes.wintypes.WORD),
        ('MinorImageVersion', ctypes.wintypes.WORD),
        ('MajorSubsystemVersion', ctypes.wintypes.WORD),
        ('MinorSubsystemVersion', ctypes.wintypes.WORD),
        ('Win32VersionValue', ctypes.wintypes.DWORD),
        ('SizeOfImage', ctypes.wintypes.DWORD),
        ('SizeOfHeaders', ctypes.wintypes.DWORD),
        ('CheckSum', ctypes.wintypes.DWORD),
        ('Subsystem', ctypes.wintypes.WORD),
        ('DllCharacteristics', ctypes.wintypes.WORD),
        ('SizeOfStackReserve', ctypes.wintypes.DWORD),
        ('SizeOfStackCommit', ctypes.wintypes.DWORD),
        ('SizeOfHeapReserve', ctypes.wintypes.DWORD),
        ('SizeOfHeapCommit', ctypes.wintypes.DWORD),
        ('LoaderFlags', ctypes.wintypes.DWORD),
        ('NumberOfRvaAndSizes', ctypes.wintypes.DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    ]

PIMAGE_OPTIONAL_HEADER32 = ctypes.POINTER(IMAGE_OPTIONAL_HEADER32)


class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ('Magic', ctypes.wintypes.WORD),
        ('MajorLinkerVersion', ctypes.wintypes.BYTE),
        ('MinorLinkerVersion', ctypes.wintypes.BYTE),
        ('SizeOfCode', ctypes.wintypes.DWORD),
        ('SizeOfInitializedData', ctypes.wintypes.DWORD),
        ('SizeOfUninitializedData', ctypes.wintypes.DWORD),
        ('AddressOfEntryPoint', ctypes.wintypes.DWORD),
        ('BaseOfCode', ctypes.wintypes.DWORD),
        ('ImageBase', ctypes.c_uint64),
        ('SectionAlignment', ctypes.wintypes.DWORD),
        ('FileAlignment', ctypes.wintypes.DWORD),
        ('MajorOperatingSystemVersion', ctypes.wintypes.WORD),
        ('MinorOperatingSystemVersion', ctypes.wintypes.WORD),
        ('MajorImageVersion', ctypes.wintypes.WORD),
        ('MinorImageVersion', ctypes.wintypes.WORD),
        ('MajorSubsystemVersion', ctypes.wintypes.WORD),
        ('MinorSubsystemVersion', ctypes.wintypes.WORD),
        ('Win32VersionValue', ctypes.wintypes.DWORD),
        ('SizeOfImage', ctypes.wintypes.DWORD),
        ('SizeOfHeaders', ctypes.wintypes.DWORD),
        ('CheckSum', ctypes.wintypes.DWORD),
        ('Subsystem', ctypes.wintypes.WORD),
        ('DllCharacteristics', ctypes.wintypes.WORD),
        ('SizeOfStackReserve', ctypes.c_uint64),
        ('SizeOfStackCommit', ctypes.c_uint64),
        ('SizeOfHeapReserve', ctypes.c_uint64),
        ('SizeOfHeapCommit', ctypes.c_uint64),
        ('LoaderFlags', ctypes.wintypes.DWORD),
        ('NumberOfRvaAndSizes', ctypes.wintypes.DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    ]

PIMAGE_OPTIONAL_HEADER64 = ctypes.POINTER(IMAGE_OPTIONAL_HEADER64)


class IMAGE_NT_HEADERS32(ctypes.Structure):
    _fields_ = [
        ('Signature', ctypes.wintypes.DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER32)
    ]
    
PIMAGE_NT_HEADERS32 = ctypes.POINTER(IMAGE_NT_HEADERS32)


class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ('Signature', ctypes.wintypes.DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER64)
    ]

PIMAGE_NT_HEADERS64 = ctypes.POINTER(IMAGE_NT_HEADERS64)


IMAGE_NT_HEADERS_ANY = Union[IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64]


class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('Characteristics', ctypes.wintypes.DWORD),
        ('TimeDateStamp', ctypes.wintypes.DWORD),
        ('MajorVersion', ctypes.wintypes.WORD),
        ('MinorVersion', ctypes.wintypes.WORD),
        ('Name', ctypes.wintypes.DWORD),
        ('Base', ctypes.wintypes.DWORD),
        ('NumberOfFunctions', ctypes.wintypes.DWORD),
        ('NumberOfNames', ctypes.wintypes.DWORD),
        ('AddressOfFunctions', ctypes.wintypes.DWORD),  # RVA from base of image
        ('AddressOfNames', ctypes.wintypes.DWORD),  # RVA from base of image
        ('AddressOfNameOrdinals', ctypes.wintypes.DWORD)  # RVA from base of image
    ]

PIMAGE_EXPORT_DIRECTORY = ctypes.POINTER(IMAGE_EXPORT_DIRECTORY)


FARPROC = ctypes.WINFUNCTYPE(ctypes.c_size_t)
LPTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID)


#############
# Functions #
#############

GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = ctypes.wintypes.HANDLE
GetCurrentProcess.argtypes = []

GetCurrentProcessId = ctypes.windll.kernel32.GetCurrentProcessId
GetCurrentProcessId.restype = ctypes.wintypes.DWORD
GetCurrentProcessId.argtypes = []

GetProcessHeap = ctypes.windll.kernel32.GetProcessHeap
GetProcessHeap.restype = ctypes.wintypes.HANDLE
GetProcessHeap.argtypes = []

HeapCreate = ctypes.windll.kernel32.HeapCreate
HeapCreate.restype = ctypes.wintypes.HANDLE
HeapCreate.argtypes = [ctypes.wintypes.DWORD, ctypes.c_size_t, ctypes.c_size_t]

HeapAlloc = ctypes.windll.kernel32.HeapAlloc
HeapAlloc.restype = ctypes.wintypes.LPVOID
HeapAlloc.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.c_size_t]

HeapFree = ctypes.windll.kernel32.HeapFree
HeapFree.restype = ctypes.wintypes.BOOL
HeapFree.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID]

VirtualAllocEx  = ctypes.windll.kernel32.VirtualAllocEx 
VirtualAllocEx.restype = ctypes.wintypes.LPVOID
VirtualAllocEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD]

VirtualFreeEx = ctypes.windll.kernel32.VirtualFreeEx
VirtualFreeEx.restype = ctypes.wintypes.BOOL
VirtualFreeEx.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.c_size_t, ctypes.wintypes.DWORD]

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = ctypes.wintypes.BOOL
ReadProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID, ctypes.wintypes.LPVOID, ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_size_t)]

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = ctypes.wintypes.BOOL
WriteProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCVOID, ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_size_t)]

CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
CreateRemoteThread.restype = ctypes.wintypes.HANDLE
CreateRemoteThread.argtypes = [ctypes.wintypes.HANDLE, LPSECURITY_ATTRIBUTES, ctypes.c_size_t, LPTHREAD_START_ROUTINE, ctypes.wintypes.LPVOID,
                               ctypes.wintypes.DWORD, ctypes.wintypes.LPDWORD]

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

IsWow64Process = ctypes.windll.kernel32.IsWow64Process
IsWow64Process.restype = ctypes.wintypes.BOOL
IsWow64Process.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.PBOOL]

WaitForMultipleObjects = ctypes.windll.kernel32.WaitForMultipleObjects
WaitForMultipleObjects.restype = ctypes.wintypes.DWORD
WaitForMultipleObjects.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.PHANDLE, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]


#############
# Variables #
#############

CurrentProcessId = GetCurrentProcessId()
CurrentProcessHandle = ProcessHandle(ctypes.wintypes.HANDLE(GetCurrentProcess()), managed=False, pid=CurrentProcessId)

ProcessHeap = SafeHandle(ctypes.wintypes.HANDLE(GetProcessHeap()), managed=False)
