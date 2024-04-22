import ctypes
from typing import TypeVar
from ... import _pywhalCore


TFunction = TypeVar('TFunction')


def attach_hook(original_function: TFunction, detour_function: TFunction) -> TFunction:
    ctypes_function_type = type(original_function)
        
    original_function_address = ctypes.cast(original_function, ctypes.c_void_p).value
    detour_function_address = ctypes.cast(detour_function, ctypes.c_void_p).value
    trampoline_function_address = _pywhalCore.hooks.attach_hook(original_function_address, detour_function_address)
    return ctypes.cast(trampoline_function_address, ctypes_function_type)


def detach_hook(trampoline_function: TFunction, detour_function: TFunction) -> TFunction:
    ctypes_function_type = type(trampoline_function)
        
    trampoline_function_address = ctypes.cast(trampoline_function, ctypes.c_void_p).value
    detour_function_address = ctypes.cast(detour_function, ctypes.c_void_p).value
    trampoline_function_address = _pywhalCore.hooks.attach_hook(trampoline_function_address, detour_function_address)
    return ctypes.cast(trampoline_function_address, ctypes_function_type)
