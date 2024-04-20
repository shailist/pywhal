import ctypes
from .. import _core
from typing import TypeVar


TFunction = TypeVar('TFunction')


class Hooks:
    """
    Class for managing hooks.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """    
    @staticmethod
    def attach(original_function: TFunction, detour_function: TFunction) -> TFunction:
        """
        Installes `detour_function` as a hook for `original_function`.
        Returns a trampoline function that can be used to call the original function.
        
        Example:
        >>> MessageBoxA = ...
        >>> 
        >>> # ctypes function pointer via decorator
        >>> @PfnMessageBoxA
        >>> def MessageBoxA_hook(...):
        >>>     return original_MessageBoxA(...)
        >>>
        >>> original_MessageBoxA = Hooks.attach(MessageBoxA, MessageBoxA_hook)
        """
        return _attach_hook(original_function, detour_function)


    @staticmethod
    def detach(trampoline_function: TFunction, detour_function: TFunction) -> TFunction:
        """
        Detaches `detour_function` hook from the original function.
        Requires the trampoline function as a parameter.
        Returns the original function.
        
        Example:
        >>> MessageBoxA = ...
        >>> 
        >>> # ctypes function pointer via decorator
        >>> @PfnMessageBoxA
        >>> def MessageBoxA_hook(...):
        >>>     return original_MessageBoxA(...)
        >>>
        >>> original_MessageBoxA = Hooks.attach(MessageBoxA, MessageBoxA_hook)
        >>> assert MessageBoxA == Hooks.detach(original_MessageBoxA, MessageBoxA_hook)
        """
        return _detach_hook(trampoline_function, detour_function)


def _attach_hook(original_function: TFunction, detour_function: TFunction) -> TFunction:
    ctypes_function_type = type(original_function)
        
    original_function_address = ctypes.cast(original_function, ctypes.c_void_p).value
    detour_function_address = ctypes.cast(detour_function, ctypes.c_void_p).value
    trampoline_function_address = _core.attach_hook(original_function_address, detour_function_address)
    return ctypes.cast(trampoline_function_address, ctypes_function_type)


def _detach_hook(trampoline_function: TFunction, detour_function: TFunction) -> TFunction:
    ctypes_function_type = type(trampoline_function)
        
    trampoline_function_address = ctypes.cast(trampoline_function, ctypes.c_void_p).value
    detour_function_address = ctypes.cast(detour_function, ctypes.c_void_p).value
    trampoline_function_address = _core.attach_hook(trampoline_function_address, detour_function_address)
    return ctypes.cast(trampoline_function_address, ctypes_function_type)

