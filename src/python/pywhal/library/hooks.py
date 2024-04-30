from typing import TypeVar
from .implementation import hooks_impl


TFunction = TypeVar('TFunction')


class Hooks:
    """
    Class for managing hooks.
    Note that the class should not be instantiated - all of the
    methods are marked with @classmethod.
    """
    def __new__(cls):
        raise TypeError('The Hooks class cannot be instantiated.')
    
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
        return hooks_impl.attach_hook(original_function, detour_function)


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
        return hooks_impl.detach_hook(trampoline_function, detour_function)
