import ctypes
from typing import TypeVar
from ... import _pywhalCore


TFunction = TypeVar('TFunction')


def is_netref(object):
    """
    Determines if an object is an RPYC netref.
    """
    return hasattr(object, '____conn__') and hasattr(object, '____id_pack__')


_forwarding_function_cache = {}


def get_forwarding_function(ctypes_function, allow_create: bool = True):
    """
    Creates and returns a ctype function that wraps the given function and
    forwards its arguments and return value to and from it.
    The created function is cached, so subsequent calls to create_forwarding_function
    with the same function will return the same forwarder function.
    """
    ctypes_function_type = type(ctypes_function)

    function_address = ctypes.cast(ctypes_function, ctypes.c_void_p).value
    if function_address not in _forwarding_function_cache:
        if not allow_create:
            raise KeyError('Given function doesn\'t have a cached forwarding function.')
        
        @ctypes_function_type
        def forwarder(*args):
            return ctypes_function(*args)
        
        forwarding_function_address = ctypes.cast(forwarder, ctypes.c_void_p).value
        _forwarding_function_cache[function_address] = forwarding_function_address

    else:
        forwarding_function_address = _forwarding_function_cache[function_address]
    
    return ctypes_function_type(forwarding_function_address)


def attach_hook(original_function: TFunction, detour_function: TFunction) -> TFunction:
    ctypes_function_type = type(original_function)

    if is_netref(original_function):
        raise ValueError('Cannot attach hooks from remote process (original_function was a netref).')
    
    if is_netref(detour_function):
        detour_function = get_forwarding_function(detour_function)

    original_function_address = ctypes.cast(original_function, ctypes.c_void_p).value
    detour_function_address = ctypes.cast(detour_function, ctypes.c_void_p).value
    trampoline_function_address = _pywhalCore.hooks.attach_hook(original_function_address, detour_function_address)
    return ctypes.cast(trampoline_function_address, ctypes_function_type)


def detach_hook(trampoline_function: TFunction, detour_function: TFunction) -> TFunction:
    ctypes_function_type = type(trampoline_function)

    if is_netref(trampoline_function):
        raise ValueError('Cannot detach hooks from remote process (trampoline_function was a netref).')

    if is_netref(detour_function):
        detour_function = get_forwarding_function(detour_function, allow_create=False)

    trampoline_function_address = ctypes.cast(trampoline_function, ctypes.c_void_p).value
    detour_function_address = ctypes.cast(detour_function, ctypes.c_void_p).value
    trampoline_function_address = _pywhalCore.hooks.detach_hook(trampoline_function_address, detour_function_address)
    return ctypes.cast(trampoline_function_address, ctypes_function_type)
