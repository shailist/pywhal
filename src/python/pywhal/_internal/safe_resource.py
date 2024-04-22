from typing import Callable, Optional, Tuple, TypeVar


TResource = TypeVar('TResource')


class SafeResource:
    """
    Manages a resource and automatically releases it when the object is deleted.
    Also offers a context manager interface to control when this happens.
    Also offers a way to "leak" the managed resource.
    """
    def __init__(self, resource: TResource, deleter: Optional[Callable[[TResource], None]] = None):
        """
        Args:
            resource (TResource): The resource to manage.
            deleter (Optional[Callable[[TResource], None]], optional):
                The function that will be called with the managed resource in order to release it.
                If the resource is a tuple, it will be unpacked in the function call.
        """
        self.resource = resource
        self.deleter = deleter
    
    def detach(self):
        """
        The managed resource won't be released when the object is destroyed.
        """
        self.deleter = None

    def release(self):
        if self.deleter is not None:
            if isinstance(self.resource, Tuple):
                self.deleter(*self.resource)
            else:
                self.deleter(self.resource)
                
            self.deleter = None
    
    @property
    def is_managed(self) -> bool:
        """
        True when the resource is to be released.
        """
        return self.deleter is not None
    
    def __del__(self):
        self.release()
    
    def __enter__(self):
        return self
         
    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.release()
