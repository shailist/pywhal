import rpyc
from ..process.memory import Memory


class PywhalService(rpyc.Service):
    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        pass

    @property
    def memory(self):
        return Memory
