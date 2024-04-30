import rpyc
import rpyc.core.service
import rpyc.utils.server
from .current_process_api import _CurrentProcessAPI


PYWHAL_SERVICE_DEFAULT_PORT = 21426


class API(_CurrentProcessAPI, rpyc.core.service.Slave):
    def __init__(self):
        _CurrentProcessAPI.__init__(self)
        rpyc.core.service.Slave.__init__(self)


class PywhalService(rpyc.SlaveService):
    def __init__(self):
        super().__init__()
        self.api = API()
    
    def on_connect(self, conn):
        super().on_connect(conn)
        self.api._conn = conn
        rpyc.MasterService._install(conn, self.api)
    
    def on_disconnect(self, conn):
        super().on_disconnect(conn)
    
    @property
    def exposed_api(self) -> API:
        return self.api
    
    @property
    def sys_modules(self) -> rpyc.core.service.ModuleNamespace:
        return self._conn.modules


def run_server(port: int = PYWHAL_SERVICE_DEFAULT_PORT):
    """
    Runs an rpyc server for PywhalService for one connection (blocking).
    """
    server = rpyc.utils.server.OneShotServer(PywhalService, port=port, protocol_config={
        'allow_public_attrs': True,
    })
    server.start()


def connect_client(host: str = 'localhost', port: int = PYWHAL_SERVICE_DEFAULT_PORT) -> API:
    client = rpyc.connect(host, port, keepalive=True)
    return client.root.api
