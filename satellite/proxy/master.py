import logging
from types import MappingProxyType

from blinker import signal
from mitmproxy.addons import default_addons
from mitmproxy.addons.view import View
from mitmproxy.flow import Error
from mitmproxy.http import HTTPFlow, make_error_response
from mitmproxy.log import LogEntry
from mitmproxy.master import Master as Master
from mitmproxy.options import Options
from mitmproxy.proxy.config import ProxyConfig

from . import ProxyMode
from .server import ProxyServer
from ..vault.vault_handler import VaultFlows


logger = logging.getLogger()


class ProxyEventsAddon:
    PROXY_LOG_LEVELS = MappingProxyType(
        {
            'error': logging.ERROR,
            'info': logging.INFO,
            'warning': logging.WARNING,
        }
    )

    def running(self):
        signal('sat_proxy_started').send(self)

    def request(self, flow: HTTPFlow):
        # Remove "vgs-client" header, that is sent by VGS-Collect.
        # This copies logic from proxy
        flow.request.headers.pop('vgs-client', None)
        if flow.request.host == 'dummy-upstream':
            flow.error = Error('No upstream is configured.')
            flow.response = make_error_response(
                400,
                'No upstream is configured.',
            )

    def log(self, entry: LogEntry):
        level = self.PROXY_LOG_LEVELS.get(entry.level)
        if level is not None:
            logger.log(level, entry.msg)


class ProxyMaster(Master):
    def __init__(self, mode: ProxyMode, port: int):
        mode = (
            f'{mode.value}:https://dummy-upstream'
            if mode == ProxyMode.REVERSE
            else mode.value
        )
        opts = Options(mode=mode, listen_port=port, ssl_insecure=False)
        super().__init__(opts)

        self.view = View()
        self.addons.add(
            *default_addons(),
            VaultFlows(),
            self.view,
            ProxyEventsAddon(),
        )

        self.server = ProxyServer(ProxyConfig(opts))
