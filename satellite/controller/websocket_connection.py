from functools import singledispatchmethod
from typing import ClassVar

from mitmproxy.tools.web.app import WebSocketEventBroadcaster

from ..flows import load_flow_from_state
from ..schemas.flows import HTTPFlowSchema
from ..proxy import events


class ClientConnection(WebSocketEventBroadcaster):
    connections: ClassVar[set] = set()

    def check_origin(self, origin: str):
        return True

    @classmethod
    async def process_proxy_event(cls, event):
        cls._process_proxy_event(event)

    @singledispatchmethod
    @classmethod
    def _process_proxy_event(cls, event):
        raise NotImplementedError(f'Unknown proxy event: {event}.')

    @_process_proxy_event.register(events.FlowAddEvent)
    @classmethod
    def _(cls, event: events.FlowAddEvent):
        flow = load_flow_from_state(event.data)
        ClientConnection.broadcast(
            resource='flows',
            cmd='add',
            data=HTTPFlowSchema().dump(flow),
        )

    @_process_proxy_event.register(events.FlowUpdateEvent)
    @classmethod
    def _(cls, event: events.FlowUpdateEvent):
        flow = load_flow_from_state(event.data)
        ClientConnection.broadcast(
            resource='flows',
            cmd='update',
            data=HTTPFlowSchema().dump(flow),
        )

    @_process_proxy_event.register(events.FlowRemoveEvent)
    @classmethod
    def _(cls, event: events.FlowRemoveEvent):
        ClientConnection.broadcast(
            resource='flows',
            cmd='remove',
            data=event.data,
        )
