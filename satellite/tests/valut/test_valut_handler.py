from unittest.mock import Mock

from satellite.vault.vault_handler import VaultFlows

from ..factories import load_flow, RouteFactory, RuleEntryFactory


def test_request_redact(monkeypatch, snapshot):
    route = RouteFactory()
    rule_entry = RuleEntryFactory()

    monkeypatch.setattr(
        'satellite.vault.vault_handler.satellite_ctx',
        Mock(webapp=Mock(master=Mock(proxy_mode='regular'))),
    )
    monkeypatch.setattr(
        'satellite.vault.vault_handler.match_route',
        Mock(return_value=(route, [rule_entry])),
    )
    monkeypatch.setattr(
        'satellite.vault.vault_handler.transform_body',
        Mock(return_value='transformed body'),
    )

    flow = load_flow('http_raw')
    assert not hasattr(flow, 'request_raw')

    VaultFlows().request(flow)

    assert hasattr(flow, 'request_raw')
    assert flow.request.content != flow.request_raw.content
    assert flow.request.match_details == {
        'route_id': route.id,
        'filter_ids': [rule_entry.id]
    }
    snapshot.assert_match(flow.request.get_state(), 'request')
    snapshot.assert_match(flow.request_raw.get_state(), 'request_raw')


def test_response_redact(monkeypatch, snapshot):
    route = RouteFactory()
    rule_entry = RuleEntryFactory()

    monkeypatch.setattr(
        'satellite.vault.vault_handler.satellite_ctx',
        Mock(webapp=Mock(master=Mock(proxy_mode='regular'))),
    )
    monkeypatch.setattr(
        'satellite.vault.vault_handler.match_route',
        Mock(return_value=(route, [rule_entry])),
    )
    monkeypatch.setattr(
        'satellite.vault.vault_handler.transform_body',
        Mock(return_value='transformed body'),
    )

    flow = load_flow('http_raw')
    assert not hasattr(flow, 'response_raw')

    VaultFlows().response(flow)

    assert hasattr(flow, 'response_raw')
    assert flow.response.content != flow.response_raw.content
    assert flow.response.match_details == {
        'route_id': route.id,
        'filter_ids': [rule_entry.id]
    }
    snapshot.assert_match(flow.response.get_state(), 'response')
    snapshot.assert_match(flow.response_raw.get_state(), 'response_raw')
