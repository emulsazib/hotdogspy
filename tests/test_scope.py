import pytest

from audittool.core.scope import Scope, ScopeError


def test_unattested_scope_blocks_everything():
    scope = Scope(attested=False, domains=["example.com"], networks=["127.0.0.1"])
    assert scope.is_authorized("example.com", ["93.184.216.34"]) is False


def test_attested_domain_allowlist():
    scope = Scope(attested=True, domains=["example.com"], networks=[])
    assert scope.is_authorized("example.com", []) is True
    assert scope.is_authorized("evil.com", []) is False


def test_attested_network_cidr():
    scope = Scope(attested=True, domains=[], networks=["192.168.1.0/24"])
    assert scope.is_authorized("192.168.1.50", ["192.168.1.50"]) is True
    assert scope.is_authorized("10.0.0.1", ["10.0.0.1"]) is False


def test_enforce_raises_without_confirm():
    scope = Scope(attested=False, domains=[], networks=[])
    with pytest.raises(ScopeError):
        scope.enforce("example.com", ["1.2.3.4"], confirm=None)


def test_enforce_allows_with_confirm_callback():
    scope = Scope(attested=False, domains=[], networks=[])
    assert scope.enforce("example.com", ["1.2.3.4"], confirm=lambda t, i: True) is True
