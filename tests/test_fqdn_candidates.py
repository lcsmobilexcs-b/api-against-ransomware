"""Unit tests for FQDN system name candidates (BeyondTrust lookup phase 1)."""

from ss_bt_automation.orchestrator import _fqdn_system_candidates


def test_empty_domain_returns_no_candidates() -> None:
    assert _fqdn_system_candidates("pc01", "") == []
    assert _fqdn_system_candidates("pc01", "   ") == []


def test_empty_hostname_returns_no_candidates() -> None:
    assert _fqdn_system_candidates("", "contoso.com") == []


def test_short_hostname_appends_domain() -> None:
    out = _fqdn_system_candidates("pc01", "contoso.com")
    assert out == ["pc01.contoso.com"]


def test_fqdn_hostname_skips_duplicate_suffix() -> None:
    out = _fqdn_system_candidates("pc01.contoso.com", "contoso.com")
    assert out == ["pc01.contoso.com"]


def test_domain_is_stripped() -> None:
    out = _fqdn_system_candidates("pc01", "  contoso.com  ")
    assert out == ["pc01.contoso.com"]
