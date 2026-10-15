import pytest
from typer.testing import CliRunner

from cipheraudit.cli import EXIT_UNAUTHORIZED, app, parse_target
from cipheraudit.config import ScanOptions
from cipheraudit.net.ratelimit import RateLimiter


def test_parse_target() -> None:
    assert parse_target("example.com") == ("example.com", 443)
    assert parse_target("example.com:8443") == ("example.com", 8443)
    assert parse_target("[::1]:8443") == ("::1", 8443)
    assert parse_target("[2001:db8::1]") == ("2001:db8::1", 443)


def test_refusing_permission_exits_2_without_scanning() -> None:
    result = CliRunner().invoke(app, ["scan", "example.invalid"], input="n\n")
    assert result.exit_code == EXIT_UNAUTHORIZED
    assert "Scanning" not in result.output


def test_sni_never_an_ip_literal() -> None:
    assert ScanOptions(host="192.0.2.1").server_name is None
    assert ScanOptions(host="::1").server_name is None
    assert ScanOptions(host="example.com").server_name == "example.com"
    assert ScanOptions(host="192.0.2.1", sni="example.com").server_name == "example.com"


def test_rate_limiter_rejects_nonpositive_rate() -> None:
    with pytest.raises(ValueError):
        RateLimiter(0)
