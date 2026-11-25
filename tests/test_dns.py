from reconx.dns import resolve_domain


def test_valid_domain():

    result = resolve_domain("example.com")

    assert result["domain"] == "example.com"
    assert result["ip_address"] is not None
    assert result["status"] == "success"


def test_invalid_domain():

    result = resolve_domain(
        "this-domain-does-not-exist-123456.com"
    )

    assert result["ip_address"] is None
    assert result["status"] == "failed"