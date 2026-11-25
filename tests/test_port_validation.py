import pytest

from reconx.scanner import validate_ports


def test_valid_port_range():
    ports = validate_ports(1, 100)

    assert ports.start == 1
    assert ports.stop == 101


def test_single_port():
    ports = validate_ports(80, 80)

    assert list(ports) == [80]


def test_invalid_start_port():
    with pytest.raises(ValueError):
        validate_ports(0, 100)


def test_invalid_end_port():
    with pytest.raises(ValueError):
        validate_ports(1, 65536)


def test_reversed_port_range():
    with pytest.raises(ValueError):
        validate_ports(100, 1)