import socket
from reconx.scanner import scan_port


def test_open_port():

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.bind(("127.0.0.1", 0))
    server.listen(1)

    port = server.getsockname()[1]

    try:
        result = scan_port("127.0.0.1", port)

        assert result["port"] == port
        assert result["status"] == "open"

    finally:
        server.close()