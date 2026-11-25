import subprocess
import sys
import socket
import ssl
import threading
from pathlib import Path

import pytest

from reconx.service_detection import (
    detect_http,
    detect_https,
    detect_banner_service,
    detect_service,
    detect_mysql,
    detect_postgresql
)


def start_test_server(response, receive_first=False):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    host, port = server.getsockname()

    def handle_connection():
        try:
            connection, _ = server.accept()

            with connection:
                connection.settimeout(2)

                if receive_first:
                    connection.recv(1024)

                connection.sendall(response)

                if not receive_first:
                    try:
                        connection.recv(1024)
                    except socket.timeout:
                        pass

        finally:
            server.close()

    thread = threading.Thread(target=handle_connection)
    thread.start()

    return host, port, thread


def test_detect_http_service():

    host, port, thread = start_test_server(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        receive_first=True
    )

    result = detect_http(host, port)
    thread.join(timeout=3)

    assert result["service"] == "HTTP"
    assert result["response"].startswith("HTTP/")


@pytest.mark.parametrize(
    "banner, expected_service",
    [
        (b"SSH-2.0-OpenSSH_9.0\r\n", "SSH"),
        (b"220 FTP Server Ready\r\n", "FTP"),
        (b"220 mail.example.com SMTP\r\n", "SMTP"),
    ]
)
def test_detect_banner_service(banner, expected_service):

    host, port, thread = start_test_server(banner)

    result = detect_banner_service(host, port)
    thread.join(timeout=3)

    assert result["service"] == expected_service


def test_detect_mysql():

    payload = b"\x0a8.0.36\x00"

    packet = (
        len(payload).to_bytes(3, "little")
        + b"\x00"
        + payload
    )

    host, port, thread = start_test_server(packet)

    result = detect_mysql(host, port)
    thread.join(timeout=3)

    assert result["service"] == "MySQL"
    assert result["version"] == "8.0.36"


@pytest.mark.parametrize(
    "response, expected_ssl",
    [
        (b"S", True),
        (b"N", False)
    ]
)
def test_detect_postgresql(response, expected_ssl):

    host, port, thread = start_test_server(
        response,
        receive_first=True
    )

    result = detect_postgresql(host, port)
    thread.join(timeout=3)

    assert result["service"] == "PostgreSQL"
    assert result["ssl_supported"] == expected_ssl


def test_detect_service_unknown_port():

    result = detect_service("127.0.0.1", 9999)

    assert result["service"] == "Unknown"


def test_detect_https():

    cert_dir = Path(__file__).parent / "certs"
    cert_file = cert_dir / "server.crt"
    key_file = cert_dir / "server.key"
    if not cert_file.exists() or not key_file.exists():
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parent / "generate_certificate.py")
            ],
            check=True
        )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    server_context.load_cert_chain(
        certfile=str(cert_file),
        keyfile=str(key_file)
    )

    client_context = ssl.create_default_context(
        cafile=str(cert_file)
    )

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    host, port = server.getsockname()

    def handle_https():

        try:
            connection, _ = server.accept()

            try:
                with server_context.wrap_socket(
                    connection,
                    server_side=True
                ) as secure_connection:
                    secure_connection.recv(1024)

            except (ssl.SSLError, OSError):
                pass

        finally:
            server.close()

    thread = threading.Thread(target=handle_https)
    thread.start()

    result = detect_https(
        host,
        port,
        ssl_context=client_context
    )

    thread.join(timeout=3)

    assert result["service"] == "HTTPS"
    assert "TLS version" in result["response"]