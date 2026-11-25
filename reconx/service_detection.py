import socket
import ssl
import struct


def detect_http(target, port):

    try:
        with socket.create_connection((target, port), timeout=2) as sock:

            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "Connection: close\r\n\r\n"
            )

            sock.sendall(request.encode())

            response = sock.recv(1024).decode(
                "utf-8",
                errors="replace"
            )

            if response.startswith("HTTP/"):
                return {
                    "port": port,
                    "service": "HTTP",
                    "response": response.splitlines()[0]
                }

            return {"port": port, "service": "Unknown"}

    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"port": port, "service": "Unavailable"}


def detect_https(target, port, ssl_context=None):

    try:
        if ssl_context is None:
            ssl_context = ssl.create_default_context()

        with socket.create_connection((target, port), timeout=2) as raw_sock:

            with ssl_context.wrap_socket(
                raw_sock,
                server_hostname=target
            ) as secure_sock:

                return {
                    "port": port,
                    "service": "HTTPS",
                    "response": f"TLS version: {secure_sock.version()}"
                }

    except (socket.timeout, ssl.SSLError, OSError):
        return {"port": port, "service": "Unavailable"}


def detect_banner_service(target, port):

    try:
        with socket.create_connection((target, port), timeout=2) as sock:

            sock.settimeout(2)

            banner = sock.recv(1024).decode(
                "utf-8",
                errors="replace"
            ).strip()

            if not banner:
                return {"port": port, "service": "Unknown"}

            if banner.startswith("SSH-"):
                service = "SSH"

            elif banner.startswith("220"):
                service = (
                    "FTP"
                    if "FTP" in banner.upper()
                    else "SMTP"
                )

            else:
                service = "Unknown"

            return {
                "port": port,
                "service": service,
                "banner": banner[:200]
            }

    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"port": port, "service": "Unavailable"}


def detect_mysql(target, port):

    try:
        with socket.create_connection((target, port), timeout=2) as sock:

            sock.settimeout(2)
            packet = sock.recv(1024)

            if len(packet) < 5:
                return {"port": port, "service": "Unknown"}

            payload = packet[4:]

            if payload and payload[0] == 0x0A:

                return {
                    "port": port,
                    "service": "MySQL",
                    "version": payload[1:].split(b"\x00")[0].decode(
                        "ascii",
                        errors="replace"
                    )
                }

            return {"port": port, "service": "Unknown"}

    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"port": port, "service": "Unavailable"}


def detect_postgresql(target, port):

    try:
        with socket.create_connection((target, port), timeout=2) as sock:

            sock.settimeout(2)

            request = struct.pack("!II", 8, 80877103)
            sock.sendall(request)

            response = sock.recv(1)

            if response in (b"S", b"N"):

                return {
                    "port": port,
                    "service": "PostgreSQL",
                    "ssl_supported": response == b"S"
                }

            return {"port": port, "service": "Unknown"}

    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"port": port, "service": "Unavailable"}


def detect_service(target, port):

    if port == 443:
        return detect_https(target, port)

    if port in (80, 8000, 8080):
        return detect_http(target, port)

    if port in (21, 22, 25):
        return detect_banner_service(target, port)

    if port == 3306:
        return detect_mysql(target, port)

    if port == 5432:
        return detect_postgresql(target, port)

    return {
        "port": port,
        "service": "Unknown"
    }