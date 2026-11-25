import socket


def detect_http(target, port):

    try:
        with socket.create_connection(
            (target, port),
            timeout=2
        ) as sock:

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

            return {
                "port": port,
                "service": "Unknown"
            }

    except (socket.timeout, ConnectionRefusedError, OSError):
        return {
            "port": port,
            "service": "Unavailable"
        }