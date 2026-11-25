import socket
from concurrent.futures import ThreadPoolExecutor


def scan_port(target, port):

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(1)

            result = sock.connect_ex((target, port))

            if result == 0:
                status = "open"
            else:
                status = "closed"

            return {
                "port": port,
                "status": status
            }

    except socket.error as error:

        return {
            "port": port,
            "status": "error",
            "message": str(error)
        }


def validate_ports(start_port, end_port):

    if not isinstance(start_port, int) or not isinstance(end_port, int):
        raise ValueError("Ports must be integers.")

    if not (1 <= start_port <= 65535):
        raise ValueError("Starting port must be between 1 and 65535.")

    if not (1 <= end_port <= 65535):
        raise ValueError("Ending port must be between 1 and 65535.")

    if start_port > end_port:
        raise ValueError("Starting port cannot be greater than ending port.")

    return range(start_port, end_port + 1)


def scan_ports(target, ports, max_workers=20):

    if max_workers < 1:
        raise ValueError("max_workers must be at least 1.")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        results = executor.map(
            lambda port: scan_port(target, port),
            ports
        )

        return list(results)