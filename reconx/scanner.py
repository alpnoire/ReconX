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


def scan_ports(target, ports, max_workers=20):

    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        results = executor.map(
            lambda port: scan_port(target, port),
            ports
        )

        return list(results)