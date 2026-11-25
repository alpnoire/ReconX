import socket


def resolve_domain(domain):

    try:
        ip_address = socket.gethostbyname(domain)

        return {
            "domain": domain,
            "ip_address": ip_address,
            "status": "success"
        }

    except socket.gaierror:

        return {
            "domain": domain,
            "ip_address": None,
            "status": "failed"
        }