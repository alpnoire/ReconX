import time

from reconx.dns import resolve_domain
from reconx.scanner import scan_ports, validate_ports
from reconx.service_detection import detect_http
from reconx.reporter import generate_report


DEFAULT_PORTS = [80, 443, 3306, 5432, 8000, 8080]


def select_ports():

    print("\nChoose scanning mode:")
    print("1. Default ports")
    print("2. Custom port range")

    choice = input("\nEnter choice: ").strip()

    if choice == "1":
        return DEFAULT_PORTS

    elif choice == "2":

        try:
            start_port = int(input("Starting port: "))
            end_port = int(input("Ending port: "))

            return validate_ports(start_port, end_port)

        except ValueError as error:
            print(f"\nInvalid input: {error}")
            return None

    else:
        print("\nInvalid choice.")
        return None


def main():

    target = input("Enter target IP: ").strip()

    ports = select_ports()

    if ports is None:
        print("Scan cancelled.")
        return

    print("\n========== RECONX ==========")
    print(f"Target: {target}")
    print(f"Ports to scan: {len(ports)}")
    print("============================")

    # DNS Resolution
    dns_result = resolve_domain(target)

    print("\n[ DNS INFORMATION ]")
    print(dns_result)

    # TCP Scanning
    print("\n[ PORT SCANNING ]")

    start_time = time.time()

    scan_results = scan_ports(target, ports)

    final_results = []

    for result in scan_results:

        port_result = {
            "port": result["port"],
            "status": result["status"],
            "service": "Unknown"
        }

        if result["status"] == "open":

            service = detect_http(target, result["port"])

            port_result["service"] = service["service"]

            print(
                f"Port {result['port']}: OPEN "
                f"| Service: {service['service']}"
            )

        final_results.append(port_result)

    end_time = time.time()

    # Generate Summary
    open_ports = sum(
        1 for result in final_results
        if result["status"] == "open"
    )

    closed_ports = sum(
        1 for result in final_results
        if result["status"] == "closed"
    )

    error_ports = sum(
        1 for result in final_results
        if result["status"] == "error"
    )

    # Prepare Report
    report_data = {
        "tool": "ReconX",
        "version": "0.5.0",
        "target": target,
        "dns": dns_result,
        "results": final_results,
        "summary": {
            "total_ports": len(ports),
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "error_ports": error_ports
        },
        "scan_duration": round(end_time - start_time, 2)
    }

    # Save JSON Report
    report_path = generate_report(report_data)

    # Final Output
    print("\n========== SCAN SUMMARY ==========")
    print(f"Total ports scanned : {len(ports)}")
    print(f"Open ports          : {open_ports}")
    print(f"Closed ports        : {closed_ports}")
    print(f"Errors              : {error_ports}")
    print(f"Time taken          : {end_time - start_time:.2f}s")
    print("==================================")

    print(f"\nReport saved: {report_path}")
    print("ReconX scan completed successfully.")


if __name__ == "__main__":
    main()