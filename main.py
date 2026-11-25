import time

from reconx.dns import resolve_domain
from reconx.scanner import scan_ports
from reconx.service_detection import detect_http
from reconx.reporter import generate_report


def main():

    target = input("Enter target IP: ").strip()

    print("\n========== RECONX ==========")
    print(f"Target: {target}")
    print("============================")

    # DNS Resolution
    dns_result = resolve_domain(target)

    print("\n[ DNS INFORMATION ]")
    print(dns_result)

    # TCP Scanning
    ports = [80, 443, 3306, 5432, 8000, 8080]

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

        print(
            f"Port {result['port']}: "
            f"{result['status'].upper()}"
        )

        if result["status"] == "open":

            service = detect_http(target, result["port"])

            port_result["service"] = service["service"]

            print(f"    Service: {service['service']}")

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

    # Prepare Report
    report_data = {
        "tool": "ReconX",
        "version": "0.4.0",
        "target": target,
        "dns": dns_result,
        "results": final_results,
        "summary": {
            "total_ports": len(ports),
            "open_ports": open_ports,
            "closed_ports": closed_ports
        },
        "scan_duration": round(end_time - start_time, 2)
    }

    # Save JSON Report
    report_path = generate_report(report_data)

    print("\n============================")
    print("Scan completed.")
    print(f"Time taken: {end_time - start_time:.2f}s")
    print(f"Report saved: {report_path}")


if __name__ == "__main__":
    main()