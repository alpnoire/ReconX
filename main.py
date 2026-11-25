from reconx.scanner import scan_ports
import time


def main():

    target = "127.0.0.1"

    ports = [
        80, 443, 3306, 5432, 8000,
        8080, 8443, 9000, 3000, 5000
    ]

    print("\n========== RECONX ==========")
    print("Multithreaded TCP Scanner")
    print("============================")

    start_time = time.time()

    results = scan_ports(target, ports)

    for result in results:

        print(
            f"Port {result['port']}: "
            f"{result['status'].upper()}"
        )

    end_time = time.time()

    print("\nScan completed.")
    print(f"Time taken: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()