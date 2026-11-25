import json
from pathlib import Path
from datetime import datetime, timezone


def generate_report(data):

    reports_dir = Path("reports")

    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S"
    )

    filename = f"scan_{timestamp}.json"

    filepath = reports_dir / filename

    with open(filepath, "w", encoding="utf-8") as file:

        json.dump(
            data,
            file,
            indent=4
        )

    return filepath