import json
from reconx.reporter import generate_report


def test_generate_json_report(tmp_path, monkeypatch):

    monkeypatch.chdir(tmp_path)

    data = {
        "tool": "ReconX",
        "target": "127.0.0.1",
        "results": [
            {
                "port": 8000,
                "status": "open",
                "service": "HTTP"
            }
        ]
    }

    filepath = generate_report(data)

    assert filepath.exists()
    assert filepath.suffix == ".json"

    with open(filepath, "r", encoding="utf-8") as file:
        saved_data = json.load(file)

    assert saved_data["tool"] == "ReconX"
    assert saved_data["target"] == "127.0.0.1"
    assert saved_data["results"][0]["port"] == 8000