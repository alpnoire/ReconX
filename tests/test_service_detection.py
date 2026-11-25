from reconx.service_detection import detect_http


def test_detect_http_service():

    result = detect_http("127.0.0.1", 8000)

    assert result["service"] == "HTTP"
    assert result["response"].startswith("HTTP/")
    