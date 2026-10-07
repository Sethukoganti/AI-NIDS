from app.services import capture_service


def test_start_capture_reports_missing_scapy(monkeypatch):
    monkeypatch.setattr(capture_service, "_scapy_installed", lambda: False)

    result = capture_service.start_capture()

    assert result == {
        "started": False,
        "reason": "scapy_missing",
        "error": "SCAPY_MISSING",
    }
