def _ask(client, auth, question: str) -> dict:
    response = client.post(
        "/api/assistant/ask",
        headers=auth,
        json={"question": question, "include_evidence": True},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_assistant_answers_detection_queries_with_stored_evidence(client, auth, analysed_sample):
    risk = _ask(client, auth, "Break down detections by risk level")
    assert set(risk["facts"]["risk_distribution"]) == {"critical", "high", "medium", "low"}
    assert risk["facts"]["total"] == sum(risk["facts"]["risk_distribution"].values())
    assert risk["facts"]["total"] >= analysed_sample["summary"]["stored_predictions"]

    recent = _ask(client, auth, "Show the most recent detections")
    assert 0 < len(recent["facts"]["detections"]) <= 8
    assert recent["facts"]["detections"][0]["prediction"]

    quality = _ask(client, auth, "How often did predictions match dataset labels?")
    assert quality["facts"]["labelled_rows"] > 0
    assert quality["facts"]["binary"]["false_positive"] >= 0
    assert quality["facts"]["binary"]["false_negative"] >= 0
    assert 0 <= quality["facts"]["match_rate"] <= 1


def test_assistant_reports_only_source_addresses_present_in_stored_flows(client, auth, analysed_sample):
    response = _ask(client, auth, "Which source IPs appear most often?")

    source_counts = response["facts"]["source_ip_counts"]
    assert isinstance(source_counts, dict)
    assert all(source_ip in response["answer"] for source_ip in source_counts)
    if not source_counts:
        assert "source IP addresses" in response["answer"]


def test_assistant_unmatched_question_gives_more_supported_prompts(client, auth):
    response = _ask(client, auth, "Can you help me understand my setup?")

    assert "recent detections" in response["answer"]
    assert "risk level" in response["answer"]
    assert response["facts"] == {}
