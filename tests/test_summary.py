"""The grounded analyst summary: every claim is verified by code against the session's events."""
from brain.agent.summary import build_summary, check_claim

SID = "att-1"
EVENTS = [
    {"event_id": "e1", "session_id": SID, "event_type": "command", "untrusted_content": "cat /opt/payouts/.env", "technique": "T1552.001"},
    {"event_id": "e2", "session_id": SID, "event_type": "login", "untrusted_content": "payouts:secret", "technique": "T1078"},
    {"event_id": "e9", "session_id": "other", "event_type": "command", "untrusted_content": "ls"},
]
BY = {e["event_id"]: e for e in EVENTS}


def test_verified_when_quote_is_in_cited_event():
    c = check_claim({"text": "The attacker read `/opt/payouts/.env`", "confidence": 0.9, "evidence": ["e1"]}, BY, SID)
    assert c["check"] == "verified" and c["confidence"] == 0.9


def test_unsupported_when_cited_event_missing():
    c = check_claim({"text": "x", "confidence": 0.9, "evidence": ["nope"]}, BY, SID)
    assert c["check"] == "unsupported" and c["confidence"] == 0.0


def test_unsupported_when_event_from_another_session():
    c = check_claim({"text": "x", "confidence": 0.9, "evidence": ["e9"]}, BY, SID)
    assert c["check"] == "unsupported"


def test_weak_when_quote_not_found_in_cited_event():
    c = check_claim({"text": "The attacker ran `mimikatz`", "confidence": 0.9, "evidence": ["e1"]}, BY, SID)
    assert c["check"] == "weak" and c["confidence"] <= 0.4


def test_technique_quote_verified():
    c = check_claim({"text": "Credential access T1552.001 observed", "confidence": 0.8, "evidence": ["e1"]}, BY, SID)
    assert c["check"] == "verified"


def test_build_summary_rates():
    claims = [
        {"text": "read `/opt/payouts/.env`", "confidence": 0.9, "evidence": ["e1"]},   # verified
        {"text": "ran `mimikatz`", "confidence": 0.8, "evidence": ["e1"]},             # weak
        {"text": "exfiltrated to evil.com", "confidence": 0.7, "evidence": ["ghost"]}, # unsupported
    ]
    s = build_summary(claims, EVENTS, SID)
    assert s["total"] == 3 and s["verified"] == 1 and s["weak"] == 1 and s["unsupported"] == 1
    assert s["hallucination_rate"] == round(1 / 3, 3) and s["grounding_rate"] == round(1 / 3, 3)
