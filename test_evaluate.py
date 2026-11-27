"""Tests for the comparison itself, so a scoring bug can't pass as a finding.

Run with:  python test_evaluate.py   (uses the Loghub CSV if it's present)
"""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from answer_key import TEMPLATES, template_regex, truth_for
from evaluate import DEFAULT_CSV, main, score, true_brute_force
from tools import RecordingClient, ToolRun, Verdict


def row(line_id, event_id, template, content):
    return {"LineId": str(line_id), "EventId": event_id, "EventTemplate": template,
            "Content": content}


def test_template_regex_extracts_slots():
    rx = template_regex("Failed password for <*> from <*> port <*> ssh2")
    assert rx.match("Failed password for root from 1.2.3.4 port 22 ssh2").groups() == \
        ("root", "1.2.3.4", "22")
    assert rx.match("Accepted password for root from 1.2.3.4 port 22 ssh2") is None


def test_answer_key_rules():
    t = truth_for(row(1, "E14", "message repeated <*> times: [ Failed password for root from <*> port <*>]",
                      "message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]"))
    assert (t.attempts, t.ip, t.user, t.port) == (5, "5.36.59.76", "root", 42393)

    t = truth_for(row(2, "E20",
                      "pam_unix(sshd:auth): authentication failure; logname= uid=<*> euid=<*> tty=ssh ruser= rhost=<*> user=<*>",
                      "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=5.36.59.76.dynamic-dsl-ip.omantel.net.om user=root"))
    assert t.attempts == 0 and t.ip is None and t.host.startswith("5.36.59.76.dynamic")

    t = truth_for(row(3, "E13", "Invalid user <*> from <*>", "Invalid user admin from 1.2.3.4"))
    assert t.attempts == 0 and t.event_type == "invalid_user"     # companion line: not counted

    assert all(len(v) == 4 for v in TEMPLATES.values()) and len(TEMPLATES) == 27


def _truths(*specs):
    """specs: (line_id, attempts, ip) -> minimal Truth objects."""
    out = {}
    for line_id, attempts, ip in specs:
        out[line_id] = truth_for(row(line_id, "E9", "Failed password for <*> from <*> port <*> ssh2",
                                     f"Failed password for root from {ip} port 22 ssh2"))
        if attempts == 0:
            out[line_id] = truth_for(row(line_id, "E13", "Invalid user <*> from <*>",
                                         f"Invalid user x from {ip}"))
    return out


def test_attempt_scoring_counts_extra_and_missed():
    truths = _truths((1, 1, "1.1.1.1"), (2, 1, "1.1.1.1"), (3, 0, "2.2.2.2"))
    run = ToolRun("t", {1: Verdict(attempts=1, ip="1.1.1.1", user="root"),
                        3: Verdict(attempts=1, ip="2.2.2.2")},     # line 2 missed, line 3 extra
                  flagged=set(), attempts_by_ip={}, seconds=0)
    s = score(run, truths, set())
    assert (s.attempt_tp, s.attempt_fp, s.attempt_fn) == (1, 1, 1)
    assert s.attempt_precision == 0.5 and s.attempt_recall == 0.5


def test_detection_scoring():
    truths = _truths((1, 1, "1.1.1.1"))
    run = ToolRun("t", {}, flagged={"1.1.1.1", "9.9.9.9"}, attempts_by_ip={}, seconds=0)
    s = score(run, truths, {"1.1.1.1", "3.3.3.3"})
    assert s.flag_tp == {"1.1.1.1"} and s.flag_fp == {"9.9.9.9"} and s.flag_fn == {"3.3.3.3"}


def test_true_brute_force_uses_the_window():
    truths = _truths(*[(i, 1, "1.1.1.1") for i in range(1, 6)])
    t0 = datetime(2026, 12, 10, tzinfo=timezone.utc)
    burst = {i: t0 + timedelta(seconds=i) for i in truths}
    slow = {i: t0 + timedelta(hours=i) for i in truths}
    assert true_brute_force(truths, burst, 5, timedelta(minutes=10))[0] == {"1.1.1.1"}
    assert true_brute_force(truths, slow, 5, timedelta(minutes=10))[0] == set()


def test_cache_means_no_second_call():
    class Inner:
        calls = 0

        class messages:
            pass

    calls = []

    def parse(**request):
        calls.append(1)
        from types import SimpleNamespace
        answer = request["output_format"](ip_address="1.2.3.4", username="root",
                                          failure_reason=None, event_type="failed_login", port=22)
        return SimpleNamespace(stop_reason="end_turn", parsed_output=answer,
                               usage=SimpleNamespace(input_tokens=100, output_tokens=20))

    inner = Inner()
    inner.messages.parse = staticmethod(parse)
    from pydantic import BaseModel

    class F(BaseModel):
        ip_address: str | None
        username: str | None
        failure_reason: str | None
        event_type: str
        port: int | None

    with tempfile.TemporaryDirectory() as tmp:
        cache = Path(tmp) / "c.json"
        request = dict(messages=[{"role": "user", "content": "<log_line>x</log_line>"}], output_format=F)
        first = RecordingClient(inner, cache)
        first.parse(**request)
        assert first.calls == 1 and first.input_tokens == 100
        second = RecordingClient(None, cache)                    # no client at all
        assert second.parse(**request).parsed_output.ip_address == "1.2.3.4"
        assert second.calls == 0 and len(calls) == 1


def test_full_run_with_the_perfect_stand_in_model():
    if not DEFAULT_CSV.exists():
        print("   (skipped: Loghub CSV not found)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        assert main(["--llm", "fake", "--report", str(Path(tmp) / "r.md")]) == 0
        text = (Path(tmp) / "r.md").read_text()
        # A perfect model labels every unambiguous line correctly...
        assert "| Event-type accuracy | doesn't label | 100.0% |" in text
        # ...and the only attempts the agent misses are the "message repeated" ones.
        assert "missed, by template: E14 ×8" in text


if __name__ == "__main__":
    import contextlib
    import io
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        with contextlib.redirect_stdout(io.StringIO()):
            test()
        print(f"ok  {test.__name__}")
    print(f"\nAll {len(tests)} tests passed!")
