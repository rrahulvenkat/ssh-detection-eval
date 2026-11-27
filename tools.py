"""Run each tool, unchanged, and collect what it says about every line.

Both tools are loaded from their own project folders (not copied), so this
measures exactly the code on GitHub. Paths default to the sibling folders
and can be changed in evaluate.py.

For every log line each tool produces a Verdict: the attempts it counts, the
event type (the agent only), and the IP and user it found. Each tool also
reports which IPs it flags as brute force.
"""

import csv
import importlib.util
import io
import json
import re
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

PROJECTS = Path(__file__).resolve().parent.parent

# Claude Haiku 4.5, USD per million tokens (the model the agent uses).
PRICES = {"claude-haiku-4-5": (1.00, 5.00)}


def load_module(path, name):
    """Import a .py file under a unique name (both tools have generic names)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass
class Verdict:
    attempts: int = 0
    event_type: str | None = None          # None: the tool doesn't label this
    ip: str | None = None
    user: str | None = None


@dataclass
class ToolRun:
    name: str
    verdicts: dict                         # line_id -> Verdict
    flagged: set                           # IPs flagged as brute force
    attempts_by_ip: dict
    seconds: float
    api_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    corrections: int = 0                   # agent answers fixed by its own checks
    notes: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# The regex tool (ssh-log-analyzer)
# ---------------------------------------------------------------------------

def run_regex(csv_path, year, threshold, window,
              repo=PROJECTS / "LogAnalyzer"):
    rx = load_module(repo / "openssh_regex.py", "ssh_log_analyzer")
    text = Path(csv_path).read_text(encoding="utf-8")
    rows = list(csv.DictReader(io.StringIO(text)))
    header = text.splitlines()[0]

    # Speed: the whole file through the real pipeline, timed.
    start = time.perf_counter()
    events = list(rx.read_events(io.StringIO(text), year, on_warning=lambda m: None))
    reports = rx.analyse(events, threshold, window)
    seconds = time.perf_counter() - start

    # Per line: feed each row through read_events on its own, so the verdict
    # for a line comes from exactly the code that processed the file.
    verdicts = {}
    for row in rows:
        one = header + "\n" + _csv_row(row)
        found = list(rx.read_events(io.StringIO(one), year, on_warning=lambda m: None))
        failed = [e for e in found if not e.success]
        first = found[0] if found else None
        verdicts[int(row["LineId"])] = Verdict(
            attempts=len(failed), event_type=None,
            ip=first.ip if first else None, user=first.user if first else None)

    return ToolRun("regex", verdicts,
                   flagged={r.ip for r in reports if r.brute_force},
                   attempts_by_ip={r.ip: r.failures for r in reports}, seconds=seconds)


def _csv_row(row):
    out = io.StringIO()
    csv.writer(out).writerow(row.values())
    return out.getvalue().rstrip("\r\n")


# ---------------------------------------------------------------------------
# The LLM tool (log-analyzer-agent)
# ---------------------------------------------------------------------------

class RecordingClient:
    """Wraps a real (or fake) client: records tokens and time for every call,
    and caches each answer by log line so re-running costs nothing.

    The agent only ever calls client.messages.parse(...), so this needs to
    look like a client in that one way (duck typing, polymorphism.py).
    """

    def __init__(self, inner, cache_path=None):
        self.inner = inner
        self.cache_path = Path(cache_path) if cache_path else None
        self.cache = {}
        if self.cache_path and self.cache_path.exists():
            self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.api_seconds = 0.0
        self.raw_answers = {}                     # line text -> what the model said
        self.messages = SimpleNamespace(parse=self.parse)

    def parse(self, **request):
        line = request["messages"][0]["content"]
        output_format = request["output_format"]
        if line in self.cache:
            saved = self.cache[line]
            self.raw_answers[line] = saved["answer"]
            parsed = output_format(**saved["answer"]) if saved["answer"] else None
            return SimpleNamespace(stop_reason=saved["stop_reason"], parsed_output=parsed)

        if self.inner is None:
            raise RuntimeError("no cached answer and no client: run with --llm real")
        start = time.perf_counter()
        response = self.inner.messages.parse(**request)
        self.api_seconds += time.perf_counter() - start
        self.calls += 1
        usage = getattr(response, "usage", None)
        self.input_tokens += getattr(usage, "input_tokens", 0) or 0
        self.output_tokens += getattr(usage, "output_tokens", 0) or 0

        answer = response.parsed_output.model_dump() if response.parsed_output else None
        self.raw_answers[line] = answer
        self.cache[line] = {"answer": answer, "stop_reason": response.stop_reason}
        self.save()
        return response

    def save(self):
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.cache, indent=1), encoding="utf-8")


def run_llm(csv_path, year, threshold, window, client,
            repo=PROJECTS / "LogAnalyzerAgent"):
    agent = load_module(repo / "main.py", "log_analyzer_agent")
    model = agent.MODEL
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "eval.db"
        start = time.perf_counter()
        stats = agent.process_logs(client, csv_path, db, limit=10**9, year=year,
                                   log=lambda m: None)
        suspects = agent.find_brute_force(db, threshold, window)
        seconds = time.perf_counter() - start

        verdicts = {}
        conn = sqlite3.connect(db)
        # The agent stores how many attempts each line stands for ("message
        # repeated N times" is N), and that's what its detection counts.
        for line_id, event_type, ip, user, attempts in conn.execute(
                "SELECT line_id, event_type, ip_address, username, attempts FROM ssh_logs"):
            verdicts[line_id] = Verdict(attempts=attempts or 0,
                                        event_type=event_type, ip=ip, user=user)
        conn.close()

    attempts_by_ip = {}
    for v in verdicts.values():
        if v.attempts and v.ip:
            attempts_by_ip[v.ip] = attempts_by_ip.get(v.ip, 0) + v.attempts

    price_in, price_out = PRICES.get(model, (0.0, 0.0))
    run = ToolRun("llm", verdicts, flagged={ip for ip, *_ in suspects},
                  attempts_by_ip=attempts_by_ip, seconds=seconds,
                  api_calls=client.calls, input_tokens=client.input_tokens,
                  output_tokens=client.output_tokens,
                  cost_usd=(client.input_tokens * price_in
                            + client.output_tokens * price_out) / 1_000_000,
                  corrections=stats["corrected"])
    if stats["skipped"]:
        run.notes.append(f"{stats['skipped']} lines skipped (API errors or refusals)")
    run.notes.append(f"model {model}")
    return run


def run_llm_unchecked(csv_path, raw_answers, brute_force, threshold, window, times):
    """The model's RAW answers, before the agent's own checks corrected them.

    `raw_answers` maps "<log_line>...</log_line>" to what the model returned
    (RecordingClient keeps these). `brute_force` is the answer key's rule, so
    the only difference from the answer key is the model's labels and fields.
    This answers: how much of the agent's accuracy comes from the model, and
    how much from the rule-based checks around it?
    """
    from answer_key import Truth                        # only for the shape of the data
    rows = list(csv.DictReader(open(csv_path, newline="", encoding="utf-8")))
    verdicts, pseudo = {}, {}
    for row in rows:
        line_id = int(row["LineId"])
        answer = raw_answers.get(f"<log_line>{row['Content'].strip()}</log_line>")
        if not answer:
            continue
        # Counted the way the agent counts (a fixed rule on the text), so this
        # column differs from the agent only in the model's own answers.
        attempts = 0
        if answer["event_type"] == "failed_login":
            repeated = re.match(r"message repeated (\d+) times: \[", row["Content"].strip())
            attempts = int(repeated[1]) if repeated else 1
        verdicts[line_id] = Verdict(attempts=attempts, event_type=answer["event_type"],
                                    ip=answer["ip_address"], user=answer["username"])
        pseudo[line_id] = Truth(line_id, "", answer["event_type"], False, attempts,
                                answer["ip_address"], answer["username"], None)
    flagged, totals = brute_force(pseudo, times, threshold, window)
    return ToolRun("llm, no checks", verdicts, flagged=flagged, attempts_by_ip=totals,
                   seconds=0.0, notes=["the model's raw answers, scored without the agent's checks"])
