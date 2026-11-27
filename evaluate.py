"""Compare rule-based (regex) and LLM-based SSH brute-force detection.

Both tools read the same Loghub OpenSSH log, and both are scored against an
answer key built from Loghub's own template labels (answer_key.py):

  1. Attempts   did each line's attempts get counted (precision / recall)?
  2. Labels     did the agent name the event type correctly? (regex doesn't label)
  3. Fields     on login lines, was the IP and username right?
  4. Detection  were the right IPs flagged as brute force?
  5. Cost       time, API calls, tokens, dollars

Usage:
    python evaluate.py --llm fake      # a perfect stand-in model: free, offline
    python evaluate.py --llm cached    # re-score saved answers: free
    python evaluate.py --llm real      # call Claude (costs money; needs a key)

The report is written to results/REPORT.md.
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from answer_key import truth_for
from tools import PROJECTS, RecordingClient, run_llm, run_llm_unchecked, run_regex

HERE = Path(__file__).resolve().parent
DEFAULT_CSV = PROJECTS / "LogAnalyzerAgent" / "data" / "OpenSSH_2k.log_structured.csv"
CACHE = HERE / "results" / "llm_cache.json"
RUN_STATS = HERE / "results" / "llm_run.json"     # what the real API run cost, kept for re-scoring
REPORT = HERE / "results" / "REPORT.md"


# ---------------------------------------------------------------------------
# The answer key, and the brute-force IPs it implies
# ---------------------------------------------------------------------------

def load_truth(csv_path, year):
    rows = list(csv.DictReader(open(csv_path, newline="", encoding="utf-8")))
    truths, times = {}, {}
    for row in rows:
        t = truth_for(row)
        truths[t.line_id] = t
        hour, minute, second = (int(x) for x in row["Time"].split(":"))
        month = datetime.strptime(row["Date"], "%b").month
        times[t.line_id] = datetime(year, month, int(row["Day"]), hour, minute, second,
                                    tzinfo=timezone.utc)
    return truths, times


def true_brute_force(truths, times, threshold, window):
    """The same rule both tools use, applied to the answer key."""
    by_ip = defaultdict(list)
    for line_id, t in truths.items():
        if t.attempts and t.ip:
            by_ip[t.ip] += [times[line_id]] * t.attempts
    flagged, totals = set(), {}
    for ip, stamps in by_ip.items():
        stamps.sort()
        totals[ip] = len(stamps)
        recent = deque()
        for when in stamps:
            recent.append(when)
            while when - recent[0] > window:
                recent.popleft()
            if len(recent) >= threshold:
                flagged.add(ip)
    return flagged, totals


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def ratio(a, b):
    return a / b if b else float("nan")


def score(run, truths, true_flagged):
    s = SimpleNamespace(name=run.name)

    # 1. Attempts, weighted: a "message repeated 5 times" line is 5 attempts.
    tp = fp = fn = 0
    missed, extra = Counter(), Counter()
    for line_id, t in truths.items():
        said = run.verdicts.get(line_id).attempts if line_id in run.verdicts else 0
        tp += min(said, t.attempts)
        if said > t.attempts:
            fp += said - t.attempts
            extra[t.template] += said - t.attempts
        if said < t.attempts:
            fn += t.attempts - said
            missed[t.template] += t.attempts - said
    s.attempt_tp, s.attempt_fp, s.attempt_fn = tp, fp, fn
    s.attempt_precision, s.attempt_recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    s.missed_by_template, s.extra_by_template = missed, extra

    # 2. Labels (agent only), on lines whose label isn't a judgement call.
    labelled = [(t, run.verdicts.get(i)) for i, t in truths.items() if not t.ambiguous]
    if any(v and v.event_type for _, v in labelled):
        right = sum(1 for t, v in labelled if v and v.event_type == t.event_type)
        s.label_accuracy, s.label_total = ratio(right, len(labelled)), len(labelled)
        s.mislabels = Counter((t.template, t.event_type, v.event_type if v else "skipped")
                              for t, v in labelled if not v or v.event_type != t.event_type)
    else:
        s.label_accuracy, s.label_total, s.mislabels = None, len(labelled), Counter()

    # 3. Fields on login lines (where detection uses them).
    scored = [(t, run.verdicts.get(i)) for i, t in truths.items() if t.scored_fields]
    s.field_total = len(scored)
    s.ip_accuracy = ratio(sum(1 for t, v in scored if v and v.ip == t.ip), len(scored))
    s.user_accuracy = ratio(sum(1 for t, v in scored if v and v.user == t.user), len(scored))

    # 4. Detection.
    s.flag_tp = run.flagged & true_flagged
    s.flag_fp = run.flagged - true_flagged
    s.flag_fn = true_flagged - run.flagged
    s.attempts_by_ip = run.attempts_by_ip

    # 5. Cost.
    s.seconds, s.api_calls, s.cost_usd = run.seconds, run.api_calls, run.cost_usd
    s.input_tokens, s.output_tokens = run.input_tokens, run.output_tokens
    s.corrections, s.notes = run.corrections, run.notes
    return s


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def pct(x):
    return "n/a" if x is None or x != x else f"{x:.1%}"


def build_report(scores, truths, true_flagged, true_totals, llm_mode, csv_path):
    lines_total = len(truths)
    attempts_total = sum(t.attempts for t in truths.values())
    r = [f"# Regex vs LLM: SSH brute-force detection",
         "",
         f"Data: `{Path(csv_path).name}` ({lines_total:,} lines, "
         f"{len({t.line_id for t in truths.values()})} labelled, "
         f"{attempts_total} real login attempts, {len(true_flagged)} brute-force IPs). "
         f"LLM answers: **{llm_mode}**.",
         ""]
    if llm_mode == "fake":
        r += ["> The LLM column uses a **perfect stand-in model** that always gives the "
              "answer key's response. It shows the best the agent's pipeline can do; any "
              "gap from 100% is the tool's design, not the model.", ""]

    def row(label, fn):
        return f"| {label} | " + " | ".join(fn(s) for s in scores) + " |"

    r += ["## Summary", "",
          "| | " + " | ".join(s.name for s in scores) + " |",
          "|---|" + "---|" * len(scores),
          row("Attempt precision", lambda s: pct(s.attempt_precision)),
          row("Attempt recall", lambda s: pct(s.attempt_recall)),
          row("Event-type accuracy", lambda s: pct(s.label_accuracy) if s.label_accuracy is not None
              else "doesn't label"),
          row("IP correct on login lines", lambda s: pct(s.ip_accuracy)),
          row("User correct on login lines", lambda s: pct(s.user_accuracy)),
          row("Brute-force IPs found", lambda s: f"{len(s.flag_tp)} of {len(true_flagged)}"),
          row("False brute-force alarms", lambda s: str(len(s.flag_fp))),
          row("Time", lambda s: f"{s.seconds:.2f} s"),
          row("API calls", lambda s: str(s.api_calls)),
          row("Cost", lambda s: f"${s.cost_usd:.4f}"),
          ""]

    r += ["## Where the counts differ", ""]
    for s in scores:
        r.append(f"**{s.name}:** {s.attempt_tp} attempts counted correctly, "
                 f"{s.attempt_fp} extra, {s.attempt_fn} missed.")
        if s.missed_by_template:
            r.append("- missed, by template: " + ", ".join(
                f"{k} ×{v}" for k, v in s.missed_by_template.most_common()))
        if s.extra_by_template:
            r.append("- extra, by template: " + ", ".join(
                f"{k} ×{v}" for k, v in s.extra_by_template.most_common()))
        if s.mislabels:
            r.append("- most common wrong labels (template, correct -> given): " + "; ".join(
                f"{tpl} {want} -> {got} ×{n}" for (tpl, want, got), n in s.mislabels.most_common(5)))
        if s.corrections:
            r.append(f"- its own checks corrected {s.corrections} model answers before scoring")
        for note in s.notes:
            r.append(f"- {note}")
        r.append("")

    r += ["## Brute-force IPs", "",
          "| IP | real attempts | " + " | ".join(f"{s.name} count" for s in scores) + " |",
          "|---|---|" + "---|" * len(scores)]
    for ip in sorted(true_flagged | set().union(*(s.flag_fp for s in scores)),
                     key=lambda ip: -true_totals.get(ip, 0)):
        cells = []
        for s in scores:
            mark = "✓" if ip in s.flag_tp else ("✗ false alarm" if ip in s.flag_fp else "missed")
            cells.append(f"{s.attempts_by_ip.get(ip, 0)} {mark}")
        r.append(f"| {ip} | {true_totals.get(ip, 0)} | " + " | ".join(cells) + " |")
    r.append("")
    return "\n".join(r)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def fake_client(truths, csv_path):
    """A stand-in model that always returns the answer key's response."""
    rows = list(csv.DictReader(open(csv_path, newline="", encoding="utf-8")))
    by_content = {row["Content"]: truths[int(row["LineId"])] for row in rows}

    def parse(**request):
        content = request["messages"][0]["content"].removeprefix("<log_line>").removesuffix("</log_line>")
        t = by_content[content]
        answer = request["output_format"](ip_address=t.ip, username=t.user, failure_reason=None,
                                          event_type=t.event_type, port=t.port)
        return SimpleNamespace(stop_reason="end_turn", parsed_output=answer,
                               usage=SimpleNamespace(input_tokens=0, output_tokens=0))
    return SimpleNamespace(messages=SimpleNamespace(parse=parse))


def build_parser():
    p = argparse.ArgumentParser(description="Compare regex and LLM SSH brute-force detection.")
    p.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    p.add_argument("--llm", choices=["fake", "cached", "real"], default="fake")
    p.add_argument("--year", type=int, default=2026)
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--window", type=int, default=10, help="minutes")
    p.add_argument("--report", type=Path, default=REPORT)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    window = timedelta(minutes=args.window)
    truths, times = load_truth(args.csv, args.year)
    true_flagged, true_totals = true_brute_force(truths, times, args.threshold, window)

    regex = run_regex(args.csv, args.year, args.threshold, window)

    if args.llm == "fake":
        client = RecordingClient(fake_client(truths, args.csv))
    elif args.llm == "cached":
        client = RecordingClient(None, CACHE)
    else:
        import anthropic
        from dotenv import load_dotenv
        load_dotenv(PROJECTS / "LogAnalyzerAgent" / ".env")
        client = RecordingClient(anthropic.Anthropic(), CACHE)
    llm = run_llm(args.csv, args.year, args.threshold, window, client)

    # The cache keeps answers, not what they cost. A real run saves its totals;
    # a cached re-score reports those instead of its own (free) numbers.
    cost_fields = ("api_calls", "input_tokens", "output_tokens", "cost_usd", "seconds")
    if args.llm == "real":
        args.report.parent.mkdir(parents=True, exist_ok=True)
        RUN_STATS.write_text(json.dumps({k: getattr(llm, k) for k in cost_fields}, indent=1))
    elif args.llm == "cached" and RUN_STATS.exists():
        saved = json.loads(RUN_STATS.read_text())
        for k in cost_fields:
            setattr(llm, k, saved.get(k, getattr(llm, k)))
        llm.notes += saved.get("notes", [])
        llm.notes.append("cost and time are from the original API run; this was a free re-score")

    unchecked = run_llm_unchecked(args.csv, client.raw_answers, true_brute_force,
                                  args.threshold, window, times)
    for k in cost_fields:                         # the same API calls, scored differently
        setattr(unchecked, k, getattr(llm, k))

    scores = [score(regex, truths, true_flagged), score(llm, truths, true_flagged),
              score(unchecked, truths, true_flagged)]
    report = build_report(scores, truths, true_flagged, true_totals, args.llm, args.csv)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report + "\n", encoding="utf-8")
    print(report)
    print(f"\n(written to {args.report})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
