# Regex vs LLM: SSH brute-force detection

Data: `OpenSSH_2k.log_structured.csv` (2,000 lines, 2000 labelled, 532 real login attempts, 11 brute-force IPs). LLM answers: **cached**.

## Summary

| | regex | llm | llm, no checks |
|---|---|---|---|
| Attempt precision | 100.0% | 100.0% | 43.4% |
| Attempt recall | 100.0% | 98.5% | 72.7% |
| Event-type accuracy | doesn't label | 99.8% | 88.8% |
| IP correct on login lines | 100.0% | 100.0% | 100.0% |
| User correct on login lines | 100.0% | 99.8% | 99.8% |
| Brute-force IPs found | 11 of 11 | 9 of 11 | 8 of 11 |
| False brute-force alarms | 0 | 0 | 0 |
| Time | 0.01 s | 1124.03 s | 1124.03 s |
| API calls | 0 | 727 | 727 |
| Cost | $0.0000 | $0.6489 | $0.6489 |

## Where the counts differ

**regex:** 532 attempts counted correctly, 0 extra, 0 missed.

**llm:** 524 attempts counted correctly, 0 extra, 8 missed.
- missed, by template: E14 ×8
- most common wrong labels (template, correct -> given): E23 other -> accepted ×1; E22 other -> disconnected ×1
- its own checks corrected 158 model answers before scoring
- model claude-haiku-4-5
- 2 more calls ($0.0018) were made in a 3-line test before the full run
- input/output token split not recorded for this run
- cost and time are from the original API run; this was a free re-score

**llm, no checks:** 387 attempts counted correctly, 504 extra, 145 missed.
- missed, by template: E10 ×133, E14 ×8, E8 ×4
- extra, by template: E20 ×384, E19 ×110, E16 ×6, E17 ×2, E15 ×2
- most common wrong labels (template, correct -> given): E10 failed_login -> invalid_user ×133; E8 failed_login -> invalid_user ×4; E23 other -> accepted ×1; E22 other -> disconnected ×1
- the model's raw answers, scored without the agent's checks

## Brute-force IPs

| IP | real attempts | regex count | llm count | llm, no checks count |
|---|---|---|---|---|
| 183.62.140.253 | 286 | 286 ✓ | 286 ✓ | 564 ✓ |
| 187.141.143.180 | 80 | 80 ✓ | 80 ✓ | 131 ✓ |
| 103.99.0.122 | 46 | 46 ✓ | 46 ✓ | 58 ✓ |
| 112.95.230.3 | 26 | 26 ✓ | 26 ✓ | 50 ✓ |
| 5.188.10.180 | 20 | 20 ✓ | 20 ✓ | 13 ✓ |
| 185.190.58.151 | 18 | 18 ✓ | 18 ✓ | 10 ✓ |
| 123.235.32.19 | 7 | 7 ✓ | 7 ✓ | 14 ✓ |
| 106.5.5.195 | 6 | 6 ✓ | 2 missed | 4 missed |
| 119.4.203.64 | 6 | 6 ✓ | 6 ✓ | 2 missed |
| 5.36.59.76 | 6 | 6 ✓ | 2 missed | 2 missed |
| 60.2.12.12 | 5 | 5 ✓ | 5 ✓ | 10 ✓ |

