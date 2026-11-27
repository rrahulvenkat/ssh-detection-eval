# ssh-detection-eval

**When is an LLM worth it for security log analysis?** This project runs a
rule-based detector and an LLM-based detector on the same SSH logs, scores
both against an independent answer key, and measures accuracy, cost and speed.

The two tools being compared:

- [ssh-log-analyzer](https://github.com/rrahulvenkat/ssh-log-analyzer): regular
  expressions and a sliding time window
- [log-analyzer-agent](https://github.com/rrahulvenkat/log-analyzer-agent):
  Claude (`claude-haiku-4-5`) reads each line, and rule-based checks verify its
  answers against the raw text

Both are run **unchanged**, loaded straight from their own repositories.

## Results

Data: the [Loghub](https://github.com/logpai/loghub) OpenSSH sample, 2,000
lines (729 distinct), 532 real login attempts, 11 brute-force IPs
(5+ failed logins within 10 minutes).

| | regex | LLM + checks | LLM alone |
|---|---|---|---|
| Attempt precision | **100.0%** | **100.0%** | 43.4% |
| Attempt recall | **100.0%** | 98.5% | 72.7% |
| Event-type accuracy | doesn't label | 99.8% | 88.8% |
| IP correct on login lines | **100.0%** | **100.0%** | 100.0% |
| Brute-force IPs found | **11 of 11** | 9 of 11 | 8 of 11 |
| False brute-force alarms | 0 | 0 | 0 |
| Time | **0.01 s** | 18.7 min | 18.7 min |
| API calls | 0 | 727 | 727 |
| Cost | **$0** | $0.65 | $0.65 |

"LLM alone" scores the model's raw answers, before the agent's own checks
corrected them. Full report: [results/REPORT.md](results/REPORT.md). The regex
column is after the fix in finding 2; before it, recall was 99.8%.

## What it found

**1. The LLM's accuracy came from the rules around it.** Claude's raw labels
were wrong on 158 of 729 distinct lines, in two systematic ways:

- `Failed password for invalid user X` (a failed attempt on an account that
  doesn't exist) was labelled `invalid_user` instead of `failed_login` on 111
  distinct lines (137 lines in the log), even though the system prompt says
  `Failed` lines are failed logins. Alone, that hides 137 real attempts.
- PAM's `authentication failure` lines, which sshd writes *alongside* the
  `Failed` line for the same attempt, were labelled `failed_login`. Alone, that
  adds 504 attempts that never happened: the busiest attacker shows 564
  attempts instead of 286.

The agent's checks compare each label with sshd's fixed wording and fixed
every one of these. With them the LLM matches the regex tool; without them
precision falls to 43%.

**2. The evaluation found a way past the regex, and it's now fixed.** One
attacker tried the username ` 0101`, with a leading space. The regex tool's
pattern expected a username with no spaces, so it missed the attempt
completely; Claude counted it (though it dropped the space). The username is
chosen by the attacker, so it can contain anything. The
[fix](https://github.com/rrahulvenkat/ssh-log-analyzer) takes the *last*
`from <ip> port <n>` on the line, so a fake `from 1.2.3.4 port 1` inside the
username can't frame another IP, and the report quotes usernames with hidden
spaces. Re-scored, the regex tool counts 532 of 532 attempts.

**3. Both tools lose information at a design level.** The agent counts
`message repeated 5 times: [ Failed password ... ]` as one attempt, not five,
which hides 2 of the 11 brute-force IPs. A perfect model wouldn't fix this:
the `--llm fake` run below shows the same gap. It's in the tool, not the model.

**4. Cost and speed.** For this log the LLM took 18.7 minutes and $0.65 for
work the regex does in a hundredth of a second for free. Its advantage is
lines nobody wrote a pattern for; on sshd's fixed, well-known formats, rules
win.

**The takeaway:** use rules for formats you know, an LLM for the ones you
don't, and never trust LLM labels without checking them against the data.
The obvious next design is a hybrid: regex first, the LLM only for lines the
regex can't read, with the same checks on its answers.

## How it's scored

The answer key ([answer_key.py](answer_key.py)) comes from Loghub's own
template labels on every line, so neither tool wrote it. Each of the 27
templates is given an event type, the position of its IP and username, and
the number of login attempts it stands for. The counting rule is the one both
tools' READMEs state: an attempt is a sshd `Failed ...` line, and
`message repeated N times` counts N.

Templates where a reasonable person could choose a different label (such as
whether a PAM failure line "is" a failed login) are marked ambiguous and left
out of the label-accuracy score, but every line counts for attempts and
detection. Two data quirks are handled explicitly: Loghub's `E14` template
doesn't match its own lines exactly, and PAM's `rhost=` sometimes holds a
hostname rather than an IP.

## Running it

You need both tool repositories next to this one, and the Loghub CSV at
`../LogAnalyzerAgent/data/OpenSSH_2k.log_structured.csv` (or pass `--csv`).

```bash
python evaluate.py --llm fake      # a perfect stand-in model: free, offline
python evaluate.py --llm cached    # re-score saved answers: free
python evaluate.py --llm real      # call Claude: about $0.65, about 19 minutes
python test_evaluate.py            # the scoring's own tests
```

`--llm real` reads the API key from `../LogAnalyzerAgent/.env`. Every answer
is cached in `results/llm_cache.json` (not committed, since it contains log
lines), so a real run is only paid for once.

## Limitations

- One dataset, from one server and one day. Other logs (and other models)
  may behave differently.
- One model, `claude-haiku-4-5`, at one prompt. A newer or larger model, or a
  better prompt, might label `invalid user` lines correctly; that's worth
  measuring, not assuming.
- The time includes the agent sending one request at a time; parallel or
  batched requests would be much faster, though not cheaper.
- The input/output token split wasn't recorded for this run, only the total
  cost.
