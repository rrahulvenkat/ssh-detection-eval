"""The answer key: what each log line REALLY says, from Loghub's own labels.

Loghub's structured CSV gives every line an EventId and an EventTemplate,
such as "Failed password for <*> from <*> port <*> ssh2". Those labels were
made by Loghub's researchers, not by either tool being tested, which keeps
the comparison fair.

For each of the 27 OpenSSH templates this file records:
  - the event type, using the agent's five categories
  - which <*> slot holds the username, IP and port
  - how many login ATTEMPTS one line stands for (the thing detection counts)
  - whether the event type is AMBIGUOUS (a reasonable person could label it
    differently); those lines are left out of the label-accuracy score

The counting rule matches both tools' READMEs: an attempt is a sshd
"Failed <method> for ..." line. "Invalid user" and PAM lines are companion
lines that sshd writes for the SAME attempt, so they count zero.
"""

import ipaddress
import re
from dataclasses import dataclass

# (event_type, slots, attempts, ambiguous). Slots are 0-based positions of <*>;
# a string value is a literal (the template itself contains the name).
TEMPLATES = {
    "E1":  ("accepted",     {"user": 0, "ip": 1, "port": 2}, 0, False),
    "E2":  ("disconnected", {"ip": 0}, 0, False),
    "E3":  ("disconnected", {"ip": 0}, 0, True),      # closed before saying hello
    "E4":  ("disconnected", {"user": "admin"}, 0, False),
    "E5":  ("disconnected", {"user": "root"}, 0, False),
    "E6":  ("disconnected", {"ip": 0}, 0, False),
    "E7":  ("disconnected", {"ip": 0}, 0, False),
    "E8":  ("failed_login", {"user": 0, "ip": 1, "port": 2}, 1, False),
    "E9":  ("failed_login", {"user": 0, "ip": 1, "port": 2}, 1, False),
    "E10": ("failed_login", {"user": 0, "ip": 1, "port": 2}, 1, False),
    "E11": ("disconnected", {}, 0, True),             # "connection reset by peer"
    "E12": ("invalid_user", {"user": 0}, 0, True),    # "input_userauth_request: invalid user"
    "E13": ("invalid_user", {"user": 0, "ip": 1}, 0, False),
    "E14": ("failed_login", {"user": "root", "ip": 1, "port": 2}, "repeat", False),
    "E15": ("other",        {"ip": 3}, 0, True),      # PAM: companion of a Failed line
    "E16": ("other",        {"ip": 3}, 0, True),
    "E17": ("other",        {"user": "root", "ip": 3}, 0, True),
    "E18": ("other",        {}, 0, False),
    "E19": ("other",        {"ip": 2}, 0, True),
    "E20": ("other",        {"ip": 2, "user": 3}, 0, True),
    "E21": ("other",        {}, 0, True),             # "check pass; user unknown"
    "E22": ("other",        {"user": 0}, 0, False),
    "E23": ("other",        {"user": 0}, 0, False),
    "E24": ("disconnected", {"ip": 0}, 0, False),
    "E25": ("disconnected", {"ip": 0}, 0, False),
    "E26": ("disconnected", {"ip": 0}, 0, False),
    "E27": ("other",        {"ip": 1}, 0, False),     # reverse DNS mismatch warning
}


@dataclass(frozen=True)
class Truth:
    line_id: int
    template: str
    event_type: str
    ambiguous: bool
    attempts: int
    ip: str | None
    user: str | None
    port: int | None
    host: str | None = None       # a hostname where an IP would go (PAM's rhost=)

    @property
    def scored_fields(self):
        """IP and user only matter where detection uses them: login lines."""
        return self.event_type in ("failed_login", "accepted")


def template_regex(template):
    """'Failed password for <*> from <*>' -> a regex with one group per <*>."""
    pattern = re.escape(template).replace(re.escape("<*>"), "(.*?)")
    return re.compile(f"^{pattern}$")


def truth_for(row):
    """Build the Truth for one CSV row, using the row's own template."""
    event_id, template, content = row["EventId"], row["EventTemplate"], row["Content"]
    if event_id not in TEMPLATES:
        raise ValueError(f"line {row['LineId']}: no answer for template {event_id}")
    event_type, slots, attempts, ambiguous = TEMPLATES[event_id]

    match = template_regex(template).match(content)
    if match is None:
        raise ValueError(f"line {row['LineId']}: content doesn't match its template")
    params = match.groups()

    def slot(name):
        where = slots.get(name)
        if where is None:
            return None
        return where if isinstance(where, str) else params[where]

    if attempts == "repeat":                      # "message repeated <N> times"
        attempts = int(params[0])
    # Loghub's E14 template ends "port <*>]" but the real lines read
    # "port 42393 ssh2]", so keep only the leading digits.
    port = re.match(r"\d+", slot("port") or "")
    # PAM's rhost= holds a HOSTNAME when reverse DNS found one, sometimes one
    # that looks like an IP ("5.36.59.76.dynamic-dsl..."). That isn't an address.
    ip, host = slot("ip"), None
    if ip is not None:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            ip, host = None, ip
    return Truth(int(row["LineId"]), event_id, event_type, ambiguous, attempts,
                 ip, slot("user"), int(port.group()) if port else None, host)
