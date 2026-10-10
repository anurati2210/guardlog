"""Parses raw log lines into Event objects."""
import re
import sys
from dataclasses import dataclass
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<ts>\S+) ip=(?P<ip>\S+) user=(?P<user>\S+) "
    r"action=(?P<action>\S+) pw=(?P<pw>\S+) path=(?P<path>.*)$"
)


@dataclass
class Event:
    ts: float       # seconds since epoch (easy to compare in time windows)
    time_str: str   # original timestamp text, for display
    ip: str
    user: str
    action: str     # LOGIN_OK, LOGIN_FAIL, REQUEST, REQUEST_404
    pw: str         # attempted password (simulated), or "-"
    path: str       # may contain spaces, so it is the last field
    raw: str        # the original line


def parse_line(line):
    """Return an Event, or None if the line is malformed."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    try:
        ts = datetime.fromisoformat(m.group("ts")).timestamp()
    except ValueError:
        return None
    return Event(ts, m.group("ts"), m.group("ip"), m.group("user"),
                 m.group("action"), m.group("pw"), m.group("path"), line.strip())


def parse_lines(lines):
    """Parse an iterable of lines. Returns (events, malformed_count)."""
    events, bad = [], 0
    for line in lines:
        if not line.strip():
            continue
        ev = parse_line(line)
        if ev is None:
            bad += 1
        else:
            events.append(ev)
    return events, bad


def parse_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_lines(f)


if __name__ == "__main__":
    # Quick self-test: python -m guardlog.parser data/sample.log
    file_path = sys.argv[1] if len(sys.argv) > 1 else "data/sample.log"
    events, bad = parse_file(file_path)
    print(f"Parsed {len(events)} events, {bad} malformed lines")
    for ev in events[:3]:
        print(ev)

    # Malformed lines must be skipped, not crash
    assert parse_line("this is not a log line") is None
    assert parse_line("") is None
    good = "2026-10-11T10:00:01 ip=1.2.3.4 user=admin action=LOGIN_FAIL pw=123456 path=/login"
    assert parse_line(good).ip == "1.2.3.4"
    spaced = "2026-10-11T10:00:01 ip=1.2.3.4 user=- action=REQUEST pw=- path=/search?q=UNION SELECT"
    assert parse_line(spaced).path == "/search?q=UNION SELECT"
    print("Self-tests passed")