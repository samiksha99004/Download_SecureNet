"""
Incident reports: a readable report of detected attacks.

Used for
  - the file attached to every attack alert email (the events in that email),
  - the daily reports on the Reports page (one per day that had attacks),
    downloadable as .txt, .csv or .pdf.

Times are shown in local time. The DB stores naive UTC; `offset_minutes` is
minutes EAST of UTC (India = +330). The browser sends its own offset; the
alert emails use the server's local time zone.
"""

from collections import Counter
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional, Sequence

from app.models.security_event import SecurityEvent
from app.services.verdict import (BENIGN_NAMES, UNKNOWN_GUESS, clean_guesses, guesses_text,
                                  possible_attack, pretty_label)
from app.utils.timeutil import utcnow

RULE = "=" * 72
LINE = "-" * 72


def server_offset_minutes() -> int:
    """Local time-zone offset of the machine running the backend."""
    offset = datetime.now().astimezone().utcoffset()
    return int(offset.total_seconds() // 60) if offset else 0


def tz_label(offset_minutes: int) -> str:
    sign = "+" if offset_minutes >= 0 else "-"
    hours, minutes = divmod(abs(offset_minutes), 60)
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def to_local(value: datetime, offset_minutes: int) -> datetime:
    return value + timedelta(minutes=offset_minutes)


def local_day_bounds_utc(day: date, offset_minutes: int) -> tuple[datetime, datetime]:
    """[start, end) of a local calendar day, as naive UTC (for DB queries)."""
    start_local = datetime(day.year, day.month, day.day)
    start = start_local - timedelta(minutes=offset_minutes)
    return start, start + timedelta(days=1)


def _fmt_time(value: datetime, offset_minutes: int) -> str:
    return to_local(value, offset_minutes).strftime("%d %b %Y, %H:%M:%S")


def _counts(values: Sequence[str], limit: int = 5) -> str:
    common = Counter(values).most_common(limit)
    return ", ".join(f"{name} ({count})" for name, count in common) if common else "-"


def _guess_name(event: SecurityEvent) -> str:
    """The class the model guessed (without the percentage), for counting."""
    if event.attack_type:
        return event.attack_type
    for g in clean_guesses(event.attack_guesses):
        if g["label"].lower() not in BENIGN_NAMES:
            return g["label"]
    return UNKNOWN_GUESS


def summarize(events: Sequence[SecurityEvent]) -> Dict[str, object]:
    severities = Counter(e.severity.value for e in events)
    return {
        "total": len(events),
        "high": severities.get("high", 0),
        "medium": severities.get("medium", 0),
        "low": severities.get("low", 0),
        "top_attack": pretty_label(Counter(_guess_name(e) for e in events).most_common(1)[0][0])
        if events else None,
        "sources": len({e.source_ip for e in events}),
    }


def render_text(events: Sequence[SecurityEvent], title: str, offset_minutes: int,
                period: Optional[str] = None, breakdown: Optional[Sequence[dict]] = None,
                abnormal_pct: Optional[float] = None) -> str:
    """Plain-text report (oldest incident first), with the live dashboard breakdown on top."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    tz = tz_label(offset_minutes)
    now_local = to_local(utcnow(), offset_minutes).strftime("%d %b %Y, %H:%M:%S")
    info = summarize(ordered)

    lines: List[str] = [
        RULE,
        "SecureNet - Intrusion Detection Report",
        RULE,
        f"Report      : {title}",
    ]
    if period:
        lines.append(f"Period      : {period} ({tz})")
    lines += [
        f"Generated   : {now_local} ({tz})",
        "",
        "SUMMARY",
        LINE,
        f"Flagged flows    : {info['total']}",
        f"By severity      : High {info['high']} | Medium {info['medium']} | Low {info['low']}",
        f"Attacks detected : {_counts([pretty_label(_guess_name(e)) for e in ordered])}",
        f"Top addresses    : {_counts([e.source_ip for e in ordered])}",
        f"Between hosts    : {_counts([e.destination_ip for e in ordered])}",
        "",
    ]
    # Live dashboard breakdown: every traffic class and its share (even 0.1%) — same as the app.
    if breakdown:
        lines += ["LIVE TRAFFIC BREAKDOWN (same as the dashboard - every class, even 0.1%)", LINE]
        if abnormal_pct is not None:
            lines.append(f"Attacks were {abnormal_pct:.1f}% of recent traffic.")
        for r in breakdown:
            raw = str(r.get("label", "?"))
            pct = float(r.get("pct", 0.0))
            tag = "" if raw.lower() in ("benign", "normal") else "  (attack)"
            lines.append(f"    {pretty_label(raw):<28} {pct:5.1f}%{tag}")
        lines.append("")
    lines += [
        "DETECTED ATTACKS",
        LINE,
    ]
    if not ordered:
        lines.append("No abnormal traffic was detected in this period.")

    for number, event in enumerate(ordered, start=1):
        lines += [
            f"#{number}  {_fmt_time(event.timestamp, offset_minutes)}",
            f"    Attack        : {possible_attack(event.attack_type, event.confidence, event.attack_guesses)}",
        ]
        # Every attack detected in this incident with its exact share of traffic (the real
        # breakdown, not a single guess) — e.g. "FTP-BruteForce 51%, Cross Site Scripting 48%, Bot 1%".
        all_attacks = guesses_text(event.attack_guesses)
        if all_attacks and all_attacks != "-":
            lines.append(f"    All attacks   : {all_attacks}")
        lines += [
            f"    Severity      : {event.severity.value.upper()}",
            f"    Source        : {event.source_ip}:{event.source_port}",
            f"    Destination   : {event.destination_ip}:{event.destination_port} ({event.protocol.value})",
            f"    Status        : {event.state.value.replace('_', ' ')} | action: {event.action_taken.value}",
        ]
        if event.detection_reason:
            lines.append(f"    Reason        : {event.detection_reason}")
        features = event.contributing_features or []
        names = [f.get("name") for f in features if isinstance(f, dict) and f.get("name")]
        if names:
            lines.append(f"    Unusual features: {', '.join(names)}")
        lines.append(f"    Event ID      : {event.id}")
        lines.append("")

    lines += [LINE, "Generated automatically by SecureNet (behavioural intrusion detection).", ""]
    return "\r\n".join(lines)  # CRLF so Windows Notepad shows the line breaks


def report_filename(prefix: str, stamp: str, extension: str) -> str:
    return f"SecureNet-{prefix}-{stamp}.{extension}"
