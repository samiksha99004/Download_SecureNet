"""
Render security events to CSV / JSON / PDF (used by event export and reports).
All functions are synchronous and CPU-bound — call them via asyncio.to_thread.
"""

import csv
import io
import json
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from app.models.security_event import SecurityEvent
from app.services.verdict import ABNORMAL, guesses_text
from app.utils.timeutil import to_iso_z

COMPUTED = {
    "verdict": lambda e: ABNORMAL,
    "attack_guesses": lambda e: guesses_text(e.attack_guesses) if e.attack_guesses else None,
}
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

COLUMNS = [
    ("timestamp", "Timestamp (UTC)"),
    ("source_ip", "Source IP"),
    ("source_port", "Src Port"),
    ("destination_ip", "Destination IP"),
    ("destination_port", "Dst Port"),
    ("protocol", "Protocol"),
    ("anomaly_score", "Score"),
    ("severity", "Severity"),
    ("verdict", "Verdict"),
    ("attack_type", "Top Attack"),
    ("confidence", "Top Attack %"),
    ("attack_guesses", "Attack Breakdown (all, exact %)"),
    ("mode", "Mode"),
    ("state", "State"),
    ("action_taken", "Action"),
    ("detection_reason", "Reason"),
]


def event_row(event: SecurityEvent) -> Dict[str, object]:
    def val(attr: str):
        if attr in COMPUTED:
            return COMPUTED[attr](event)
        value = getattr(event, attr)
        if isinstance(value, datetime):
            return to_iso_z(value)
        return getattr(value, "value", value)

    return {attr: val(attr) for attr, _ in COLUMNS} | {"id": str(event.id)}


def _cell(value) -> object:
    """CSV cell; text that a spreadsheet would run as a formula (=, +, -, @) is quoted with '
    so a crafted value can never execute when the export is opened in Excel."""
    if value is None:
        return ""
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value


def to_csv(events: Sequence[SecurityEvent]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ID"] + [label for _, label in COLUMNS])
    for event in events:
        row = event_row(event)
        writer.writerow([row["id"]] + [_cell(row[a]) for a, _ in COLUMNS])
    return buffer.getvalue().encode("utf-8-sig")  # BOM so Excel opens UTF-8 correctly


def breakdown(events: Sequence[SecurityEvent]) -> Dict[str, Dict[str, int]]:
    return {
        "severity": dict(Counter(e.severity.value for e in events)),
        "state": dict(Counter(e.state.value for e in events)),
        "possible attack": dict(Counter(e.attack_type or "Unknown" for e in events)),
        "action": dict(Counter(e.action_taken.value for e in events)),
    }


def to_json(events: Sequence[SecurityEvent], meta: Optional[dict] = None, include_breakdown: bool = True) -> bytes:
    doc: dict = {"meta": meta or {}, "total": len(events)}
    if include_breakdown:
        doc["breakdown"] = breakdown(events)
    doc["events"] = [event_row(e) for e in events]
    return json.dumps(doc, indent=2, default=str).encode("utf-8")


# ── PDF branding ───────────────────────────────────────────────────────────────
_PDF_NAVY = "#0f172a"
_PDF_BLUE = "#2563eb"
_PDF_SLATE = "#334155"
_PDF_GRAY = "#64748b"
_PDF_LIGHT = "#eef2f7"
_PDF_BORDER = "#cbd5e1"
_SEV_COLORS = {"high": "#dc2626", "medium": "#d97706", "low": "#16a34a"}


def _draw_shield(c, cx: float, cy: float, s: float) -> None:
    """Draw a small shield with a check mark, centred at (cx, cy), size `s` (points)."""
    from reportlab.lib import colors
    top, mid, bot = cy + s * 0.45, cy + 0.0, cy - s * 0.55
    half = s * 0.38
    p = c.beginPath()
    p.moveTo(cx - half, top)
    p.lineTo(cx + half, top)
    p.lineTo(cx + half, mid)
    p.lineTo(cx, bot)
    p.lineTo(cx - half, mid)
    p.close()
    c.setFillColor(colors.HexColor(_PDF_BLUE))
    c.setStrokeColor(colors.white)
    c.setLineWidth(1.1)
    c.drawPath(p, fill=1, stroke=1)
    # check mark
    c.setStrokeColor(colors.white)
    c.setLineWidth(1.6)
    c.setLineCap(1)
    c.setLineJoin(1)
    chk = c.beginPath()
    chk.moveTo(cx - s * 0.20, cy + s * 0.02)
    chk.lineTo(cx - s * 0.02, cy - s * 0.16)
    chk.lineTo(cx + s * 0.24, cy + s * 0.20)
    c.drawPath(chk, fill=0, stroke=1)


def to_pdf(events: Sequence[SecurityEvent], title: str, subtitle: str = "",
           include_breakdown: bool = True) -> bytes:
    from datetime import timezone
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    page_w, page_h = landscape(A4)
    generated = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    def _decorate(canvas, doc):
        """Draw the page border, the SecureNet header (shield + title) and the footer — every page."""
        canvas.saveState()
        m = 8 * mm
        # double border
        canvas.setStrokeColor(colors.HexColor(_PDF_NAVY))
        canvas.setLineWidth(1.6)
        canvas.roundRect(m, m, page_w - 2 * m, page_h - 2 * m, 8, stroke=1, fill=0)
        canvas.setStrokeColor(colors.HexColor(_PDF_BORDER))
        canvas.setLineWidth(0.6)
        canvas.roundRect(m + 3, m + 3, page_w - 2 * m - 6, page_h - 2 * m - 6, 7, stroke=1, fill=0)
        # header band
        band_h = 16 * mm
        bx, by, bw = m + 3, page_h - m - 3 - band_h, page_w - 2 * m - 6
        canvas.setFillColor(colors.HexColor(_PDF_NAVY))
        canvas.roundRect(bx, by, bw, band_h, 7, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor(_PDF_NAVY))     # square off the bottom corners of the band
        canvas.rect(bx, by, bw, band_h / 2, stroke=0, fill=1)
        # shield + title
        _draw_shield(canvas, bx + 12 * mm, by + band_h / 2, 9 * mm)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 17)
        canvas.drawString(bx + 20 * mm, by + band_h / 2 - 1 * mm, "SecureNet Report")
        canvas.setFillColor(colors.HexColor("#93c5fd"))
        canvas.setFont("Helvetica", 8)
        canvas.drawString(bx + 20 * mm, by + band_h / 2 - 5.2 * mm, "Network Intrusion Detection System")
        canvas.setFillColor(colors.HexColor("#cbd5e1"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(bx + bw - 6 * mm, by + band_h / 2 - 3 * mm, f"Generated {generated}")
        # footer
        fy = m + 4 * mm
        canvas.setStrokeColor(colors.HexColor(_PDF_BORDER))
        canvas.setLineWidth(0.5)
        canvas.line(m + 6, fy + 3.5 * mm, page_w - m - 6, fy + 3.5 * mm)
        canvas.setFillColor(colors.HexColor(_PDF_GRAY))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(m + 6, fy, "SecureNet — Behavioural Intrusion Detection System")
        canvas.drawCentredString(page_w / 2, fy, "Confidential — for the account owner")
        canvas.drawRightString(page_w - m - 6, fy, f"Page {doc.page}")
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        leftMargin=14 * mm, rightMargin=14 * mm, topMargin=34 * mm, bottomMargin=18 * mm, title=title,
    )

    h1 = ParagraphStyle("snTitle", fontName="Helvetica-Bold", fontSize=15,
                        textColor=colors.HexColor(_PDF_NAVY), spaceAfter=2, alignment=TA_LEFT)
    sub = ParagraphStyle("snSub", fontName="Helvetica", fontSize=9.5,
                         textColor=colors.HexColor(_PDF_GRAY), spaceAfter=6)
    h2 = ParagraphStyle("snH2", fontName="Helvetica-Bold", fontSize=10.5,
                        textColor=colors.HexColor(_PDF_SLATE), spaceBefore=4, spaceAfter=4)

    story: List = [Paragraph(title or "Security Report", h1)]
    if subtitle:
        story.append(Paragraph(subtitle, sub))

    # summary strip
    sev = Counter(e.severity.value for e in events)
    summary = Table([[
        f"{len(events)}\nTotal alerts",
        f"{sev.get('high', 0)}\nHigh",
        f"{sev.get('medium', 0)}\nMedium",
        f"{sev.get('low', 0)}\nLow",
        f"{len({e.source_ip for e in events})}\nSources",
    ]], colWidths=[52 * mm] + [40 * mm] * 4)
    summary.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 13),
        ("TEXTCOLOR", (0, 0), (0, 0), colors.HexColor(_PDF_NAVY)),
        ("TEXTCOLOR", (1, 0), (1, 0), colors.HexColor(_SEV_COLORS["high"])),
        ("TEXTCOLOR", (2, 0), (2, 0), colors.HexColor(_SEV_COLORS["medium"])),
        ("TEXTCOLOR", (3, 0), (3, 0), colors.HexColor(_SEV_COLORS["low"])),
        ("TEXTCOLOR", (4, 0), (4, 0), colors.HexColor(_PDF_SLATE)),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(_PDF_LIGHT)),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor(_PDF_BORDER)),
        ("LINEAFTER", (0, 0), (-2, -1), 0.5, colors.HexColor(_PDF_BORDER)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEADING", (0, 0), (-1, -1), 13),
    ]))
    story += [summary, Spacer(1, 6 * mm)]

    header_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(_PDF_NAVY)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor(_PDF_BLUE)),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor(_PDF_BORDER)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(_PDF_LIGHT)]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ])

    if include_breakdown and events:
        story.append(Paragraph("Summary breakdown", h2))
        blocks = []
        for name, counts in breakdown(events).items():
            rows = [[name.capitalize(), "Count"]] + [[k, str(v)] for k, v in sorted(counts.items(), key=lambda kv: -kv[1])]
            t = Table(rows, colWidths=[46 * mm, 18 * mm])
            t.setStyle(header_style)
            blocks.append(t)
        # lay the breakdown tables side by side (2 per row)
        for i in range(0, len(blocks), 2):
            pair = blocks[i:i + 2]
            wrap = Table([pair + [""] * (2 - len(pair))], colWidths=[70 * mm, 70 * mm], hAlign="LEFT")
            wrap.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                      ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 8)]))
            story += [wrap, Spacer(1, 3 * mm)]
        story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("Flagged flows (the model's guesses)", h2))
    story.append(Paragraph(
        "Each row is a flow the model flagged as possibly abnormal. The attack is a guess, not confirmed "
        "— on normal internet traffic some are false positives, and for one flow either end may be the source.",
        ParagraphStyle("snNote", fontName="Helvetica-Oblique", fontSize=8,
                       textColor=colors.HexColor(_PDF_GRAY), spaceAfter=6)))
    cols = ["timestamp", "source_ip", "destination_ip", "destination_port", "protocol",
            "severity", "attack_type", "state", "action_taken"]
    labels = dict(COLUMNS)
    rows = [[labels[c] for c in cols]]
    sev_rows: list = []
    for event in events:
        row = event_row(event)
        rows.append([
            f"{row[c]:.3f}" if c == "anomaly_score" and row[c] is not None else ("" if row[c] is None else str(row[c]))
            for c in cols
        ])
        sev_rows.append(event.severity.value)
    table = Table(rows, repeatRows=1)
    tstyle = TableStyle(header_style.getCommands())
    sev_col = cols.index("severity")
    for i, s in enumerate(sev_rows, start=1):
        if s in _SEV_COLORS:
            tstyle.add("TEXTCOLOR", (sev_col, i), (sev_col, i), colors.HexColor(_SEV_COLORS[s]))
            tstyle.add("FONTNAME", (sev_col, i), (sev_col, i), "Helvetica-Bold")
    table.setStyle(tstyle)
    story.append(table)

    doc.build(story, onFirstPage=_decorate, onLaterPages=_decorate)
    return buffer.getvalue()


def report_to_pdf(events: Sequence[SecurityEvent], title: str, offset_minutes: int,
                  period: Optional[str] = None, breakdown: Optional[Sequence[dict]] = None,
                  abnormal_pct: Optional[float] = None) -> bytes:
    """Styled A4 report PDF that mirrors incident_report.render_text section-for-section
    (meta → SUMMARY → optional LIVE TRAFFIC BREAKDOWN → DETECTED ATTACKS). Same content as
    the .txt download, laid out as clean branded cards instead of a raw table."""
    from xml.sax.saxutils import escape
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    from app.services import incident_report as ir
    from app.services.verdict import guesses_text, possible_attack, pretty_label
    from app.utils.timeutil import utcnow

    ordered = sorted(events, key=lambda e: e.timestamp)
    tz = ir.tz_label(offset_minutes)
    now_local = ir.to_local(utcnow(), offset_minutes).strftime("%d %b %Y, %H:%M:%S")
    info = ir.summarize(ordered)
    page_w, page_h = A4
    content_w = page_w - 32 * mm

    navy = colors.HexColor(_PDF_NAVY)
    slate = colors.HexColor(_PDF_SLATE)
    gray = colors.HexColor(_PDF_GRAY)
    border = colors.HexColor(_PDF_BORDER)
    light = colors.HexColor(_PDF_LIGHT)
    ink = colors.HexColor("#0b1220")

    def _decorate(canvas, doc):
        canvas.saveState()
        m = 8 * mm
        canvas.setStrokeColor(navy); canvas.setLineWidth(1.6)
        canvas.roundRect(m, m, page_w - 2 * m, page_h - 2 * m, 8, stroke=1, fill=0)
        canvas.setStrokeColor(border); canvas.setLineWidth(0.6)
        canvas.roundRect(m + 3, m + 3, page_w - 2 * m - 6, page_h - 2 * m - 6, 7, stroke=1, fill=0)
        band_h = 16 * mm
        bx, by, bw = m + 3, page_h - m - 3 - band_h, page_w - 2 * m - 6
        canvas.setFillColor(navy)
        canvas.roundRect(bx, by, bw, band_h, 7, stroke=0, fill=1)
        canvas.rect(bx, by, bw, band_h / 2, stroke=0, fill=1)
        _draw_shield(canvas, bx + 11 * mm, by + band_h / 2, 9 * mm)
        canvas.setFillColor(colors.white); canvas.setFont("Helvetica-Bold", 15)
        canvas.drawString(bx + 18 * mm, by + band_h / 2 - 1 * mm, "SecureNet Report")
        canvas.setFillColor(colors.HexColor("#93c5fd")); canvas.setFont("Helvetica", 7.5)
        canvas.drawString(bx + 18 * mm, by + band_h / 2 - 4.8 * mm, "Network Intrusion Detection System")
        canvas.setFillColor(colors.HexColor("#cbd5e1")); canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(bx + bw - 5 * mm, by + band_h / 2 - 2.5 * mm, f"Generated {now_local}")
        fy = m + 4 * mm
        canvas.setStrokeColor(border); canvas.setLineWidth(0.5)
        canvas.line(m + 6, fy + 3.5 * mm, page_w - m - 6, fy + 3.5 * mm)
        canvas.setFillColor(gray); canvas.setFont("Helvetica", 7.5)
        canvas.drawString(m + 6, fy, "SecureNet - Behavioural Intrusion Detection System")
        canvas.drawCentredString(page_w / 2, fy, "Confidential - for the account owner")
        canvas.drawRightString(page_w - m - 6, fy, f"Page {doc.page}")
        canvas.restoreState()

    h1 = ParagraphStyle("rTitle", fontName="Helvetica-Bold", fontSize=15, textColor=navy,
                        spaceBefore=6, spaceAfter=9, leading=19)
    lbl = ParagraphStyle("rLbl", fontName="Helvetica-Bold", fontSize=8.5, textColor=slate, leading=12)
    val = ParagraphStyle("rVal", fontName="Helvetica", fontSize=9, textColor=ink, leading=12)
    note = ParagraphStyle("rNote", fontName="Helvetica-Oblique", fontSize=8, textColor=gray, leading=11)

    def section(text: str):
        t = Table([[text]], colWidths=[content_w])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), navy),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    def kv(pairs, lw=40 * mm):
        rows = [[Paragraph(escape(k), lbl), Paragraph(escape(str(v)), val)] for k, v in pairs]
        t = Table(rows, colWidths=[lw, content_w - lw])
        t.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, border), ("INNERGRID", (0, 0), (-1, -1), 0.4, border),
            ("BACKGROUND", (0, 0), (0, -1), light), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    story: List = [Paragraph(escape(title or "SecureNet Report"), h1), Spacer(1, 2.5 * mm)]
    meta = [("Report", title)]
    if period:
        meta.append(("Period", f"{period} ({tz})"))
    meta.append(("Generated", f"{now_local} ({tz})"))
    mt = Table([[Paragraph(escape(k), lbl), Paragraph(escape(str(v)), val)] for k, v in meta],
               colWidths=[26 * mm, content_w - 26 * mm])
    mt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (0, -1), 0),
                            ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5)]))
    story += [mt, Spacer(1, 6 * mm)]

    # SUMMARY
    story += [section("SUMMARY"), Spacer(1, 1.5 * mm)]
    story += [kv([
        ("Flagged flows", info["total"]),
        ("By severity", f"High {info['high']} | Medium {info['medium']} | Low {info['low']}"),
        ("Attacks detected", ir._counts([pretty_label(ir._guess_name(e)) for e in ordered])),
        ("Top addresses", ir._counts([e.source_ip for e in ordered])),
        ("Between hosts", ir._counts([e.destination_ip for e in ordered])),
    ]), Spacer(1, 4 * mm)]

    # LIVE TRAFFIC BREAKDOWN (only when provided, same as render_text)
    if breakdown:
        story += [section("LIVE TRAFFIC BREAKDOWN (every class, even 0.1%)"), Spacer(1, 1.5 * mm)]
        if abnormal_pct is not None:
            story.append(Paragraph(f"Attacks were {abnormal_pct:.1f}% of recent traffic.", note))
        brows = []
        for r in breakdown:
            raw = str(r.get("label", "?"))
            pct = float(r.get("pct", 0.0))
            tag = "" if raw.lower() in ("benign", "normal") else "attack"
            brows.append([Paragraph(escape(pretty_label(raw)), val), f"{pct:5.1f}%", tag])
        bt = Table(brows, colWidths=[content_w - 46 * mm, 18 * mm, 28 * mm])
        bt.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, border), ("INNERGRID", (0, 0), (-1, -1), 0.3, border),
            ("FONTNAME", (1, 0), (-1, -1), "Helvetica"), ("FONTSIZE", (1, 0), (-1, -1), 8.5),
            ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor(_SEV_COLORS["high"])),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story += [bt, Spacer(1, 4 * mm)]

    # DETECTED ATTACKS
    story += [section("DETECTED ATTACKS"), Spacer(1, 2 * mm)]
    if not ordered:
        story.append(Paragraph("No abnormal traffic was detected in this period.", val))

    for number, event in enumerate(ordered, start=1):
        sev = event.severity.value
        sev_color = colors.HexColor(_SEV_COLORS.get(sev, _PDF_SLATE))
        head = Table([[f"#{number}   {ir._fmt_time(event.timestamp, offset_minutes)}", sev.upper()]],
                     colWidths=[content_w - 30 * mm, 30 * mm])
        head.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), slate), ("BACKGROUND", (1, 0), (1, 0), sev_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("ALIGN", (1, 0), (1, 0), "CENTER"), ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (0, 0), 8), ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ]))
        pairs = [("Attack", possible_attack(event.attack_type, event.confidence, event.attack_guesses))]
        all_attacks = guesses_text(event.attack_guesses)
        if all_attacks and all_attacks != "-":
            pairs.append(("All attacks", all_attacks))
        pairs += [
            ("Severity", sev.upper()),
            ("Source", f"{event.source_ip}:{event.source_port}"),
            ("Destination", f"{event.destination_ip}:{event.destination_port} ({event.protocol.value})"),
            ("Status", f"{event.state.value.replace('_', ' ')} | action: {event.action_taken.value}"),
        ]
        if event.detection_reason:
            pairs.append(("Reason", event.detection_reason))
        names = [f.get("name") for f in (event.contributing_features or [])
                 if isinstance(f, dict) and f.get("name")]
        if names:
            pairs.append(("Unusual features", ", ".join(names)))
        pairs.append(("Event ID", str(event.id)))
        story.append(KeepTogether([head, kv(pairs), Spacer(1, 3.5 * mm)]))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=37 * mm, bottomMargin=16 * mm, title=title)
    doc.build(story, onFirstPage=_decorate, onLaterPages=_decorate)
    return buffer.getvalue()
