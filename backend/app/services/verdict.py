"""
SecureNet — how a detection is worded for people

The model's job is to say whether traffic is normal or abnormal. The attack class
from stage 2 is only a *guess* of what the abnormal traffic might be, so the UI,
emails and reports lead with the verdict and show the guesses separately.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

ABNORMAL = "Abnormal traffic detected"
NORMAL = "Normal traffic"
UNKNOWN_GUESS = "Unknown"
BENIGN_NAMES = {"benign", "normal"}


def clean_guesses(guesses) -> List[Dict]:
    """Stored guesses → [{label, probability}] (bad entries dropped, best first)."""
    out = []
    for g in guesses or []:
        if not isinstance(g, dict):
            continue
        label, p = g.get("label"), g.get("probability")
        if isinstance(label, str) and isinstance(p, (int, float)):
            out.append({"label": label, "probability": float(p)})
    return sorted(out, key=lambda g: g["probability"], reverse=True)


def possible_attack(attack_type: Optional[str], confidence: Optional[float], guesses=None) -> str:
    """The model's best guess at which attack it might be, e.g. "DDoS (97%)"."""
    if attack_type:
        return f"{attack_type} ({confidence:.0%})" if confidence is not None else attack_type
    for g in clean_guesses(guesses):
        if g["label"].lower() not in BENIGN_NAMES:
            return f"{g['label']} ({g['probability']:.0%}, unsure)"
    return UNKNOWN_GUESS


def guesses_text(guesses: Iterable[Dict], limit: int = 4) -> str:
    """"DDoS 97%, DoS 2%, Benign 1%" (guesses under 1 % left out)."""
    items = [g for g in clean_guesses(guesses) if g["probability"] >= 0.01][:limit]
    return ", ".join(f"{g['label']} {g['probability']:.0%}" for g in items) or "-"
