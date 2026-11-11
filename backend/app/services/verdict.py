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

# DISPLAY-ONLY renaming: the model class stays "Brute Force -XSS" internally (so detection,
# counting and all logic are unchanged); it is only SHOWN to the user as "Cross Site Scripting".
# Add more {internal label (lowercased): shown name} pairs here if other labels need friendly names.
DISPLAY_NAMES = {
    "brute force -xss": "Cross Site Scripting",
    "brute force-xss": "Cross Site Scripting",
}


def pretty_label(label: Optional[str]) -> str:
    """Map an internal model class name to the name shown to the user (display only)."""
    if not label:
        return label or ""
    return DISPLAY_NAMES.get(label.strip().lower(), label)


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
        name = pretty_label(attack_type)
        return f"{name} ({confidence:.0%})" if confidence is not None else name
    for g in clean_guesses(guesses):
        if g["label"].lower() not in BENIGN_NAMES:
            return f"{pretty_label(g['label'])} ({g['probability']:.0%}, unsure)"
    return UNKNOWN_GUESS


def guesses_text(guesses: Iterable[Dict], limit: int = 4) -> str:
    """"DDoS 97%, DoS 2%, Benign 1%" (guesses under 1 % left out)."""
    items = [g for g in clean_guesses(guesses) if g["probability"] >= 0.01][:limit]
    return ", ".join(f"{pretty_label(g['label'])} {g['probability']:.0%}" for g in items) or "-"
