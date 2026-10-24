"""Layer 1 - Cleaner.

Removes invisible characters and normalises text. Produces two versions:
  * `clean`   - what gets stored and shown (readable, original letters kept)
  * `scan`    - lower-cased, look-alike letters folded to Latin, used for pattern checks
Anything suspicious that was removed is reported as a finding.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width, bidi-control, word-joiner, BOM, soft hyphen, and similar invisible code points.
INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f"
    "\u202a-\u202e\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]"
)
# Other control characters except tab and newline.
CONTROL_RE = re.compile("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]")
MULTI_SPACE_RE = re.compile(r"[ \t]{2,}")
MULTI_NEWLINE_RE = re.compile(r"\n{3,}")

# Common Cyrillic / Greek look-alikes of Latin letters.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ո": "n", "ν": "v", "ο": "o", "α": "a", "ε": "e",
    "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "А": "A", "В": "B", "Е": "E",
    "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ү": "Y",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS)


@dataclass
class SanitizeResult:
    clean: str
    scan: str
    invisible_removed: int = 0
    controls_removed: int = 0
    homoglyphs_found: int = 0
    findings: list[str] = field(default_factory=list)

    @property
    def obfuscated(self) -> bool:
        return self.invisible_removed > 0 or self.homoglyphs_found > 0


def _has_latin(word: str) -> bool:
    return any("a" <= ch.lower() <= "z" for ch in word)


def sanitize(text: str) -> SanitizeResult:
    if text is None:
        text = ""
    # NFKC folds full-width letters, ligatures and compatibility forms into plain ones.
    normalized = unicodedata.normalize("NFKC", str(text))
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")

    invisible = len(INVISIBLE_RE.findall(normalized))
    normalized = INVISIBLE_RE.sub("", normalized)
    controls = len(CONTROL_RE.findall(normalized))
    normalized = CONTROL_RE.sub("", normalized)

    clean = MULTI_SPACE_RE.sub(" ", normalized)
    clean = MULTI_NEWLINE_RE.sub("\n\n", clean).strip()

    # Count look-alike letters only when mixed into words that also use Latin letters:
    # genuine Russian or Greek text is not penalised.
    homoglyphs = 0
    for word in re.findall(r"\w+", clean):
        if _has_latin(word):
            homoglyphs += sum(1 for ch in word if ch in HOMOGLYPHS)

    scan = clean.translate(HOMOGLYPH_TABLE).lower()
    scan = re.sub(r"\s+", " ", scan)

    findings: list[str] = []
    if invisible:
        findings.append(f"removed {invisible} invisible character(s)")
    if controls:
        findings.append(f"removed {controls} control character(s)")
    if homoglyphs:
        findings.append(f"found {homoglyphs} look-alike letter(s) mixed into Latin words")

    return SanitizeResult(clean, scan, invisible, controls, homoglyphs, findings)
