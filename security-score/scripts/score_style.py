"""Terminal styling: colour, width and glyphs, decided once per output stream."""

import os
import re
import shutil

# Repository-controlled text (paths, titles) must never reach a terminal as control
# sequences: escapes could rewrite what the user reads.
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "cyan": "36",
    "bold-red": "1;31",
}
SEVERITY_COLOURS = {
    "critical": "bold-red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}
BAR_WIDTH = 10


def safe(value):
    return CONTROL.sub("?", str(value))


class Style:
    """Plain, deterministic output unless built from a capable terminal."""

    def __init__(self, color=False, unicode=True, width=100):
        self.color = color
        self.unicode = unicode
        self.width = width

    @classmethod
    def detect(cls, stream):
        environment = os.environ
        terminal = stream.isatty() and environment.get("TERM") != "dumb"
        try:
            # In-memory streams have no encoding and accept any text.
            "█░→·".encode(getattr(stream, "encoding", None) or "utf-8")
            unicode = True
        except (UnicodeEncodeError, LookupError):
            unicode = False
        width = shutil.get_terminal_size((100, 24)).columns if terminal else 100
        return cls(
            color=terminal and not environment.get("NO_COLOR"),
            unicode=unicode,
            width=max(60, min(width, 120)),
        )

    def paint(self, text, *names):
        if not self.color or not names:
            return text
        codes = ";".join(CODES[name] for name in names)
        return f"\033[{codes}m{text}\033[0m"

    def severity(self, level, text=None):
        text = level.upper() if text is None else text
        return self.paint(text, SEVERITY_COLOURS.get(level, "bold"))

    def tag(self, level, width=8):
        """Severity or relevance level as a padded, coloured label column."""
        return self.severity(level, f"{level.upper():<{width}}")

    def band(self, score):
        """Colour follows the documented grade bands: A/B green, C/D yellow, below red."""
        if score is None:
            return "dim"
        return "green" if score >= 80 else "yellow" if score >= 60 else "red"

    def bar(self, score):
        filled = 0 if score is None else round(score / 100 * BAR_WIDTH)
        full, empty = ("█", "░") if self.unicode else ("#", "-")
        text = self.paint(full * filled, self.band(score)) if filled else ""
        if filled < BAR_WIDTH:
            text += self.paint(empty * (BAR_WIDTH - filled), "dim")
        return text if self.unicode else f"[{text}]"

    @property
    def dot(self):
        return "·" if self.unicode else "-"

    @property
    def arrow(self):
        return "→" if self.unicode else "->"
