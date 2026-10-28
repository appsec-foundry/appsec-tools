# Security Score

Bewertet ein Repository mit einem deterministischen Score von 0 bis 100 (A bis F) oder ordnet die Sicherheitsrelevanz von Änderungen ein. Python 3.10+ ist erforderlich; für Git-Vergleiche auch Git. Die lokale Bewertung benötigt keine zusätzlichen Python-Pakete.

## Quick Start

Mit installiertem `pipx` vom Repository-Root aus:

```sh
pipx install ./security-score
security-score /pfad/zum/repository
```

## Weitere Aufrufe

```sh
security-score /pfad/zum/repository --details
security-score /pfad/zum/repository --staged --json
security-score /pfad/zum/repository --base main --head HEAD
security-score --list-rules --json
security-score --verify-rules
```

Ein Verzeichnis oder eine unterstützte GitHub- oder GitLab-HTTPS-URL liefert einen Repository-Score. Vergleiche und Patches liefern eine Relevanzklasse. `--json` und `--yaml` liefern strukturierte Ausgaben; `--help` zeigt alle Optionen. Regeln und Berechnung stehen in [references/scoring.md](references/scoring.md).

`--engine analyzer` verwendet einen separat installierten kompatiblen AppSec Analyzer und unterstützt nur Repository-Scores. Voraussetzungen: [Kompatibilität](references/compatibility.md).

Tests aus diesem Verzeichnis: `python3 -B -m unittest test_security_score -v`.
