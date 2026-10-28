# Security Score

Eigenständig startbares Python-Tool für deterministische Repository-Scores (0–100, A–F) und die Sicherheitsrelevanz von Änderungen. Die Prüfungen benötigen weder Modellaufrufe noch AppSec Analyzer.

## Voraussetzungen und Aufruf

Python 3.10+ unter Linux/macOS; für lokale Git-Vergleiche zusätzlich Git. Es werden keine Python-Pakete installiert. Aus diesem Verzeichnis:

```sh
python3 scripts/score.py /pfad/zum/repository
python3 scripts/score.py /pfad/zum/repository --details
python3 scripts/score.py /pfad/zum/repository --staged --json
python3 scripts/score.py /pfad/zum/repository --base main --head HEAD
python3 scripts/score.py --list-rules --json
python3 scripts/score.py --verify-rules
```

Ein Verzeichnis oder eine unterstützte GitHub-/GitLab-HTTPS-URL liefert einen Repository-Score. Vergleiche und Patches liefern stattdessen eine Relevanzklasse (high, medium, low oder unclear) und Befunde. `--details` zeigt Begründung, Abdeckung und Berechnung; `--json` und `--yaml` liefern strukturierte Ergebnisse. `--help` beschreibt alle Optionen und Eingaben.

Die Regeln liegen in [rules.json](rules.json), die Berechnung und Grenzen in [references/scoring.md](references/scoring.md). Ein hoher Score beweist keine Sicherheit; bei unzureichender Abdeckung wird kein Score ausgegeben.

## Optionaler Analyzer

`--engine analyzer` nutzt einen separat installierten kompatiblen AppSec Analyzer und unterstützt nur Repository-Scores. Sein Ergebnis folgt einer anderen Bewertungsrichtlinie. Voraussetzungen stehen in [references/compatibility.md](references/compatibility.md) und [dependencies.json](dependencies.json).

## Tests

```sh
python3 -B -m unittest test_security_score -v
```

Das Tool ist unabhängig von den anderen Tools dieses Repositories nutzbar. Der zugehörige Assistenten-Skill liegt in `appsec-skills` und ruft diese Installation auf.
