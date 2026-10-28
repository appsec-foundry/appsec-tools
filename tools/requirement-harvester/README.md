# Requirement Harvester

Liest Requirements aus Webseiten und Wikis und speichert sie als **OSCAL-YAML**.
Zum Beispiel, um Code-Reviews gegen interne Unternehmensvorgaben zu prüfen.

```text
Webseiten → Extraktionsregeln aus der Config → OSCAL-Katalog
```

Mehrere Startseiten, Crawl-Tiefe und erlaubte Hosts/Pfade stehen in der Config.
Der Scan läuft ohne LLM. Ein externer Assistent kann beim Erstellen der Regeln helfen.

## Quick Start

**Voraussetzung:** Python ≥3.10 auf Linux oder macOS, mit `venv` und `pip`.
Vom Repository-Root aus:

```bash
cd tools/requirement-harvester
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock

# Öffentliche TSS-WEB-Seiten einlesen und den OSCAL-Katalog schreiben
.venv/bin/python -m harvester run --config examples/tss-web.yaml
```

Ergebnis:

```text
out/
├── tss-web.oscal.yaml    # Requirements mit Quellverweisen
└── tss-web-report.json   # Eingelesene Seiten, Anzahl und Fehler
```

Der geprüfte Beispieldurchlauf hat **121 Requirements aus 21 Seiten** erzeugt.
Das Ergebnis hängt vom aktuellen Inhalt der Quelle ab.

## Eigene Quelle einlesen

Eine passende Beispielconfig kopieren, URLs und HTML-Selektoren anpassen:

```bash
cp examples/lists.yaml examples/company.yaml

# Config prüfen, ohne Seiten abzurufen
.venv/bin/python -m harvester validate --config examples/company.yaml

# Seiten lesen und Ergebnisse im Laufbericht unter „preview“ ansehen
.venv/bin/python -m harvester run --config examples/company.yaml --dry-run

# OSCAL-Datei schreiben
.venv/bin/python -m harvester run --config examples/company.yaml
```

Dateipfade in der Config gelten **relativ zur Config-Datei**.
Jeder erfolgreiche Lauf ersetzt die Ausgabedateien vollständig.
Manuelle Ergänzungen werden überschrieben. Bei Abruf- oder Extraktionsfehlern
bleiben die bisherigen Dateien erhalten. Der Probelauf schreibt nur den Bericht.

## Config-Beispiele

| Beispiel | Was es zeigt |
| --- | --- |
| [tss-web.yaml](examples/tss-web.yaml) | Direkt nutzbarer Crawl der öffentlichen TSS-WEB-Seiten. |
| [lists.yaml](examples/lists.yaml) | Requirements aus Listen; zwei Startseiten, Pfad-Scope, Ausschluss und maximale Tiefe. |
| [table.yaml](examples/table.yaml) | Tabellen mit ID, Titel, Aussage und Verbindlichkeit. |
| [sections.yaml](examples/sections.yaml) | Ein Requirement pro `h2`-Abschnitt. |
| [multiple-outputs.yaml](examples/multiple-outputs.yaml) | Zwei Quellen, ein gemeinsamer und ein zusätzlicher separater Katalog. |
| [token.yaml](examples/token.yaml) | Geschützte Seiten mit API-Token aus `HARVEST_TOKEN`. |
| [entra-ci.yaml](examples/entra-ci.yaml) | Entra-ID-Zugriff aus CI über Client Credentials. |

Außer TSS-WEB verwenden die Beispiele Platzhalter für deine Quelle.
Sie enthalten vollständige Configs und keine echten Zugangsdaten.

### Beispiel: Liste auf einer Webseite

```html
<main>
  <ul class="requirements">
    <li id="REQ-001">Anträge müssen innerhalb von zwei Werktagen bearbeitet werden.</li>
    <li id="REQ-002">Änderungen müssen protokolliert werden.</li>
  </ul>
</main>
```

Diese Regel aus [lists.yaml](examples/lists.yaml) liest jeden Eintrag einzeln:

```yaml
extraction:
  content-selector: main
  rules:
    - id: list-items
      strategy: blocks
      item-selector: ul.requirements > li
      fields:
        original-id: {attribute: id}
        statement: {}
```

Im OSCAL-Katalog wird jeder Eintrag ein Control. Aussage, Original-ID und
Quellverweis bleiben erhalten. Vorhandene Bedingungen und Ausnahmen müssen
von den Regeln ebenfalls erfasst werden; der Probelauf hilft beim Prüfen.

### Beispiel: Crawl begrenzen

```yaml
start-urls:
  - https://wiki.example.org/requirements/engineering
  - https://wiki.example.org/requirements/operations
crawl:
  allowed-origins: [https://wiki.example.org]
  allowed-path-prefixes: [/requirements/]
  exclude-path-prefixes: [/requirements/archive/]
  max-depth: 2
```

Startseiten zählen als Tiefe `0`. Mit `2` werden Links bis zwei Schritte entfernt
verfolgt. Als Pfad `/` erlaubst du den ganzen Host. Ausschlüsse haben Vorrang.

## GitLab CI

Diese Datei als `.gitlab-ci.yml` im Repository-Root verwenden:

```yaml
include:
  - local: /tools/requirement-harvester/ci/gitlab-ci.yml

harvest-requirements:
  script:
    - .venv/bin/python scripts/ci_run.py examples/tss-web.yaml
```

Die Vorlage prüft das Tool und führt den Crawl bei manuellen oder zeitgesteuerten
Pipelines auf dem geschützten Default-Branch eines privaten Projekts aus.
Sie benötigt einen non-root Shell-Runner mit Python ≥3.10 und Tag `python-nonroot`.
Kataloge und Bericht werden als Artefakte für sieben Tage bereitgestellt.

Für eigene Quellen den Config-Pfad im Aufruf austauschen. Zugangsdaten als
maskierte, geschützte CI-Variablen mit Environment-Scope `requirement-harvest`
hinterlegen. Für Entra ID heißt die Variable im Beispiel `ENTRA_CLIENT_SECRET`.

[GitLab-Beispieldatei](examples/gitlab-ci.yml) · [Vollständige Pipeline](ci/gitlab-ci.yml) ·
[CI-Einrichtung und GitHub Actions](ci/README.md)

## Weitere Details

- [Config, Authentifizierung, interne Netze und Exit-Codes](docs/reference.md)
- [Config-Schema](harvester/schemas/config.schema.json)
- [Anforderungen und Umsetzungsstand](requirements.md)

Unterstützt statisches HTML, API-Token, HTTP Basic und Entra-Bearer-Token.
JavaScript-Rendering, PDFs und anwendungsspezifische Formular-/Cookie-Logins
benötigen zusätzliche Unterstützung. Die Regeln müssen zur jeweiligen Seite passen.
