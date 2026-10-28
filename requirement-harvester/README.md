# Requirement Harvester

Liest Anforderungen aus konfigurierten Webseiten und Wikis und schreibt einen OSCAL-YAML-Katalog. Python 3.10+ auf Linux oder macOS ist erforderlich.

## Quick Start

Mit installiertem `pipx` vom Repository-Root aus:

```sh
pipx install ./requirement-harvester
requirement-harvester validate --config requirement-harvester/examples/tss-web.yaml
requirement-harvester run --config requirement-harvester/examples/tss-web.yaml
```

Der Lauf liest öffentliche TSS-WEB-Seiten. Katalog und Bericht werden in `requirement-harvester/out/` geschrieben; die Anzahl der Anforderungen hängt vom aktuellen Seiteninhalt ab.

## Eigene Quelle

Eine [Beispielconfig](examples/lists.yaml) kopieren und URLs sowie Selektoren anpassen. Pfade in der Config gelten relativ zur Config-Datei.

```sh
requirement-harvester validate --config meine-config.yaml
requirement-harvester run --config meine-config.yaml --dry-run
requirement-harvester run --config meine-config.yaml
```

`validate` ruft keine Seiten ab. `--dry-run` schreibt einen Bericht mit Vorschau, aber keinen Katalog. Ein erfolgreicher Lauf ersetzt die Ausgabedateien.

## CI und Referenz

Die [GitLab- und GitHub-Vorlagen](ci/README.md) verwenden eine lokale virtuelle Umgebung und die gesperrten Abhängigkeiten. Zugangsdaten gehören in geschützte CI-Variablen.

- [Konfiguration, Authentifizierung und Exit-Codes](docs/reference.md)
- [Config-Schema](harvester/schemas/config.schema.json)
- [Anforderungen](requirements.md)

Unterstützt statisches HTML, API-Token, HTTP Basic und Entra-Bearer-Token. JavaScript-Rendering, PDFs und Formular-Logins werden nicht unterstützt.
