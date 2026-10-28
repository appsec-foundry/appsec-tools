# appsec-analyzer-tools

Zentrales Repository für Zusatztools rund um
[appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer).

Hier werden eigenständig nutzbare Hilfsprogramme gesammelt, die die Arbeit mit
appsec-analyzer ergänzen. Die Kernanwendung wird im Hauptrepository entwickelt.

## Zweck und Umfang

Mögliche Einsatzbereiche sind zum Beispiel:

- Eingabedaten für appsec-analyzer vorbereiten oder konvertieren.
- Analyseergebnisse auswerten, vergleichen oder exportieren.
- Wiederkehrende Integrations- und Entwicklungsaufgaben automatisieren.

Verfügbares Tool:

- [Requirement Harvester](tools/requirement-harvester/README.md): Requirements
  beliebiger Art aus konfigurierten HTTPS-Webquellen crawlen und als
  OSCAL-YAML exportieren. Siehe [Anforderungen](tools/requirement-harvester/requirements.md).
- [Security Score](tools/security-score/README.md): Repositories deterministisch
  bewerten und die Sicherheitsrelevanz von Änderungen prüfen; als Python-CLI
  unabhängig von AppSec Analyzer und Assistenten-Skills nutzbar.

## Aufbau

Neue Tools werden unter `tools/<tool-name>/` abgelegt. Jedes Tool erhält eine
eigene `README.md` mit:

- Zweck und Bezug zu appsec-analyzer.
- Voraussetzungen und Installation.
- Aufruf und einem nachvollziehbaren Beispiel.
- Ein- und Ausgabeformaten sowie benötigter Konfiguration.
- Unterstützten Versionen oder Schnittstellen von appsec-analyzer, soweit relevant.

Abhängigkeiten und Tests liegen beim jeweiligen Tool. Gemeinsame Infrastruktur
wird ergänzt, sobald mehrere Tools sie tatsächlich benötigen.

## Mitarbeit

Neue Tools sollen eine klar abgegrenzte Aufgabe erfüllen und unabhängig
voneinander nutzbar bleiben. Änderungen an der Kernanwendung gehören in das
[appsec-analyzer-Repository](https://github.com/appsec-foundry/appsec-analyzer).

Die Arbeitsregeln für Coding-Agenten stehen in [AGENTS.md](AGENTS.md).
