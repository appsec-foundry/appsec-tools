# Arbeitsregeln für Coding-Agenten

## Repository-Zweck

Dieses Repository ist die zentrale Sammlung ergänzender Tools für
[appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer).
Entwickle hier Hilfsprogramme und Integrationen; Änderungen an der Kernanwendung
gehören in das Hauptrepository.

## Ausgangslage

Das erste Tool ist der eigenständige Python-Requirement-Harvester unter
`requirement-harvester/`. Er verwendet Python >=3.10, lokale Lockfiles und
pytest. Tests werden im Tool-Verzeichnis mit `.venv/bin/python -m pytest`
ausgeführt. Die README beschreibt Installation, CLI und CI-Vorlagen.
Leite Funktionen oder Schnittstellen des Hauptprojekts nicht aus dem
Repository-Namen ab; prüfe sie vor einer davon abhängigen Implementierung.

## Struktur und Umsetzung

- Lege jedes neue Tool in einem eigenen Verzeichnis im Repository-Root ab.
- Halte Tools eigenständig nutzbar und ihre Abhängigkeiten lokal beim Tool.
- Wähle Sprache und Laufzeit passend zur Aufgabe und zu bestehenden Mustern.
- Führe gemeinsame Bibliotheken oder Frameworks erst bei konkretem Bedarf ein.
- Beschränke Änderungen auf die angeforderte Aufgabe.

## Dokumentation

- Pflege die Repository-Dokumentation auf Deutsch, sofern nichts anderes verlangt wird.
- Dokumentiere jedes Tool mit einer eigenen `README.md`: Zweck, Voraussetzungen,
  Installation, Konfiguration, Aufrufbeispiel und Ein-/Ausgaben.
- Benenne relevante Kompatibilitätsanforderungen an appsec-analyzer ausdrücklich.
- Ergänze in der zentralen README einen verlinkten Eintrag, sobald ein Tool existiert.
- Kennzeichne geplante Funktionen als geplant; dokumentiere keine ungeprüften
  Befehle oder Schnittstellen als funktionsfähig.

## Prüfung und Übergabe

- Ergänze bei funktionalen Änderungen geeignete Tests und nutze vorhandene
  Prüfwerkzeuge des betroffenen Tools.
- Verwende für Beispiele und Tests synthetische oder bereinigte Daten; lege keine
  Zugangsdaten oder vertraulichen Analyseergebnisse im Repository ab.
- Prüfe vor der Übergabe den Diff und halte die Dokumentation zur tatsächlichen
  Implementierung konsistent.
- Nenne bei der Übergabe die Änderungen, ausgeführte Prüfungen und verbleibende
  Einschränkungen. Behaupte keine erfolgreiche Prüfung, die nicht ausgeführt wurde.
