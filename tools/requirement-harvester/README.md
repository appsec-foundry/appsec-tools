# Requirement Harvester

Eigenständiges Python-Kommandozeilen-Tool: Requirements beliebiger Art aus
konfigurierten HTTPS-Webseiten extrahieren und als OSCAL-1.2.3-Kataloge speichern.
Gedacht für interne Unternehmensvorgaben, beispielsweise als Input für
Code-Reviews gegen Unternehmens-Policies.

Der Scan ist deterministisch und benötigt kein LLM. Configs können manuell oder
mit einem externen, für die jeweiligen Inhalte freigegebenen Assistenten erstellt
werden. Das Tool prüft sie und zeigt im Probelauf die extrahierten Ergebnisse.

## Installation und erster Lauf

Voraussetzungen: Python 3.10 oder neuer auf Linux/macOS, `venv` und `pip`.
Windows wird in dieser Version wegen der verwendeten harten Laufzeitbegrenzung
nicht unterstützt. Alle folgenden Befehle werden in diesem Tool-Verzeichnis ausgeführt.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m harvester validate --config examples/tss-web.yaml
.venv/bin/python -m harvester run --config examples/tss-web.yaml --dry-run
.venv/bin/python -m harvester run --config examples/tss-web.yaml
```

Die mitgelieferte [TSS-WEB-Config](examples/tss-web.yaml) liest öffentliche
Requirement-Seiten unter `https://tss-web.secodis.com/Controls/`.
Die Ausgabe liegt unter `out/tss-web.oscal.yaml`, der Laufbericht unter
`out/tss-web-report.json`. Die Beispielregeln sind an die aktuelle Seitenstruktur
gebunden und müssen bei Layoutänderungen geprüft werden.

`validate` arbeitet ohne Netzwerkzugriff und ohne Lesen von Credential-Werten.
`--dry-run` ruft Seiten ab und validiert den Export, ersetzt aber keine Kataloge.
Sein Bericht enthält zusätzlich `preview` mit den extrahierten Aussagen und
Quellstellen; dieser Bericht ist genauso vertraulich wie die Anforderungen.

Jeder erfolgreiche Lauf erzeugt alle konfigurierten Kataloge vollständig neu.
Manuelle Ergänzungen in Ausgabedateien werden überschrieben. Bei Abruf-,
Extraktions- oder Validierungsfehlern bleiben vorhandene Kataloge unverändert.
Die Veröffentlichung ist pro Datei atomar; ein Dateisystemfehler zwischen
mehreren Ausgaben wird im Bericht mit dem tatsächlichen Stand je Datei ausgewiesen.

## Config erstellen

Das vollständige [JSON-Schema](harvester/schemas/config.schema.json) ist die
maßgebliche Config-Schnittstelle. Ein zweites Beispiel ist [table.yaml](examples/table.yaml).

```bash
.venv/bin/python -m harvester schema > /tmp/harvester-config.schema.json
```

Die Config enthält `config-version: 1`, `output`, optionale `defaults` und
`sources`. Unbekannte Felder, doppelte YAML-Schlüssel, YAML-Aliase und ausführbare
Tags sind nicht zulässig. Pfade werden relativ zur Config-Datei aufgelöst.

Pro Quelle werden angegeben:

- `id`, `title` und eine oder mehrere `start-urls`;
- `crawl.allowed-origins`, etwa `https://wiki.example.org` ohne abschließenden Slash;
- optional `allowed-path-prefixes`, `exclude-path-prefixes`, `allowed-query-keys`;
- `auth`, optional `ca-bundle`, sowie `extraction`.

Der Pfadbereich `/` erlaubt den gesamten Host; `/policies/` erlaubt diesen
Bereich einschließlich seiner Unterpfade, aber nicht `/policies-old/`.
Subdomains sind eigenständige Origins. Startseiten müssen im Scope liegen.
Query-Parameter werden nur mit ausdrücklich erlaubten Schlüsseln verfolgt.
Parameter für Zugangsdaten sind ausgeschlossen. Diagnostics enthalten keine Query-Werte.

`crawl.max-depth: 0` liest ausschließlich Startseiten, `1` zusätzlich direkte
Links usw. `null` entfernt die Tiefengrenze; andere Ressourcenlimits gelten
weiterhin. `crawl.mode: explicit-pages` beschränkt einen Lauf auf Startseiten.
Mehrere Startseiten werden gemeinsam in Breitensuche verarbeitet; bei mehreren
Linkwegen gilt die kürzeste Entfernung. Unverlinkte Seiten werden nicht entdeckt.

Wichtige Defaults: 200 Seiten, Linktiefe 3, 400 Requests pro Quelle,
5 MiB pro Antwort vor und nach Dekompression, 1 Sekunde Request-Abstand,
5 Sekunden Verbindungs- und 30 Sekunden Lese-Timeout. Der gesamte Lauf ist auf
900 Sekunden begrenzt. `defaults` verändert diese Werte; `crawl` kann die
quellbezogenen Werte überschreiben. Weitere Grenzen stehen im Schema.
Budgetüberschreitungen melden einen unvollständigen Lauf; das reguläre Ende
am konfigurierten Scope oder an der Linktiefe ist kein Fehler.

Interne Netze werden je Quelle explizit konfiguriert:

```yaml
crawl:
  allowed-origins: [https://wiki.internal.example]
  allowed-path-prefixes: [/requirements/]
  allowed-private-networks: [10.20.30.0/24]
ca-bundle: ./company-ca.pem
```

Nur RFC1918-Netze und IPv6-ULA können zusätzlich freigegeben werden.
Loopback, Link-local, Metadatenziele und IPv6-Übergangsadressen bleiben gesperrt.
Zieladressen werden unmittelbar vor der Verbindung aufgelöst, geprüft und als
numerische Adressen verbunden; TLS prüft weiterhin den ursprünglichen Hostnamen.
Weiterleitungen werden erneut geprüft. Umgebungsvariablen für HTTP-Proxies
werden nicht verwendet; der Runner benötigt direkte Erreichbarkeit der Quellen.

## Extraktionsregeln

`content-selector` muss genau einen Hauptinhalt auswählen. Ein optionaler
`context-selector` übernimmt gemeinsamen Kontext aus diesem Bereich;
`exclude-selectors` entfernt beispielsweise Navigation oder bekannte Randnotizen.

Jede Regel hat eine eindeutige `id`, einen `item-selector`, `fields` und eine Strategie:

| Strategie | Bedeutung |
| --- | --- |
| `blocks` | Ein Requirement pro ausgewähltem Inhaltsblock, etwa einem Listeneintrag. |
| `table-rows` | Ein Requirement pro `tr`; bei Übernahme der gesamten Zeile werden Tabellenüberschriften als Feldbezeichnungen erhalten. |
| `sections` | Eine Überschrift plus folgende Geschwisterelemente bis zur nächsten gleich- oder höherstufigen Überschrift. |

`page-selector` aktiviert eine Regel nur für passende Seiten. Eine aktive Regel
muss Treffer liefern, außer `required: false` ist gesetzt. Ohne Requirements
scheitert eine Seite standardmäßig; für bekannte reine Indexseiten kann
`extraction.allow-empty-pages: true` gesetzt werden. Hauptinhalt und Regeln
werden trotzdem geprüft. Eine vollständig leere Quelle bleibt ein Fehler.

Felder: `original-id`, `title`, `statement`, `obligation`, `context`,
`applicability`, `exceptions`, `category`, `revision`, `guidance`, `example`.
Nur `statement` ist Pflicht; es muss nach der Extraktion nichtleer sein.

```yaml
fields:
  original-id: {attribute: id}
  title: {selector: h2}
  statement: {selector: .requirement-text}
  applicability:
    scope: page
    selector: .applicability
    many: true
```

Ein Feldselektor ist relativ zum Eintrag, mit `scope: page` relativ zur gesamten
Seite. Ohne Selektor wird der ganze Eintrag übernommen. `attribute` liest eines
der im Schema erlaubten Attribute, `many: true` verbindet mehrere Treffer;
sonst sind mehrere Treffer ein Fehler. Alternativ setzt `value` einen expliziten
konstanten Wert. Fehlende optionale Felder bleiben leer. Das Tool leitet keine
Verbindlichkeit aus Schlüsselwörtern ab und ergänzt weder MUST noch SHOULD.

Absätze, verschachtelte Listen, Tabellen und Code werden als Markdown erhalten.
Bedingungen und Ausnahmen gehören in die Aussage oder in die entsprechenden
Kontextfelder. Regeln können ihre fachliche Vollständigkeit nicht selbst beweisen:
Probeläufe sind gegen repräsentative Seiten und erwartete Ergebnisse zu prüfen.

Identität: Original-ID innerhalb der Quelle, sonst Seiten-URL plus Anker direkt
am Eintrag, sonst Seiten-URL plus Inhalt. IDs sind SHA-256-basiert und nach Quelle
getrennt. Ohne Original-ID oder stabilen Anker führt eine Inhaltsänderung zu einer
neuen ID. Einfügen weiterer Einträge verschiebt die bestehenden IDs nicht.
Widersprüchliche Aussagen mit derselben Quellidentität brechen den Lauf ab.

## Authentifizierung

Credentials werden ausschließlich über externe Referenzen geladen. Keine echten
Zugangsdaten in Configs, Prozessargumenten oder Git ablegen. Authentifizierte Quellen
haben genau eine Origin; Zugangsdaten werden nicht an andere Origins weitergegeben.

API-Token:

```yaml
auth:
  mode: token
  token-env: HARVEST_TOKEN
  header: Authorization
  prefix: Bearer
```

Für beispielsweise `X-Api-Key` ist `prefix: ""` möglich.

Benutzername/Passwort über HTTP Basic mit geprüftem HTTPS:

```yaml
auth:
  mode: basic
  username-env: HARVEST_USERNAME
  password-env: HARVEST_PASSWORD
```

Formularlogins sind kein generisches HTTP-Basic-Verfahren und benötigen bei
Bedarf einen Adapter für die konkrete Zielanwendung.

Entra ID für unbeaufsichtigte Läufe:

```yaml
auth:
  mode: entra
  flow: client-credentials
  tenant-id: 00000000-0000-4000-8000-000000000001
  client-id: 00000000-0000-4000-8000-000000000002
  client-secret-env: ENTRA_CLIENT_SECRET
  scopes: [api://YOUR-RESOURCE/.default]
```

Tenant, Client und Scope sind durch die realen, administrativ eingerichteten
Werte zu ersetzen. Die Zielanwendung muss dieses Token für ihren Inhalt akzeptieren
und entsprechende Leserechte für die Anwendung bereitstellen.

Für interaktive Anmeldung mit Microsoft Entra ID:

```yaml
auth:
  mode: entra
  flow: interactive
  tenant-id: 00000000-0000-4000-8000-000000000001
  client-id: 00000000-0000-4000-8000-000000000002
  scopes: [api://YOUR-RESOURCE/Requirements.Read]
  token-file: ../.sessions/company.json
```

```bash
.venv/bin/python -m harvester login --config company.yaml --source company
.venv/bin/python -m harvester run --config company.yaml
```

Die interaktive Anmeldung verwendet MSALs Authorization-Code-Flow mit PKCE und
lokalem Callback. Die App-Registrierung benötigt den dazugehörigen Desktop-/Public-Client-
Zugriffsweg mit `http://localhost` als Redirect-URI. Siehe
[Microsofts MSAL-Dokumentation](https://learn.microsoft.com/en-us/entra/msal/python/getting-started/acquiring-tokens).

Nur das Access-Token wird mit Ablaufzeit und Bindung an Quelle, Tenant, Client,
Origin und Scopes in einer Datei mit Modus 0600 gespeichert; kein Refresh-Token.
Bei Ablauf ist eine neue Anmeldung erforderlich. `run` öffnet niemals einen
Browser und wartet auch ohne `--non-interactive` nie auf Eingaben.

Entra-Unterstützung bedeutet hier Bearer-Token-Zugriff auf die Zielanwendung.
Eine Webseite, die ausschließlich ihre eigenen Browser-Session-Cookies akzeptiert,
ist damit nicht automatisch erschlossen. Dafür muss der konkrete Zugriffsweg
zunächst geklärt werden. Ein echter Unternehmensmandant war für den lokalen
Implementierungstest nicht verfügbar; SDK-Anbindung, Fehlerfälle und Speicherung
sind mit synthetischen Antworten getestet.

## Ausgaben und OSCAL

Standard: `output.catalog`, `title`, `version`, `report`. Mehrere Dateien:

```yaml
output:
  report: ../out/report.json
  catalogs:
    - id: all
      path: ../out/all.oscal.yaml
      title: Alle Anforderungen
      version: "1.0.0"
      source-ids: [engineering, operations]
    - id: operations
      path: ../out/operations.oscal.yaml
      title: Operations
      version: "1.0.0"
      source-ids: [operations]
```

Eine Quelle wird nur einmal gecrawlt, auch wenn sie mehreren Ausgaben zugeordnet
ist. Jede Quelle muss mindestens einer Ausgabe angehören. Das Beispiel benötigt
entsprechende Quell-IDs in `sources`.

Jede Quelle wird eine OSCAL-Gruppe, jedes Requirement ein Control mit
`statement`. Original-ID, Provenienz und optionale Metadaten werden über Properties
im projektspezifischen Namespace gespeichert. Mehrzeiliger Kontext, Geltungsbereich
und Ausnahmen sind eigene Parts; `guidance` und `example` verwenden OSCAL-Part-Namen.
Quell-URLs und Referenzen bleiben als Links erhalten. Verlinkte Ressourcen werden
nur über die normalen Crawl-Regeln abgerufen, nicht zur Exportvalidierung.

Das [offizielle NIST-Schema](harvester/schemas/README.md) ist lokal eingebunden.
Jeder neue Export erhält eine neue Dokument-UUID und Änderungszeit; Control-IDs und
fachlicher Inhalt bleiben bei gleichen Eingaben stabil. Ein Vergleich der gesamten
Datei einschließlich Laufzeitmetadaten ist daher nicht bytegleich.

| Exit-Code | Bedeutung |
| --- | --- |
| 0 | Erfolgreich; bei Probelauf validiert, aber kein Katalog geschrieben. |
| 2 | Config oder Aufruf ungültig. |
| 3 | Authentifizierung fehlgeschlagen, fehlt oder ist abgelaufen. |
| 4 | Abruf, Scope, Budget oder Extraktion fehlgeschlagen. |
| 5 | Exportvalidierung, Veröffentlichung oder CI-Artefaktbereitstellung fehlgeschlagen. |
| 130 | Durch Benutzer abgebrochen. |

## CI und Entwicklung

Vorlagen für [GitLab CI/CD](ci/gitlab-ci.yml) und [GitHub Actions](ci/github-actions.yml)
mit Einrichtungshinweisen stehen in [ci/README.md](ci/README.md). Sie werden nicht
automatisch aktiviert. Es gibt keinen Schreibzugriff auf Repositories.

```bash
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m pytest
python3 scripts/check_dependencies.py
```

Die Tests verwenden synthetische Quellen, kontrollierte Transportschnittstellen
und Netzwerkfehler. Der Dependency-Check fragt veröffentlichte PyPI-Advisories ab;
Netzwerkfehler lassen ihn fehlschlagen. Die bei der Erstellung geprüften
Paketversionen und Ursprünge stehen in `dependency-provenance.json`.

HTML wird statisch gelesen. JavaScript-Rendering, Anhänge, PDFs, beliebige
Loginformulare und automatische Änderungen der Regeln sind nicht implementiert.
Die [requirements.md](requirements.md) dokumentiert Anforderungen, Entscheidungen
und den Stand ihrer Umsetzung.
