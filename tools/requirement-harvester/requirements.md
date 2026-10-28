# Requirement Harvester – Anforderungen und Umsetzungsplan

Stand: 2026-10-28. Status: Version 0.1.0 implementiert; Betriebsanbindung an
geschützte Unternehmensquellen und gehostete CI-Instanzen noch vor Ort zu prüfen.

## Umsetzungsstand

- Python-CLI mit Config-Schema, Offline-Prüfung, Probelauf und vollständigem
  Neuerzeugen eines oder mehrerer OSCAL-1.2.3-Kataloge ist vorhanden.
- Crawl-Scope, Tiefe, mehrere Startseiten, Ressourcenbudgets, drei deklarative
  Extraktionsstrategien, Provenienz und kontrollierte Fehlerbehandlung sind implementiert.
- Die mitgelieferte TSS-WEB-Config wurde live mit 21 Seiten geprüft und erzeugte
  121 schema-valide Requirements. Die Config enthält Regeln für die beobachteten
  Listen-, Abschnitts- und Tabellenlayouts; eine vollständige semantische Bewertung
  sämtlicher Quelltexte ist dadurch nicht ersetzt.
- Authentifizierung ist als Header-Token, HTTP Basic und Entra-Bearer-Token
  umgesetzt. Entra verwendet MSAL für interaktive Anmeldung oder Client Credentials.
  Anwendungsspezifische Formularlogins und Webseiten mit ausschließlich eigenen
  Browser-Session-Cookies benötigen einen gesonderten Adapter.
- GitLab- und GitHub-Vorlagen sowie deren gemeinsamer nichtinteraktiver Einstieg
  sind vorhanden. Gehostete Pipeline-Läufe und ein realer Entra-Mandant waren
  nicht verfügbar; die entsprechenden Schnittstellen und Fehlerpfade sind lokal
  mit synthetischen Quellen beziehungsweise Antworten getestet.
- Installation, konkrete Config-Felder und betriebliche Voraussetzungen stehen
  in der [README](README.md); das [Config-Schema](harvester/schemas/config.schema.json)
  ist die maßgebliche Schnittstelle.

## Ziel und bestätigter Umfang

Das Tool soll Requirements beliebiger Art von HTTPS-Webseiten und
Wiki-Seiten sammeln und in OSCAL-YAML ablegen. Die Inhalte können je Quelle
unterschiedlich beschrieben und strukturiert sein. Eine Konfigurationsdatei
steuert Quellen, Crawl-Verhalten und Erkennung der Inhalte.

Hauptzweck ist die Aufbereitung interner Unternehmensvorgaben als Input für
maschinelle Automatisierungen, beispielsweise Code-Reviews gegen die Security
Policies des Unternehmens. Verbindlichkeit, Geltungsbereich, Bedingungen,
Ausnahmen und Herkunft müssen dabei erhalten bleiben. Die öffentliche erste
Quelle dient als Ausgangspunkt; der Einsatzzweck umfasst interne Webseiten.
Security Policies sind ein Anwendungsbeispiel, keine fachliche Einschränkung.
Auch funktionale, organisatorische, technische und andere Anforderungen können
verarbeitet werden. Das Tool setzt keine feste fachliche Taxonomie voraus.

Bestätigte Entscheidungen:

- Umsetzung als Python-Kommandozeilen-Tool, das mit einer Config-Datei gestartet wird.
- Eigenständige Neuentwicklung in diesem Repository; keine Übernahme von Code,
  Extraktionsregeln oder Tests des bisherigen Harvesters aus appsec-analyzer.
- Unbeaufsichtigte Ausführung in GitLab CI/CD und GitHub Actions wird unterstützt;
  GitLab wird zuerst umgesetzt.
- Erste Quelle: `https://tss-web.secodis.com`, laut Nutzer öffentlich zugänglich.
  Eine geprüfte Beispielconfig für den Bereich `/Controls/` liegt vor.
- Geschützte interne Seiten werden bereits im ersten Funktionsumfang unterstützt.
  API-Token, Benutzername/Passwort und Firmen-SSO werden als je Quelle
  konfigurierbare Zugriffsarten eingeplant.
- Microsoft Entra ID ist die zuerst zu unterstützende Firmen-SSO-Lösung.
- Mehrere Startseiten, rekursives Folgen von Links sowie ein konfigurierbarer
  Scope auf Host- oder Pfadebene und eine maximale Crawl-Tiefe werden unterstützt.
- Erwartete Größenordnung: einige Dutzend Seiten pro Lauf. Crawl-Limits bleiben
  konfigurierbar; eine verteilte Crawl-Infrastruktur ist dafür nicht vorgesehen.
- Standardmäßig landen alle Requirements in einer gemeinsamen OSCAL-Datei.
  Mehrere Ausgabedateien und deren Zuordnung werden optional konfiguriert.
- OSCAL-YAML ist das einzige fachliche Ausgabeformat. Ein zusätzlicher Export
  in das bisherige appsec-analyzer-Katalogformat ist nicht Teil des Umfangs.
- Jeder Lauf erzeugt die vorgesehenen Kataloge vollständig neu aus den aktuellen
  Quellen und der Config. Bestehende Kataloginhalte und manuelle Ergänzungen
  werden nicht zusammengeführt oder übernommen.
- Der Scan läuft vollständig deterministisch anhand einer gespeicherten Config,
  ohne LLM, API-Key oder laufenden Modelldienst.
- Die Config wird manuell oder mit einem externen Assistenten erstellt und
  überarbeitet. Die erste Version enthält keine eigene LLM-Anbindung.
  Schema, Beispiele, Config-Prüfung und Probelauf unterstützen beide Arbeitsweisen.

Das Tool gehört als eigenständig nutzbares Zusatztool in dieses Repository.
Es soll für appsec-analyzer und weitere Automatisierungen nutzbare Kataloge vorbereiten. Es bewertet weder
Anwendungen auf Compliance noch verändert es die Quellseiten.

Die folgenden Muss-Anforderungen dokumentieren das vereinbarte Zielverhalten.
Konkrete Einschränkungen und noch erforderliche Betriebsprüfungen sind im
Umsetzungsstand und in der README ausgewiesen.

## Fachliches Modell

Ein Requirement ist eine aus der Quelle übernommene Anforderung mit ihrem
ursprünglichen Aussagegehalt, ihrer Verbindlichkeit und ihrem Geltungsbereich.
Die Bezeichnung auf der Webseite ist nicht entscheidend für die Erfassung.
Optionale Kategorien und Gruppierungen stammen aus der Quelle oder einer
expliziten Config-Zuordnung; sie sind keine Voraussetzung für die Extraktion.
Das Tool bewahrt vorhandene Semantik, ohne Anforderungen in vorgegebene
fachliche Klassen einordnen zu müssen.

## Ablauf

### Optionale Vorbereitung der Config

1. Betreiber wählt repräsentative Beispielseiten und den zulässigen Quellbereich.
2. Optional schlägt ein externer Assistent deklarative Extraktionsregeln aus
   diesen Beispielen vor. Der Harvester ruft selbst kein Modell auf.
3. Der Vorschlag durchläuft die gleiche Schema- und Werteprüfung wie manuelle
   Konfiguration. Der Betreiber prüft vor Übernahme insbesondere, ob die
   vorgeschlagenen Startseiten und Scope-Angaben seinem beabsichtigten Bereich entsprechen.
4. Ein deterministischer Probelauf zeigt die erkannten Einträge mit Quellstellen
   und macht fehlende oder widersprüchliche Zuordnungen sichtbar.
5. Die geprüfte Config wird gespeichert und versioniert. Erwartete Ergebnisse
   für repräsentative Seiten dienen als Regressionstest für spätere Regeländerungen.

Das LLM erzeugt Konfigurationsdaten, keinen auszuführenden Programmcode.
Seiteninhalte und Modellantworten sind untrusted Daten; darin enthaltene
Anweisungen beeinflussen weder Berechtigungen noch Abrufziele des Harvesters.
Die Wahl eines für interne Inhalte freigegebenen Assistenten und die Freigabe
der Beispieldaten erfolgen außerhalb des Tools. Die Harvester-Config enthält
keine Modellanbieter-Einstellungen oder LLM-Zugangsdaten.

### Regulärer Scan

1. Konfiguration laden und vollständig validieren.
2. Freigegebene Startseiten abrufen und weitere Seiten innerhalb des Crawl-Bereichs entdecken.
3. Hauptinhalt und relevante Strukturen mit den Regeln der jeweiligen Quelle lesen.
4. Inhalte mit Quellbelegen in ein gemeinsames internes Modell überführen.
5. Identitäten, Dubletten, Konflikte und unklare Zuordnungen prüfen.
6. OSCAL-Dokument erzeugen und gegen die festgelegte Version validieren.
7. Erst nach erfolgreicher Prüfung aller vorgesehenen Kataloge die Zieldateien
   jeweils atomar veröffentlichen und einen Laufbericht schreiben.

Bei gleichen Seiteninhalten, gleicher Config und gleicher Tool-Version müssen
Einträge, IDs, Reihenfolge und fachliche Aussagen reproduzierbar sein.
Laufzeitmetadaten und OSCAL-Dokumentversionierung werden separat behandelt.
Layoutänderungen lösen Diagnosen aus; es gibt keinen automatischen LLM-Fallback
und keine automatische Änderung der gespeicherten Regeln während des Scans.

Beschlossen: lokale Python-CLI mit getrennten Komponenten für Konfiguration,
HTTP-Abruf, Linkermittlung, Extraktion, internes Modell und OSCAL-Export.
Eine Weboberfläche oder ein laufender Server ist für den ersten Stand nicht vorgesehen.

## Funktionale Anforderungen

| ID | Anforderung |
| --- | --- |
| RH-F01 | Mehrere benannte Quellen pro Konfiguration unterstützen; jede Quelle besitzt eine stabile, eindeutige ID und eine oder mehrere Start-URLs. |
| RH-F02 | Requirements beliebiger fachlicher Art auch aus gemischten Quellen verarbeiten. Optionale Kategorien aus Quelle oder Config nachvollziehbar erhalten; keine feste Taxonomie verlangen. |
| RH-F03 | Von mehreren Startseiten aus rekursiv Links verfolgen. Startseiten zählen als Tiefe 0; jeder verfolgte Seitenlink erhöht die Tiefe um 1. Für mehrfach erreichbare Seiten gilt die kürzeste Entfernung zu einer Startseite derselben Quelle. |
| RH-F04 | Hosts, Ports, Pfadbereiche, Ein-/Ausschlüsse, Tiefe und Abrufbudgets je Quelle definieren. Ausschlüsse haben Vorrang; Links außerhalb des Bereichs werden nicht abgerufen. |
| RH-F05 | Unterschiedliche Inhaltsstrukturen über benannte Extraktionsregeln unterstützen: beispielsweise Tabellenzeilen, Überschriften mit Folgeabsätzen, Listen und markierte Inhaltsblöcke. |
| RH-F06 | Hauptinhalt von Navigation, Footer und sonstiger Seitengestaltung trennen. Unpassende oder mehrdeutige Regeln melden, statt beliebigen Seitentext als Requirements zu übernehmen. |
| RH-F07 | Je Eintrag mindestens stabilen Bezeichner, Aussage und Quellbeleg erfassen. Titel, Original-ID, Verbindlichkeit, Geltungsbereich, Bedingungen, Ausnahmen, Kontext, Kategorie und Quellversion übernehmen, soweit vorhanden. |
| RH-F08 | Inhalt vollständig in der Quellsprache erhalten. Normative Begriffe, Negationen, Bedingungen, Ausnahmen, Tabellenbeziehungen und relevante Codebeispiele dürfen beim Normalisieren nicht verloren gehen. |
| RH-F09 | Nicht jede Webseite und nicht jeden Absatz automatisch als eine Anforderung behandeln. Definition, Empfehlung, Beispiel und erläuternder Kontext müssen unterscheidbar bleiben. |
| RH-F10 | Fehlende Verbindlichkeit als unbekannt behandeln. Ohne Quellbeleg oder ausdrücklich konfigurierte Quellkonvention weder MUST noch SHOULD oder MAY ergänzen. |
| RH-F11 | Quelle, tatsächlich abgerufene Seiten-URL, Abschnitt oder Anker sowie Abrufzeit je Eintrag nachvollziehbar machen. Wenn verfügbar, Seitenrevision und Original-ID übernehmen. |
| RH-F12 | Wiederholte Abrufe derselben Seite und identische Einträge innerhalb einer Quelle deduplizieren. Gleiche IDs mit abweichendem Inhalt als Konflikt behandeln; verschiedene Quellen nicht stillschweigend zusammenführen. |
| RH-F13 | Eintrags-IDs bei unveränderter Quellidentität über Wiederholungsläufe stabil halten. Original-IDs erhalten und Quellnamensräume zur Kollisionsvermeidung verwenden. Ohne Original-ID oder stabilen Anker gilt Seiten-URL plus Aussage als Identität; eine Inhaltsänderung erzeugt dann eine neue ID. |
| RH-F14 | Vorhandene Beziehungen und Verweise zwischen Anforderungen erhalten. Referenzierte Inhalte außerhalb des Crawl-Bereichs nicht automatisch nachladen; ungelöste Beziehungen im Bericht ausweisen. |
| RH-F15 | Einen validen OSCAL-Katalog als UTF-8-YAML erzeugen; fachlich unvollständige, widersprüchliche oder schemawidrige Ergebnisse nicht als erfolgreich veröffentlichen. |
| RH-F16 | Einen maschinenlesbaren Laufbericht mit abgerufenen, ausgeschlossenen und fehlgeschlagenen Seiten sowie Eintragszahlen, Konflikten und Extraktionslücken schreiben. Berichte enthalten keine vollständigen Quellseiten. |
| RH-F17 | Konfigurationsprüfung ohne Netzwerkzugriff sowie einen Probelauf mit Abruf und Extraktion ohne Ersetzen des Zielkatalogs anbieten. |
| RH-F18 | Bei Abruffehlern, ausgeschöpften Ressourcenbudgets mit offenen Seiten innerhalb des gewählten Scopes und der Tiefe, Extraktionskonflikten oder unerwartet leerem Ergebnis standardmäßig mit Fehlerstatus enden und den letzten gültigen Katalog unverändert lassen. Gewollte Scope- und Tiefengrenzen sind keine Fehler. Seiten ohne relevante Inhalte separat von Extraktionsfehlern ausweisen. |
| RH-F19 | Den vollständigen Scan einschließlich OSCAL-Export ohne LLM-Abhängigkeit, Modellzugriff oder API-Key ermöglichen. Bei identischem Input und gleicher Tool-Version fachlich reproduzierbare Ergebnisse erzeugen. |
| RH-F20 | Ein dokumentiertes Config-Schema und Beispiele für manuelle Erstellung oder Erstellung mit einem externen Assistenten bereitstellen. Importierte Configs unabhängig von ihrer Herkunft validieren und per Probelauf prüfbar machen. Die erste Version enthält keine Modellaufrufe oder LLM-Anbieterintegration. |
| RH-F21 | Standardmäßig einen gemeinsamen OSCAL-Katalog aus allen Quellen erzeugen. Optional mehrere benannte Kataloge mit konfigurierten Zielpfaden und Quellzuordnungen unterstützen. Jede Ausgabe muss eigenständig valide sein und die Provenienz ihrer Einträge erhalten. |
| RH-F22 | Neben öffentlichen Quellen Zugriff mit API-Token, Benutzername/Passwort und Firmen-SSO unterstützen. Verfahren und Credential-Referenzen je Quelle konfigurieren; Anmeldung und Session-Verwaltung bleiben unabhängig von einem LLM. |
| RH-F23 | Bei jedem Lauf die Kataloge vollständig aus den aktuell erfassten Quellen und der Config erzeugen. Nach erfolgreichem Abruf, Extraktion und Validierung die bisherigen Ausgabedateien ersetzen. Keine manuell ergänzten oder inzwischen aus den Quellen entfernten Requirements aus alten Ausgabedateien übernehmen. Stabile Requirement-Identitäten bleiben gemäß RH-F13 erhalten. |
| RH-F24 | Nichtinteraktive Läufe und dokumentierte CI-Vorlagen für GitLab CI/CD sowie GitHub Actions bereitstellen, zuerst für GitLab. Beide verwenden dieselbe CLI und Config wie lokale Läufe. Erfolg, ungültige Konfiguration, Zugriffsprobleme und unvollständige Ergebnisse müssen über dokumentierte Exit-Codes und den Laufbericht unterscheidbar sein. |

## Konfiguration als zentrale Schnittstelle

Versionierte YAML-Datei mit striktem Schema und verständlichen
Fehlermeldungen einschließlich Feldpfad. Unbekannte Felder, doppelte Schlüssel,
ungültige Selektoren, widersprüchliche Bereiche, nicht auflösbare Regelreferenzen
und fehlende Pflichtwerte werden vor dem ersten Abruf zurückgewiesen.
YAML wird ausschließlich als Datenformat ohne ausführbare Tags geladen.

Die Konfiguration beschreibt:

- globale Grenzen und explizite Überschreibungen je Quelle;
- Quellidentität, Startseiten und zulässigen Crawl-Bereich;
- Authentifizierungsreferenzen und bei Bedarf eine organisationsinterne CA;
- Quelltyp beziehungsweise Adapter und Regeln für unterschiedliche Seitenlayouts;
- Feldzuordnung einschließlich Original-ID, Titel, Aussage, Kontext und Verbindlichkeit;
- optionale Kategorien und Gruppierungen entsprechend der Quelle;
- ein gemeinsames Ausgabeziel oder mehrere Kataloge mit Quellzuordnung,
  Katalogmetadaten und festgelegter OSCAL-Version.

Die Konfiguration darf keine Python-Ausdrücke, Shell-Kommandos oder beliebige
Importpfade ausführen. Zunächst sind deklarative CSS-Selektoren und feste
Extraktionsstrategien vorgesehen. Ein zusätzliches Layout erhält eine weitere
Regel; ein grundsätzlich anderes Abrufverfahren gegebenenfalls einen Adapter.
Für unbekannte Layouts gibt es einen Diagnosebericht statt einer stillen Ersatzregel.

### Startseiten, Scope und Tiefe

- `start-urls` enthält eine oder mehrere Startseiten pro Quelle. Jede Startseite
  muss im konfigurierten Scope liegen; andernfalls ist die Config ungültig.
- `allowed-origins` legt HTTPS-Host und Port exakt fest. Subdomains sind nicht
  automatisch eingeschlossen. Der Pfadbereich `/` erlaubt den gesamten Host.
- `allowed-path-prefixes` begrenzt den Scope auf einen oder mehrere Pfadbereiche.
  Ein Bereich `/policies/` umfasst `/policies/` und darunterliegende Pfade,
  aber beispielsweise nicht `/policies-old/`.
- Host, Pfad und Ausschlüsse werden gemeinsam geprüft. Ein Link darf den Scope
  auch dann nicht verlassen, wenn er auf einer erlaubten Seite steht.
- `max-depth: 0` liest nur Startseiten, `1` zusätzlich deren direkte Links usw.
  Ein endlicher Wert ist eine nichtnegative Ganzzahl; `null` erlaubt das
  Verfolgen aller erreichbaren Links im Scope ohne Tiefengrenze. Seiten-,
  Request- und Laufzeitbudgets gelten weiterhin.
- Die Tiefe zählt Links, nicht URL-Pfadsegmente. Weiterleitungen erhöhen nicht
  die Linktiefe, unterliegen aber Scope-Prüfung und eigenem Redirect-Limit.
- Überlappende Startseiten und Linkschleifen dürfen keine mehrfachen Abrufe
  derselben normalisierten Seiten-URL innerhalb einer Quelle verursachen.
- Der Scope erlaubt das Abrufen erreichbarer Seiten; er garantiert nicht das
  Auffinden unverlinkter Seiten. Solche Seiten benötigen weitere Start-URLs
  oder später eine zusätzliche, ausdrücklich konfigurierte Discovery-Methode.

### Authentifizierung je Quelle

Bestätigt sind drei Zugriffsarten zusätzlich zu `auth.mode: none`:

- **API-Token:** Extern bereitgestelltes Token über das für die Quelle festgelegte
  Header-Verfahren senden. Kein Token in URL oder Prozessargumenten.
- **Benutzername/Passwort:** Extern bereitgestellte Zugangsdaten über das von der
  Quelle unterstützte Verfahren verwenden. Implementiert ist HTTP Basic über HTTPS.
  Eine Formularanmeldung erfordert bei Bedarf einen Adapter für die Zielanwendung.
- **Firmen-SSO:** Als Ansatz einen separaten interaktiven Anmeldeschritt über
  den regulären Unternehmens-Login vorsehen. MFA und andere Login-Vorgaben bleiben
  wirksam. Der Crawl verwendet den daraus vorgesehenen, gültigen Zugriffskontext.
  Microsoft Entra ID ist als erster Anbieter beschlossen. Der konkrete
  Integrationsweg ist anhand der geschützten Zielanwendung festzulegen;
  die Anbieterwahl allein legt deren Login-Schnittstelle noch nicht fest.

Session-Daten werden, soweit eine Speicherung erforderlich ist, getrennt von
der versionierten Config mit restriktiven Zugriffsrechten abgelegt. Credentials
und Sessions sind an die jeweilige Quelle beziehungsweise Identität gebunden.
Abgelaufene oder abgewiesene Zugriffe führen zu einem Authentifizierungsfehler;
der Lauf wird nicht unbemerkt mit eingeschränktem anonymem Inhalt fortgesetzt.
Für unbeaufsichtigte Läufe ist ein dafür geeignetes Verfahren erforderlich;
SSO mit notwendiger Benutzerinteraktion wird nicht als unbeaufsichtigt nutzbar
zugesagt. Anmeldeziele werden separat vom Crawl-Scope konfiguriert und nur vom
vorgesehenen Login-Verfahren verwendet, nicht durch gewöhnliche Seitenlinks.

### Unbeaufsichtigte Ausführung und CI

- Zuerst eine GitLab-CI/CD-Vorlage, anschließend einen entsprechenden
  GitHub-Actions-Workflow bereitstellen. Beide unterstützen manuell ausgelöste
  und zeitgesteuerte Jobs; die Zeitplanung übernimmt die jeweilige CI-Plattform.
- Die CLI wartet im nichtinteraktiven Betrieb niemals auf Passwort-Eingaben,
  Browser-Login oder MFA. Fehlender oder abgelaufener Zugriff führt zum Fehlerstatus.
- Für geschützte Quellen wird ein von der Zielanwendung unterstützter und
  freigegebener maschineller Zugriff benötigt. Die Entra-ID-Anbindung muss diesen
  konkreten Zugriffsweg berücksichtigen; interaktives SSO allein genügt dafür nicht.
- Credentials über die Secret-Verwaltung der jeweiligen CI-Plattform zuführen.
  Secrets bleiben aus versionierten Configs, Logs, Caches und Artefakten ausgeschlossen.
- Erfolgreich erzeugte OSCAL-Dateien und der Laufbericht sind Job-Artefakte.
  Nach fehlgeschlagenen Läufen wird kein alter oder unvollständiger Katalog als
  erfolgreiches neues Ergebnis hochgeladen. Diagnosen bleiben zugänglich.
- Artefakte mit internen Requirements erhalten entsprechend beschränkte
  Zugriffsrechte und eine dokumentierte Aufbewahrungsdauer. Keine automatische
  öffentliche Veröffentlichung oder Rückschreibung in ein Repository vorsehen.
- Runner müssen die konfigurierten internen Quellen erreichen können. Benötigte
  Netzzugänge und interne CA werden als Betriebsanforderungen dokumentiert.

### Beispiel für eine Quelle mit tabellarischen Requirements

Synthetisches Beispiel im implementierten Config-Format. Domain und Selektoren
sind an die eigene Quelle anzupassen. Die ausführbare öffentliche Beispielconfig
steht in [examples/tss-web.yaml](examples/tss-web.yaml).

```yaml
config-version: 1
output:
  catalog: ./out/catalog.oscal.yaml
  report: ./out/harvest-report.json
  title: Organisationsrichtlinien
  version: "1.0.0"
  oscal-version: "1.2.3"
defaults:
  max-pages: 200
  max-depth: 3
  max-response-bytes: 5242880
  connect-timeout-seconds: 5
  read-timeout-seconds: 30
  max-run-seconds: 900
  max-requests: 400
  request-interval-seconds: 1
sources:
  - id: engineering-requirements
    title: Engineering Requirements
    adapter: html
    start-urls:
      - https://wiki.example.org/security/index
      - https://wiki.example.org/security/services
    crawl:
      mode: linked-pages
      max-depth: 2
      allowed-origins:
        - https://wiki.example.org
      allowed-path-prefixes:
        - /security/
      exclude-path-prefixes:
        - /security/history/
    auth:
      mode: none
    extraction:
      content-selector: main
      rules:
        - id: requirement-table
          strategy: table-rows
          item-selector: table.requirements tbody tr
          fields:
            original-id: {selector: "td:nth-child(1)"}
            title: {selector: "td:nth-child(2)"}
            statement: {selector: "td:nth-child(3)"}
            obligation: {selector: "td:nth-child(4)"}
```

Die Grenzwerte sind Vorschläge für den ersten Stand und bieten Spielraum für
die erwarteten wenigen Dutzend Seiten pro Lauf. Request-Budget und
Laufzeit gelten auch für Wiederholungen und Weiterleitungen; das Größenlimit
gilt für dekomprimierte Inhalte. Eine abweichende Regel für eine weitere Quelle
darf weder globale Sicherheitsgrenzen noch die Zielprüfung umgehen.

### Eine oder mehrere Ausgabedateien

`output.catalog` im obigen Beispiel ist der Standard: alle konfigurierten
Quellen werden in einem Katalog zusammengeführt. Alternativ definiert
`output.catalogs` mehrere Kataloge. Beide Formen schließen sich gegenseitig aus.

Implementierte Zuordnung: Jede Ausgabe nennt die IDs der
Quellen, deren Requirements sie enthalten soll. Eine Quelle kann mehreren
Ausgaben zugeordnet werden und wird dafür nur einmal gecrawlt. Jede konfigurierte
Quelle muss mindestens einer Ausgabe zugeordnet sein. Unbekannte Quell-IDs,
doppelte Katalog-IDs sowie kollidierende Zielpfade werden vor dem Abruf abgewiesen.
Weitere Aufteilungskriterien innerhalb einer Quelle sind noch nicht festgelegt.

Dieser alternative Config-Ausschnitt setzt Quellen mit den IDs `engineering`
und `operations` voraus:

```yaml
output:
  report: ./out/harvest-report.json
  catalogs:
    - id: engineering-catalog
      path: ./out/engineering.oscal.yaml
      title: Engineering Requirements
      version: "1.0.0"
      source-ids: [engineering]
    - id: operations-catalog
      path: ./out/operations.oscal.yaml
      title: Operations Requirements
      version: "1.0.0"
      source-ids: [operations]
```

Die Zuordnung ändert keine Requirement-Identitäten. Jede Datei besitzt eigene
Katalogmetadaten und eine eigene Dokument-UUID. Alle Kataloge werden vor der
Veröffentlichung validiert. Das atomare Ersetzen gilt jeweils pro Datei;
mehrere Dateien bilden keine Dateisystemtransaktion. Ein Fehler während der
Veröffentlichung führt zu einem Fehlerstatus und einem Bericht über bereits
ersetzte und nicht ersetzte Dateien, niemals zu einem Gesamterfolg.

## OSCAL-Abbildung

Vorgesehen ist zunächst das **Catalog Model**: Es beschreibt Sammlungen von
Controls einschließlich Aussagen, Gruppen und Referenzen und unterstützt YAML.
Siehe [NIST: Control Layer](https://pages.nist.gov/OSCAL/learn/concepts/layer/control/)
und [Catalog Model](https://pages.nist.gov/OSCAL/learn/concepts/layer/control/catalog/).

| Internes Merkmal | OSCAL-Abbildung |
| --- | --- |
| Sammlung und Version | `catalog.metadata` mit Titel, Version, OSCAL-Version und Änderungszeit |
| Kategorie oder Quellgliederung | `groups` mit stabilen IDs und Titeln |
| Eigenständige Anforderung oder Empfehlung | `controls` mit `id`, `title` und Aussage in `parts` mit `name: statement` |
| Erläuterungen und Beispiele | Gesonderte Parts, etwa `guidance` und `example` |
| Original-ID | Property am Control; ursprünglichen Wert erhalten |
| Quellverweis | `links` mit `rel: reference`, möglichst mit Abschnittsanker |
| Zusätzliche Provenienz und optionale Kategorien | Properties im Namespace `https://github.com/appsec-foundry/appsec-analyzer-tools/ns/requirement-harvester` |
| Mehrzeiliger Kontext, Geltungsbereich und Ausnahmen | Parts `context`, `applicability` und `exceptions` im selben Namespace |

OSCAL dient als gewünschtes Austauschformat. Die Abbildung einer Anforderung
auf ein Control macht sie fachlich nicht automatisch zu einer Security-Vorgabe.
Die Eignung der Feldzuordnung wird auch an Anforderungen anderer Art geprüft.

Implementiert ist OSCAL 1.2.3. Das offizielle Schema ist unverändert lokal
versioniert; die Validierung unterstützt auch dessen Unicode-Zeichenmuster.
Es gibt keine Schema-Downloads anhand von Quellinhalten.
Stabile Control-IDs sind von der Dokument-UUID zu unterscheiden: Bei geändertem
Dokumentinhalt sind nach NIST Dokument-UUID und `metadata.last-modified` zu erneuern.
Gleicher fachlicher Inhalt muss unabhängig von Laufzeitmetadaten vergleichbar bleiben.

## Integration mit appsec-analyzer

Im lokalen Checkout `/home/mrohr/appsec-analyzer`, HEAD
`486d201252409859ddcf6aac69e5d8ea299c953e`, wurden bei der Planung gelesen:

- `scripts/requirements/harvest_requirements.py`: vorhandener konfigurierbarer
  HTML-Harvester für Requirements und Blueprints mit eigenem YAML-Katalogformat.
- `schemas/requirements-catalog.schema.yaml`: dokumentierter Katalogvertrag mit
  `categories[].requirements[]` und Feldern wie `id`, `text`, `priority` und `url`.

Dieser Vertrag entspricht nicht der OSCAL-Katalogstruktur. Eine direkte
OSCAL-Unterstützung des Consumers wurde damit nicht nachgewiesen.
Beschlossen ist ausschließlich OSCAL-YAML als fachlicher Export. Eine eventuell
benötigte Consumer-Erweiterung im Hauptprojekt ist eine separate Integrationsaufgabe
und keine Voraussetzung für die Fertigstellung des Harvesters. OSCAL-Schemavalidität
allein belegt keine Kompatibilität mit dem bisherigen Analyzer-Import.

Das neue Tool wird eigenständig anhand der hier beschriebenen Anforderungen
entwickelt. Code, Extraktionsregeln und Tests des bisherigen Harvesters werden
nicht übernommen. Die oben genannten Dateien dokumentieren ausschließlich den
bei der Planung vorgefundenen Integrationsstand. Änderungen oder eine Ablösung
des bisherigen Harvesters im Hauptprojekt sind nicht Teil dieses Plans.

## Sicherheits- und Betriebsanforderungen

Die betroffenen Assets sind Wiki-Zugangsdaten, interne Inhalte, der lokale
Katalog und die Erreichbarkeit der Quellen. Vertrauensgrenzen bestehen zwischen
Betreiberkonfiguration, entfernten Seiten und Links, Parser und lokalen Dateien.

| ID | Anforderung |
| --- | --- |
| RH-S01 | Nur HTTPS mit Zertifikats- und Hostnamenprüfung verwenden; eine konfigurierte interne CA ermöglichen. Keine Abschaltoption für TLS-Prüfung. |
| RH-S02 | Konfigurierte Origins, Ports, Pfadbereiche und zulässige Zielnetze an der tatsächlichen Verbindung prüfen, einschließlich IPv6 und DNS-Wechseln. Loopback, Link-local und Metadatenziele sperren; interne Wiki-Netze nur ausdrücklich und eng begrenzt konfigurieren. |
| RH-S03 | Jeden Redirect erneut auf Zielbereich und Adressen prüfen und die Hop-Zahl begrenzen. Authentifizierungsdaten und Cookies niemals an andere Origins weiterreichen. URL-Normalisierung und Pfadgrenzen dürfen sich nicht durch Traversal oder alternative Adressschreibweisen umgehen lassen. |
| RH-S04 | Für geschützte Quellen nur lesend berechtigte Zugangsdaten aus externer Konfiguration oder Secret-Verwaltung beziehen. Config enthält Referenzen, keine Secret-Werte. Fehlende erforderliche Zugangsdaten sowie 401/403 führen zu klaren Fehlern; Loginseiten gelten nicht als erfolgreiche Inhaltsseiten. |
| RH-S05 | URLs mit eingebetteten Zugangsdaten zurückweisen. Tokens nicht in URLs, Prozessargumenten, Katalogen oder Berichten ablegen; Logs auch von sensitiven Query-Werten bereinigen und fremde Logfelder strukturiert kodieren. |
| RH-S06 | Seitenzahl, Linkwarteschlange, Requests, Redirects, Wiederholungen, dekomprimierte Bytes, Parser-Aufwand und Laufzeit begrenzen. Rate-Limits und Retry-After beachten; keine Endlosschleifen durch Links oder URL-Varianten. |
| RH-S07 | Webseiten und Konfiguration ausschließlich als Daten behandeln. Keine Skripte, eingebetteten Anweisungen oder Parser-Nachladefunktionen ausführen; keine ungeplanten Subressourcen abrufen. |
| RH-S08 | Nur benötigte Inhaltstypen parsen, Content-Type und tatsächlichen Inhalt berücksichtigen. PDF-, Office-, Archiv- und Anhangsverarbeitung ist zunächst ausgeschlossen. |
| RH-S09 | Lokale Zieldateien stammen aus der Betreiberkonfiguration, niemals aus Seitentiteln oder entfernten Dateinamen. YAML sicher serialisieren, Ausgabe vor Ersetzen prüfen und vertrauliche Kataloge mit restriktiven Dateirechten schreiben. |
| RH-S10 | Keine vollständigen authentifizierten Seiten standardmäßig speichern. Das Tool überträgt keine Inhalte oder Zugangsdaten an Modelldienste. Extern erstellte Configs anhand desselben strikten Schemas und erlaubter Werte wie manuelle Configs prüfen; unbekannte Felder und ausführbare Inhalte abweisen. |
| RH-S11 | CI-Jobs erhalten minimale, standardmäßig nur lesende Berechtigungen. Code und Config aus nicht vertrauenswürdigen Merge-/Pull-Requests dürfen nicht mit Quellzugangsdaten ausgeführt werden. Abhängigkeiten werden mit Lockfile und überprüften Integritätswerten installiert; externe Actions und Container auf unveränderliche Referenzen festgelegt und Abhängigkeiten regelmäßig auf Schwachstellen geprüft. Container laufen ohne Root-Rechte. |

## Abnahmekriterien und Tests

| ID | Nachweis |
| --- | --- |
| RH-A01 | Eine synthetische Quelle je für Tabelle, Liste und Kapitelstruktur ergibt die erwarteten Einträge einschließlich Kontext und Quellanker. Beispiele decken unterschiedliche fachliche Anforderungen und Anforderungen ohne Kategorie ab. |
| RH-A02 | Negationen, MUST NOT, Bedingungen, Beispiele, Umlaute, mehrzeilige Aussagen und Code bleiben fachlich korrekt erhalten; unbekannte Verbindlichkeit wird nicht geraten. |
| RH-A03 | Gleichbleibende Quellidentitäten ergeben stabile IDs; Linkschleifen und doppelte Seiten erzeugen keine doppelten Einträge. Widersprüchliche Original-IDs führen zu einem Konflikt. |
| RH-A04 | Ein- und Ausschlüsse, Pfadgrenzen, Tiefe und Budgets werden eingehalten; fehlende Startseiten und erreichte Limits ergeben keinen irreführenden Erfolg. |
| RH-A05 | Unbekannte Felder, doppelte YAML-Schlüssel, ausführbare YAML-Tags, falsche Typen und fehlerhafte Regeln werden vor Netzwerkzugriff abgelehnt. |
| RH-A06 | Ungültige Zertifikate, Redirects aus dem Bereich, private oder Metadatenziele ohne Freigabe, IPv6-Varianten und DNS-Wechsel werden an der Verbindungsgrenze abgewiesen. Erlaubte interne Wikis funktionieren innerhalb ihrer expliziten Netzfreigabe. |
| RH-A07 | Fehlende Secrets, 401/403 und Loginseiten werden erkannt. Tests mit synthetischen Tokens belegen deren Abwesenheit in Logs und Ausgaben sowie bei Redirects zu anderen Origins. |
| RH-A08 | Überlange und stark komprimierte Antworten, große Linkmengen, endlose Redirects, 429 und Timeouts enden innerhalb der konfigurierten Grenzen. |
| RH-A09 | Der YAML-Export besteht die Validierung gegen das festgelegte OSCAL-Schema und zusätzliche fachliche Regeln zu IDs, Aussagen, Typen und Provenienz. Ein absichtlich ungültiger Export wird abgewiesen. |
| RH-A10 | Bei Abruf-, Extraktions-, Erzeugungs- oder Validierungsfehlern vor der Veröffentlichung bleiben bestehende Zieldateien unverändert; Probeläufe ersetzen keinen Katalog. Fehler während der Veröffentlichung werden gemäß RH-A16 behandelt. |
| RH-A12 | Ein vollständiger Scan mit gespeicherten Seiten-Fixtures funktioniert ohne Modellzugriff und API-Key. Wiederholungen mit identischer Config und Tool-Version liefern identische fachliche Ergebnisse einschließlich IDs und Reihenfolge. |
| RH-A13 | Fehlerhafte extern erstellte Configs, unbekannte Felder und ausführbare Inhalte werden zurückgewiesen. Links und Anweisungen in Seiten können den in der geprüften Config vorgegebenen Quellbereich nicht erweitern. Manuelle und extern erzeugte Configs durchlaufen dieselben Prüfungen. |
| RH-A14 | Eine Layoutänderung führt zu einer Diagnose ohne Modellaufruf oder automatische Config-Änderung. Regeltests prüfen erwartete Inhalte und bewusst auszuschließende Seitenelemente. |
| RH-A15 | Mehrere überlappende Startseiten, kürzere alternative Linkwege und Linkschleifen ergeben die erwartete Seitenmenge ohne Mehrfachabrufe. Tiefe 0, 1 und 2, Host-Scope, Pfad-Scope und ausgeschlossene Nachbarpfade werden geprüft. Gewollte Tiefengrenzen ergeben einen vollständigen Lauf innerhalb des konfigurierten Bereichs; ein vorzeitig erschöpftes Ressourcenbudget meldet Unvollständigkeit. |
| RH-A16 | Ohne Aufteilung entsteht ein gemeinsamer Katalog. Mit mehreren konfigurierten Ausgaben enthält jede Datei genau die Requirements ihrer Quellen und besteht die OSCAL-Validierung. Unbekannte oder nicht zugeordnete Quellen und kollidierende Ziele werden abgewiesen. Eine mehrfach zugeordnete Quelle wird nicht mehrfach gecrawlt. Veröffentlichungsfehler werden als Fehler mit dem tatsächlichen Stand je Datei berichtet. |
| RH-A17 | Die drei implementierten Anmeldeverfahren jeweils mit gültigen, fehlenden und abgewiesenen Zugriffsdaten prüfen. SSO-Abbruch und Session-Ablauf werden als Fehler erkannt. Sessions und Credentials gelangen weder an fremde Quellen noch in Config, Kataloge oder Logs; gespeicherte Sessions besitzen restriktive Zugriffsrechte. |
| RH-A18 | Ein erfolgreicher Folgelauf übernimmt geänderte und neue Quellanforderungen, entfernt nicht mehr vorhandene Anforderungen und übernimmt keine manuellen Ergänzungen aus der alten Ausgabe. Unveränderte Quellidentitäten behalten ihre Requirement-IDs. Ein fehlgeschlagener Abruf darf nicht als Löschung von Requirements veröffentlicht werden. |
| RH-A19 | Beide CI-Vorlagen führen den nichtinteraktiven Pfad mit synthetischen Quellen aus und liefern erwartete Exit-Codes, Berichte und valide Artefakte. Fehlende oder abgelaufene Zugriffsdaten verursachen keinen Eingabedialog. Fehlerläufe veröffentlichen keinen Erfolgskatalog. Job-Berechtigungen, Secret-Abgrenzung gegenüber nicht vertrauenswürdigen Änderungen und Artefaktzugriff werden für beide Plattformen geprüft. |

Tests verwenden synthetische HTML-Fixtures und kontrollierte HTTP-/DNS-Testdoubles.
Verbindungsschutz wird am Transport geprüft; ein Mock oberhalb der Zielprüfung
ist dafür kein ausreichender Nachweis. Live-Tests mit echten Wiki-Zugangsdaten
gehören nicht in die reguläre Testsuite.

## Implementierte Arbeitspakete

1. **Quellen und Exportvertrag klären:** Repräsentative Seiten unterschiedlicher
   Struktur, Zugriff, Erkennung und genaue OSCAL-Version festlegen.
2. **Config und internes Modell:** Schema, Fehlermeldungen, Feldzuordnung,
   Identitäten und synthetische Beispieldaten definieren.
3. **Abruf und Crawl:** HTTPS, Zugriff, Zielgrenzen, Linkermittlung, Limits und
   Fehlerbehandlung implementieren und an positiven sowie negativen Fällen prüfen.
4. **Extraktion:** Zunächst die tatsächlich benötigten Layouts unterstützen,
   Kontext und Provenienz erhalten, Dubletten und Konflikte behandeln.
5. **OSCAL-Export:** Versioniertes Schema, semantische Regeln, atomare Ausgabe
   und Laufbericht umsetzen.
6. **CLI und Dokumentation:** Konfigurationsprüfung, Probelauf, Statuscodes,
   Installation und reproduzierbare Aufrufbeispiele dokumentieren.
7. **Externe Config-Erstellung dokumentieren:** Schema, repräsentative Beispiele
   und einen Ablauf für Erstellen, Prüfen und Versionieren der Config bereitstellen.
   Derselbe Ablauf funktioniert manuell oder mit einem externen Assistenten.
8. **CI-Anbindung:** Zuerst GitLab CI/CD, danach GitHub Actions mit nichtinteraktivem
   Aufruf, Secret-Anbindung, Artefakten und positiven sowie negativen Prüfläufen ergänzen.

## Noch quell- beziehungsweise betriebsabhängig zu klären

| ID | Frage | Vorschlag / Auswirkung |
| --- | --- | --- |
| O01 | Welche weiteren Unternehmensseiten sollen erfasst werden? | TSS-WEB ist als Beispiel umgesetzt. Weitere Layouts benötigen passende Configs und fachliche Prüfung ihrer Probeläufe. |
| O02 | Welchen Zugriff unterstützt die konkrete geschützte Zielanwendung? | Header-Token, HTTP Basic und Entra-Bearer-Token sind umgesetzt. Tenant, App-Registrierung, Leserechte und Akzeptanz der Tokens am Quellendpunkt sind vor Ort zu prüfen. Cookie-/Formular-Adapter sind bei entsprechendem Bedarf zusätzlich erforderlich. |
| O10 | Welche privaten CI-Projekte, Runner und berechtigten Artefaktempfänger werden verwendet? | Die Vorlagen dokumentieren Voraussetzungen und liefern lokal geprüfte Einstiegspunkte. Gehostete Pipeline-Prüfungen erfolgen bei der Einrichtung. |
