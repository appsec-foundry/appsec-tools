# CI-Einrichtung

Beide Vorlagen führen dieselbe CLI wie lokale Läufe aus. GitLab ist die erste
Integration; GitHub Actions ist als gleichwertige Vorlage vorhanden. Die Vorlagen
wurden lokal strukturell und mit dem echten CI-Einstiegspunkt an synthetischen
Quellen getestet; gehostete Pipeline-Läufe wurden nicht gestartet.

## GitLab CI/CD

1. `ci/gitlab-ci.yml` als Projekt-Pipeline übernehmen oder per `include:local` einbinden.
2. Einen dedizierten Shell-Runner mit Tag `python-nonroot` bereitstellen:
   Python >=3.10, `venv`, Schreibrechte im Job-Verzeichnis, Ausführung ohne Root.
   Produktive Crawl-Jobs benötigen einen geschützten Runner; nicht vertrauenswürdige
   Projekte dürfen ihn nicht gemeinsam nutzen.
3. Projekt privat und Default-Branch geschützt halten. Schedule oder manuell
   ausgelöste Web-Pipeline auf diesem Branch konfigurieren.
4. Zugangsdaten als maskierte und geschützte CI-Variablen mit Environment-Scope
   `requirement-harvest` hinterlegen. Dadurch erhalten Verify-Jobs und fremde
   Merge-Request-Pipelines keine Quellzugangsdaten. Job-Token-Rechte lesend belassen.
5. `examples/tss-web.yaml` im Harvest-Job durch die freigegebene Unternehmensconfig
   ersetzen. Für öffentliche Testquellen werden keine Credentials benötigt.

Kataloge und Berichte sind 7 Tage verfügbar, Zugriff nur für Maintainer.
Die Vorlage verwendet `artifacts:access`; die eingesetzte GitLab-Version muss
`maintainer` unterstützen. Details:
[GitLab-Artefaktzugriff](https://docs.gitlab.com/ci/jobs/job_artifacts/#control-who-can-download-artifacts).

## GitHub Actions

1. `ci/github-actions.yml` nach `.github/workflows/requirement-harvester.yml` kopieren.
2. Ein privates Repository und Environment `requirement-harvest` verwenden.
   Das Environment auf den geschützten Default-Branch beschränken.
3. Benötigte Environment-Secrets setzen: `HARVEST_TOKEN`, `HARVEST_USERNAME`,
   `HARVEST_PASSWORD` oder `ENTRA_CLIENT_SECRET`; nur das gewählte Auth-Verfahren
   benötigt seine Werte. Keine Secrets im Verify-Job.
4. Die Config im Harvest-Schritt anpassen. Workflow manuell oder über den
   mitgelieferten Wochenplan starten; Cron-Zeiten beziehen sich auf UTC.
5. Für nicht öffentlich erreichbare Unternehmensseiten einen passenden privaten
   Runner einsetzen. Er muss aktuelle Actions-Runner-Versionen und die Runtime
   der verwendeten Actions unterstützen.

Die Vorlage verwendet `contents: read`, keine PR-Trigger für den Crawl,
`persist-credentials: false` und 7 Tage Artefaktaufbewahrung. Artefakte sind für
Personen mit Leserechten am privaten Repository verfügbar. Diese Empfänger müssen
für die enthaltenen Requirements berechtigt sein. Siehe
[GitHub: Secure use](https://docs.github.com/en/actions/reference/security/secure-use).

Die beiden Actions sind an signierte, über die offizielle GitHub-API geprüfte
Release-Commits gebunden (Stand 2026-10-28):

| Action | Version | Commit |
| --- | --- | --- |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |

## Artefakte und Fehler

`scripts/ci_run.py` legt ein frisches Verzeichnis `ci-artifacts` an. Ist es bereits
vorhanden, wird der Job abgebrochen. Erfolgreiche Kataloge werden erst nach einem
vollständig erfolgreichen CLI-Lauf gemeinsam in das Artefaktverzeichnis übernommen.
Bei Fehlern wird nur ein Fehlerbericht bereitgestellt; ausführliche kontrollierte
Diagnosen stehen außerdem im Job-Log. Alte Kataloge aus `out/` werden nicht kopiert.

Für lokale Wiederholungen dieses Helpers ein frisches Arbeitsverzeichnis verwenden.
Credentials, Session-Dateien und komplette HTML-Seiten sind keine Job-Artefakte.
Die Vorlagen verwenden keine gemeinsamen Caches für Laufdaten.

## Entra ID und Netz

CI kann keinen interaktiven Browser-Login oder MFA-Dialog erledigen. Für Entra ID
benötigt die Zielanwendung einen freigegebenen Client-Credentials-Zugriff mit
passenden Anwendungs-Leserechten. Eine persönliche Browser-Session ist kein
Dauerzugang für eine Pipeline. Ohne unterstützten maschinellen Zugriffsweg endet
der Job mit einem Authentifizierungsfehler.

Die Runner benötigen direkten HTTPS-Zugriff auf Quellhosts, bei Entra außerdem
auf `login.microsoftonline.com`. Installation und Dependency-Check benötigen PyPI;
der Scan selbst lädt weder Pakete noch OSCAL-Schemas nach. Interne Netze und
CA-Zertifikate werden in der Quellconfig freigegeben. TLS-Prüfung bleibt aktiv.
