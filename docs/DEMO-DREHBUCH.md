# Demo: GIF, Video und Drehbuch

## Fertige Dateien

- `docs/demo.gif` (31 s, 1000 × 680 px): für die README auf GitHub.
- `docs/demo.mp4` (31 s): für LinkedIn. LinkedIn spielt MP4 automatisch ab, GIFs oft nicht.
- `docs/screenshot-dark.png`, `docs/screenshot-light.png`, `docs/screenshot-mobile.png`: der
  HTML-Bericht der Demo in dunkel, hell und auf dem Handy.
- `docs/sample-report.html` und `docs/sample-report.json`: der vollständige Demo-Bericht.

Alle Dateien zeigen nur **erfundene Daten** aus dem eingebauten Generator. Die Geräte heißen
`fw-branch-01`, `fw-hub-01` und `fw-lab-01`, die öffentlichen Adressen stammen aus dem
Dokumentationsbereich `203.0.113.0/24`.

Neu erzeugen: `scripts/demo/make_gif.sh` (braucht Python, Node.js mit Playwright und ffmpeg). Das
Skript schreibt die Demo-Dateien in einen temporären Ordner, ruft fgaudit dreimal auf und rendert
die farbige Ausgabe als Terminal-Fenster.

## Drehbuch für eine eigene 30-Sekunden-Aufnahme

Für eine echte Bildschirmaufnahme, zum Beispiel mit OBS, der Windows-Bildschirmaufnahme
(Win + Alt + R) oder `asciinema` unter Linux/macOS. **Nimm keine echte Konfiguration.** Erzeug
die Demo-Dateien vorher so:

```bash
python -c "from fgaudit import synth; d = synth.demo_inputs(); open('fw-branch.conf','w',newline='').write(d['audit'][1]); open('before.conf','w',newline='').write(d['before'][1]); open('after.conf','w',newline='').write(d['after'][1]); [open(n,'w',newline='').write(t) for n,t in d['logs'].items()]"
```

Danach liegen im Ordner `fw-branch.conf`, `before.conf`, `after.conf`, `branch-01.log`,
`hub-01-syslog.log` und `lab-01.log`.

Vorbereitung: Terminal auf 100 × 28 Zeichen, dunkles Farbschema, Schriftgröße 16 bis 18, Prompt
kurz halten (zum Beispiel `$ `). Vor jedem Befehl `clear` (Windows: `cls`).

| Zeit | Befehl / Aktion | Was man sieht | Texteinblendung (optional) |
|---|---|---|---|
| 0–2 s | leeres Terminal | Cursor blinkt | „FortiGate-Backup prüfen, offline“ |
| 2–4 s | `fgaudit fw-branch.conf` tippen, Enter | | |
| 4–10 s | nichts tun, oben bleiben (Mausrad oder `| more`) | SUMMARY mit 8 HIGH, erste Befunde: Subnetz-Überschneidung port2/port6, Policy 20 wird von 40 verdeckt | „Verdeckte Regeln, IP-Überschneidungen“ |
| 10–11 s | `clear` | | |
| 11–13 s | `fgaudit before.conf after.conf` tippen, Enter | | |
| 13–19 s | oben bleiben | „Overall change risk: HIGH“, Policy-Reihenfolge geändert, Management-Zugriff auf port2 entfernt | „Änderungsrisiko vor dem Einspielen“ |
| 19–20 s | `clear` | | |
| 20–22 s | `fgaudit *.log` tippen, Enter | | |
| 22–28 s | ans Ende scrollen | TIMELINE: Config-Änderung, port1 down, 401 SD-WAN-Meldungen in einer Zeile, IPsec und BGP folgen | „Auslöser und Folgekette als Hypothese“ |
| 28–30 s | stehen lassen | | „Open Source, offline, keine Daten verlassen den Rechner“ |

Tipps:

- Bei `fgaudit fw-branch.conf` ist die Ausgabe lang. Für die Aufnahme kannst du
  `fgaudit fw-branch.conf | more` nutzen (Farben gehen dabei verloren) oder nach dem Durchlauf
  mit dem Mausrad nach oben scrollen.
- Für die deutsche Fassung hängst du `--lang de` an jeden Befehl.
- Die Farben erscheinen nur im echten Terminal. In Windows nimm das **Windows-Terminal**, nicht
  die alte Eingabeaufforderung.
- Wer lieber den HTML-Bericht zeigt: `fgaudit --demo --html demo.html`, dann `demo.html` im Browser
  öffnen und langsam durchscrollen. Oben rechts lässt sich zwischen hell und dunkel umschalten.
