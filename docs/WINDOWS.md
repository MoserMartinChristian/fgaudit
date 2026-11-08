# fgaudit unter Windows: Anleitung für Einsteiger

Diese Anleitung führt dich von einem Windows-Rechner ohne Python bis zum ersten Ergebnis. Du
brauchst etwa 10 Minuten. fgaudit arbeitet komplett offline: Es verbindet sich nicht mit der
FortiGate und schickt nichts ins Internet.

## 1. Python installieren

1. Öffne <https://www.python.org/downloads/windows/> und lade den aktuellen **Python 3 Windows
   installer (64-bit)** herunter. Version 3.10 oder neuer reicht.
2. Starte die heruntergeladene Datei.
3. **Wichtig:** Setz unten im ersten Fenster den Haken bei **„Add python.exe to PATH“**.
4. Klick auf **Install Now** und warte, bis „Setup was successful“ erscheint. Klick auf **Close**.

Alternativ geht es über den Microsoft Store: Such dort nach „Python 3.13“ und klick auf
**Herunterladen**.

## 2. Ein Terminal öffnen

1. Drück die **Windows-Taste**, tipp `powershell` und drück **Enter**.
2. Prüf, ob Python da ist:

   ```powershell
   py --version
   ```

   Es sollte etwas wie `Python 3.13.1` erscheinen. Kommt eine Fehlermeldung, schließ PowerShell,
   öffne sie neu und versuch es noch einmal. Hilft das nicht, installier Python erneut und achte auf
   den Haken aus Schritt 1.3.

## 3. fgaudit installieren

**Wenn fgaudit schon auf PyPI veröffentlicht ist:**

```powershell
py -m pip install fgaudit
```

**Solange es noch nicht veröffentlicht ist** (du hast den Ordner `fgaudit` oder die Datei
`fgaudit.zip`):

1. Entpack `fgaudit.zip`, zum Beispiel nach `C:\Tools\fgaudit`.
2. Installier es aus diesem Ordner:

   ```powershell
   py -m pip install C:\Tools\fgaudit
   ```

Am Ende steht `Successfully installed fgaudit-1.0.0`.

## 4. Erster Test mit Demo-Daten

```powershell
py -m fgaudit --demo
```

fgaudit zeigt jetzt alle vier Prüfungen mit erfundenen Daten. Du brauchst dafür keine echte Datei.
Auf Deutsch geht es so:

```powershell
py -m fgaudit --demo --lang de
```

Hinweis: Statt `py -m fgaudit` kannst du meist auch kurz `fgaudit` schreiben. Wenn Windows dann
„Der Befehl wurde nicht gefunden“ meldet, liegt der Programmordner von Python nicht im PATH. `py -m
fgaudit` funktioniert immer.

## 5. Das Fenster (ohne Kommandozeile)

Wenn du lieber mit der Maus arbeitest, öffne das Fenster:

```powershell
py -m fgaudit --gui --lang de
```

Alternativ tippst du `fgaudit-gui --lang de`. Im Fenster:

1. Klick auf **Dateien hinzufügen…** und wähl ein Backup, zwei Backups oder Logdateien aus. Unter
   der Liste steht, welche Prüfung laufen wird. Bei zwei Backups muss das ältere oben stehen. Mit
   **Hoch** und **Runter** tauschst du die Reihenfolge.
2. Stell bei **Sprache** `de` ein. Optional: VDOM eintragen oder **Namen und IPs anonymisieren**
   anhaken.
3. Klick auf **Prüfen**. Ohne eigene Dateien zeigt **Demo mit erfundenen Daten**, wie es aussieht.
4. Klick einen Befund an, um unten die Erklärung und den nächsten Schritt zu sehen. Bei Logs
   zeigt der Reiter **Timeline** die Ereignisse.
5. Mit **HTML-Bericht speichern…** bekommst du denselben Bericht wie mit `--html`.

**Verknüpfung auf dem Desktop:** Rechtsklick auf den Desktop → **Neu → Verknüpfung**. Als Speicherort
gibst du `pyw -m fgaudit.gui --lang de` ein, als Namen `fgaudit`. Ein Doppelklick öffnet dann das Fenster
ohne schwarzes Konsolenfenster.

Alle folgenden Schritte gehen genauso im Fenster. Die Befehle zeigen die Variante für die
Kommandozeile.

## 6. Eine eigene Sicherung prüfen

### 6.1 Unverschlüsselte Sicherung von der FortiGate holen

1. Melde dich in der Weboberfläche der FortiGate an.
2. Klick oben rechts auf deinen Benutzernamen und dann auf **Configuration → Backup**.
3. Lass **Encryption** ausgeschaltet. fgaudit kann verschlüsselte Sicherungen nicht lesen und
   meldet das dann auch.
4. Klick auf **OK**. Die Datei landet im Download-Ordner, zum Beispiel
   `FGT60F_7-4_1234_202611061200.conf`.

Die Bezeichnungen im Menü können je nach FortiOS-Version leicht abweichen.

**Achtung:** Eine unverschlüsselte Sicherung enthält deine ganze Konfiguration. Die Passwörter darin
sind zwar verschlüsselt (`ENC …`), trotzdem gehört die Datei nicht in E-Mails, Cloud-Ordner oder
Git-Repos. Lösch sie, wenn du fertig bist.

### 6.2 Prüfen

Wechsel in den Download-Ordner und starte die Prüfung:

```powershell
cd $HOME\Downloads
py -m fgaudit FGT60F_7-4_1234_202611061200.conf --lang de
```

Tipp: Tipp `py -m fgaudit FGT` und drück die **Tab-Taste**. PowerShell ergänzt den Dateinamen.

Als HTML-Bericht, den du im Browser öffnen kannst:

```powershell
py -m fgaudit FGT60F_7-4_1234_202611061200.conf --lang de --html bericht.html
start bericht.html
```

### 6.3 Zwei Sicherungen vergleichen

Mach vor einer Änderung eine Sicherung und danach noch eine. Dann:

```powershell
py -m fgaudit vorher.conf nachher.conf --lang de
```

Die erste Datei ist immer der alte Stand, die zweite der neue.

### 6.4 Logs auswerten

Exportier die Ereignis-Logs (zum Beispiel unter **Log & Report → System Events** über
**Download**, oder aus FortiAnalyzer) als Textdatei. Dann:

```powershell
py -m fgaudit fw1.log fw2.log --lang de
```

Du kannst auch alle Logs eines Ordners auf einmal angeben: `py -m fgaudit *.log --lang de`.

## 7. Ergebnisse weitergeben

Wenn du einen Bericht mit Kollegen oder im Internet teilen willst, nimm `--anonymize`. Dann ersetzt
fgaudit IP-Adressen, Hostnamen, Benutzernamen und Objektnamen:

```powershell
py -m fgaudit sicherung.conf --lang de --anonymize --html bericht-anonym.html
```

Schau dir den Bericht trotzdem an, bevor du ihn teilst.

## 8. Was die Ergebnisse bedeuten

- **[HIGH]**: Sollte zeitnah geklärt werden, zum Beispiel eine Regel, die nie greift und deren
  Verkehr eine andere Aktion bekommt.
- **[MEDIUM]** und **[LOW]**: Aufräumen und prüfen, wenn Zeit ist.
- **[INFO]**: Hinweise. „Nicht sicher prüfbar“ heißt, dass die Datei allein nicht reicht, um eine
  sichere Aussage zu machen (zum Beispiel bei FQDN-Adressen). Das ist kein Fehler.

fgaudit ändert nichts an der FortiGate. Prüf vor jedem Löschen einer Regel die Trefferzahl (Hit
Count) auf dem Gerät.

## 9. Wenn etwas nicht klappt

| Meldung | Lösung |
|---|---|
| `py` wird nicht erkannt | Python neu installieren, Haken bei „Add python.exe to PATH“ setzen, PowerShell neu öffnen. |
| `fgaudit` wird nicht erkannt | `py -m fgaudit` statt `fgaudit` verwenden. |
| „… encrypted backup …“ bzw. „… verschlüsselten Backup …“ | Sicherung ohne Verschlüsselung neu erstellen (Schritt 6.1). |
| „cannot be read (No such file or directory)“ | Mit `dir` prüfen, ob du im richtigen Ordner bist und der Name stimmt. |
| Das Fenster öffnet sich nicht | In PowerShell `py -m fgaudit --gui` eingeben und die Meldung lesen. Python von python.org bringt alles Nötige mit. |
| Seltsame Zeichen statt Farben | Das neue **Windows-Terminal** verwenden (im Microsoft Store kostenlos), oder `$env:NO_COLOR=1` setzen. |

## 10. Deinstallieren

```powershell
py -m pip uninstall fgaudit
```
