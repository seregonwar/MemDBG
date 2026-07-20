# PS4 / GoldHEN – Startnotizen

*Verfügbar in: [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

Wenn Sie MemDBG über das GoldHEN-Menü starten, kann der Payload in einen Loader-Prozess injiziert werden, der bei einem früheren Versuch bereits MemDBG ausgeführt hat. Wenn der vorherige Payload abgestürzt ist oder ohne Aufräumen beendet wurde, kann im Datenstammverzeichnis eine `memdbg.pid`-Datei zurückbleiben. Da der PS4-Kernel PIDs schnell wiederverwendet, kann diese veraltete Datei versehentlich mit dem neuen Loader-Prozess übereinstimmen und MemDBG glauben machen, es laufe bereits.

Bei GoldHEN-Builds ist das Standard-Datenstammverzeichnis `/data/memdbg`; die
PID-Datei liegt also unter `/data/memdbg/memdbg.pid`.

## Was MemDBG beim Start tut

1. **Er liest die vorhandene PID-Datei** (`/data/memdbg/memdbg.pid`).
2. **Er vergleicht die gespeicherte PID mit `getpid()`**.
3. **Wenn die PIDs übereinstimmen, geht er nicht automatisch davon aus, dass der Daemon läuft.** Stattdessen sendet er einen `HELLO`-Probe an den konfigurierten Debug-Port und wartet auf eine gültige MemDBG-`HELLO`-Antwort.
   - Wenn ein echter Daemon mit der richtigen Magic, Version und Feature-Level antwortet, beendet sich MemDBG mit der Benachrichtigung *"MemDBG is already running"*.
   - Wenn nichts antwortet, wird die PID-Datei als **veraltet** behandelt, entfernt und der Start wird normal fortgesetzt.

Das bedeutet, dass eine veraltete PID-Datei nach einem Absturz automatisch wiederhergestellt wird; Sie müssen sie nicht manuell löschen.

## Warum Sie möglicherweise immer noch "MemDBG is already running" sehen

Diese Meldung erscheint nur, wenn **ein anderer live MemDBG-Daemon auf die HELLO-Probe am Debug-Port antwortet**. Häufige Ursachen sind:

- MemDBG lief bereits und Sie haben eine zweite Instanz gestartet.
- Ein vorheriger Payload hat überlebt, aber seine PID-Datei wurde überschrieben oder verloren.
- Eine andere Homebrew oder ein anderer Dienst ist an denselben Debug-Port gebunden und antwortet mit einer gültigen MemDBG-kompatiblen HELLO-Antwort (sehr unwahrscheinlich).

## Logs

Wenn MemDBG früh beendet, weil ein live Daemon erkannt wurde, initialisiert er absichtlich **keine eigene Log-Datei**. Das Öffnen des Log-Sinks würde Sockets oder Dateien des laufenden Daemons stören. Das einzige Feedback ist die OS-Benachrichtigung.Wenn Sie eine veraltete PID vermuten, prüfen Sie `/data/memdbg/memdbg.pid`.  Wenn die Datei eine PID enthält, die nicht mehr existiert, wird sie beim nächsten Start entfernt und normal gestartet.
