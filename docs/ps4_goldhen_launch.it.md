# Note di avvio PS4 / GoldHEN

*Disponibile in: [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

Quando avvii MemDBG dal menu GoldHEN, il payload può essere iniettato in un processo loader che ha già eseguito MemDBG durante un tentativo precedente. Se il payload precedente è crashato o è stato terminato senza pulizia, potrebbe rimanere un file `memdbg.pid` nella root dei dati. Poiché il kernel PS4 riutilizza rapidamente i PID, quel file obsoleto può corrispondere accidentalmente al nuovo processo loader e far credere a MemDBG di essere già in esecuzione.

Nelle build GoldHEN, la root dei dati predefinita è `/data/memdbg`; il file PID
è quindi `/data/memdbg/memdbg.pid`.

## Cosa fa MemDBG all'avvio

1. **Legge il file PID esistente** (`/data/memdbg/memdbg.pid`).
2. **Confronta il PID memorizzato con `getpid()`**.
3. **Se i PID corrispondono, non assume che il daemon sia vivo.** Invece invia una sonda `HELLO` alla porta di debug configurata e attende una risposta `HELLO` MemDBG valida.
   - Se un daemon reale risponde con il magic, la versione e il livello di funzionalità corretti, MemDBG esce con la notifica *"MemDBG is already running"*.
   - Se niente risponde, il file PID viene trattato come **obsoleto**, rimosso e l'avvio continua normalmente.

Questo significa che un file PID obsoleto dopo un crash viene recuperato automaticamente; non è necessario eliminarlo manualmente.

## Perché potresti ancora vedere "MemDBG is already running"

Questo messaggio appare solo quando **un altro daemon MemDBG attivo risponde alla sonda HELLO sulla porta di debug**. Le cause comuni sono:

- MemDBG era già in esecuzione e hai avviato una seconda copia.
- Un payload precedente è sopravvissuto, ma il suo file PID è stato sovrascritto o perso.
- Un altro homebrew o servizio è associato alla stessa porta di debug e risponde con una risposta HELLO compatibile MemDBG (molto improbabile).

## Log

Quando MemDBG termina anticipatamente perché è stato rilevato un daemon attivo, non inizializza intenzionalmente **il proprio file di log**. L'apertura del log disturberebbe i socket o i file del daemon in esecuzione. L'unico feedback è la notifica del sistema operativo.Se sospetti un problema di PID obsoleto, controlla `/data/memdbg/memdbg.pid`.  Se il file contiene un PID che non esiste più, il prossimo avvio lo rimuoverà e partirà normalmente.
