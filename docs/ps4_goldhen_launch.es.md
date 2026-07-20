# Notas de lanzamiento de PS4 / GoldHEN

*Disponible en: [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

Cuando inicias MemDBG desde el menú de GoldHEN, el payload puede inyectarse en un proceso loader que ya ejecutó MemDBG durante un intento anterior. Si el payload anterior falló o fue terminado sin limpiar, puede quedar un archivo `memdbg.pid` en la raíz de datos. Como el kernel de PS4 reutiliza los PID rápidamente, ese archivo obsoleto puede coincidir accidentalmente con el nuevo proceso loader y hacer que MemDBG piense que ya está en ejecución.

En las compilaciones de GoldHEN, la raíz de datos predeterminada es `/data/memdbg`;
por tanto, el archivo PID está en `/data/memdbg/memdbg.pid`.

## Qué hace MemDBG al iniciarse

1. **Lee el archivo PID existente** (`/data/memdbg/memdbg.pid`).
2. **Compara el PID almacenado con `getpid()`**.
3. **Si los PID coinciden, no asume que el daemon está vivo.** En su lugar, envía una sonda `HELLO` al puerto de depuración configurado y espera una respuesta `HELLO` válida de MemDBG.
   - Si un daemon real responde con la magia, versión y nivel de características correctos, MemDBG sale con la notificación *"MemDBG is already running"*.
   - Si nada responde, el archivo PID se trata como **obsoleto**, se elimina y el inicio continúa normalmente.

Esto significa que un archivo PID obsoleto después de un fallo se recupera automáticamente; no necesitas eliminarlo manualmente.

## Por qué aún puedes ver "MemDBG is already running"

Este mensaje aparece solo cuando **otro daemon MemDBG vivo responde a la sonda HELLO en el puerto de depuración**. Las causas comunes son:

- MemDBG ya estaba en ejecución y lanzaste una segunda copia.
- Un payload anterior sobrevivió, pero su archivo PID fue sobrescrito o perdido.
- Otro homebrew o servicio está vinculado al mismo puerto de depuración y responde con una respuesta HELLO compatible con MemDBG (muy poco probable).

## Logs

Cuando MemDBG se cierra temprano porque se detectó un daemon vivo, **no inicializa su propio archivo de registro** intencionalmente. Abrir el registro perturbaría los sockets o archivos del daemon en ejecución. La única retroalimentación es la notificación del SO.Si sospechas de un problema de PID obsoleto, revisa `/data/memdbg/memdbg.pid`.  Si el archivo contiene un PID que ya no existe, el siguiente inicio lo eliminará y continuará normalmente.
