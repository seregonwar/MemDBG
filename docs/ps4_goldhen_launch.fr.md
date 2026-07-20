# Notes de lancement PS4 / GoldHEN

*Disponible en : [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

Lorsque vous lancez MemDBG depuis le menu GoldHEN, le payload peut être injecté dans un processus loader qui a déjà exécuté MemDBG lors d'une tentative antérieure. Si le payload précédent a crashé ou a été tué sans nettoyage, un fichier `memdbg.pid` peut rester dans la racine des données. Comme le noyau PS4 réutilise rapidement les PID, ce fichier obsolète peut correspondre accidentellement au nouveau processus loader et faire croire à MemDBG qu'il est déjà en cours d'exécution.

Sur les builds GoldHEN, la racine des données par défaut est `/data/memdbg`;
le fichier PID est donc `/data/memdbg/memdbg.pid`.

## Ce que fait MemDBG au lancement

1. **Il lit le fichier PID existant** (`/data/memdbg/memdbg.pid`).
2. **Il compare le PID stocké avec `getpid()`**.
3. **Si les PID correspondent, il ne suppose pas que le daemon est vivant.** Au lieu de cela, il envoie une sonde `HELLO` au port de débogage configuré et attend une réponse `HELLO` MemDBG valide.
   - Si un vrai daemon répond avec la magie, la version et le niveau de fonctionnalités corrects, MemDBG quitte avec la notification *"MemDBG is already running"*.
   - Si rien ne répond, le fichier PID est traité comme **obsolète**, est supprimé et le démarrage continue normalement.

Cela signifie qu'un fichier PID obsolète après un crash est récupéré automatiquement ; vous n'avez pas besoin de le supprimer manuellement.

## Pourquoi vous pourriez toujours voir "MemDBG is already running"

Ce message n'apparaît que lorsque **un autre daemon MemDBG actif répond à la sonde HELLO sur le port de débogage**. Les causes courantes sont :

- MemDBG était déjà en cours d'exécution et vous avez lancé une seconde copie.
- Un payload précédent a survécu, mais son fichier PID a été écrasé ou perdu.
- Un autre homebrew ou service est lié au même port de débogage et répond avec une réponse HELLO compatible MemDBG (très peu probable).

## Logs

Lorsque MemDBG quitte prématurément parce qu'un daemon actif a été détecté, il n'initialise intentionnellement **pas son propre fichier journal**. L'ouverture du journal perturberait les sockets ou fichiers appartenant au daemon en cours d'exécution. Le seul retour est la notification du système d'exploitation.Si vous suspectez un problème de PID obsolète, vérifiez `/data/memdbg/memdbg.pid`.  Si le fichier contient un PID qui n'existe plus, le prochain lancement le supprimera et démarrera normalement.
