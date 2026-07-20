# PS4 / GoldHEN 실행 안내

*지원 언어: [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

GoldHEN 메뉴에서 MemDBG를 실행하면, 이전 시도에서 이미 MemDBG를 실행한 loader 프로세스에 페이로드가 주입될 수 있습니다. 이전 페이로드가 충돌하거나 정리 없이 종료된 경우 데이터 루트에 `memdbg.pid` 파일이 남아 있을 수 있습니다. PS4 커널은 PID를 빠르게 재사용하므로, 그 오래된 파일이 새로운 loader 프로세스와 우연히 일치하여 MemDBG가 이미 실행 중이라고 인식할 수 있습니다.

GoldHEN 빌드에서는 기본 데이터 루트가 `/data/memdbg`이므로 PID 파일은
`/data/memdbg/memdbg.pid`입니다.

## MemDBG 시작 시 동작

1. **기존 PID 파일을 읽습니다** (`/data/memdbg/memdbg.pid`).
2. **저장된 PID와 `getpid()`를 비교합니다**.
3. **PID가 일치하더라도 데몬이 살아 있다고 가정하지 않습니다.** 대신 설정된 디버그 포트로 `HELLO` 프로브를 보내 유효한 MemDBG `HELLO` 응답을 기다립니다.
   - 실제 데몬이 올바른 매직, 버전, 기능 레벨로 응답하면 MemDBG는 *"MemDBG is already running"* 알림과 함께 종료됩니다.
   - 아무것도 응답하지 않으면 PID 파일은 **오래된 것**으로 처리되어 제거되고 시작이 정상적으로 계속됩니다.

이는 충돌 후 오래된 PID 파일이 자동으로 복구됨을 의미하며, 수동으로 삭제할 필요가 없습니다.

## "MemDBG is already running"이 여전히 표시되는 이유

이 메시지는 **다른 살아 있는 MemDBG 데몬이 디버그 포트의 HELLO 프로브에 응답할 때**만 표시됩니다. 일반적인 원인은 다음과 같습니다.

- MemDBG가 이미 실행 중이었고 두 번째 복사본을 실행했다.
- 이전 페이로드가 살아남았지만 PID 파일이 덮어쓰기되거나 손실되었다.
- 다른 homebrew나 서비스가 동일한 디버그 포트에 바인딩되어 MemDBG 호환 HELLO 응답을 반환하고 있다(매우 드물다).

## 로그

MemDBG가 살아 있는 데몬을 감지하여 일찍 종료할 때, 의도적으로 **자체 로그 파일을 초기화하지 않습니다**. 로그 싱크를 열면 실행 중인 데몬이 소유한 소켓이나 파일이 방해받습니다. 유일한 피드백은 OS 알림입니다.오래된 PID 문제가 의심되면 `/data/memdbg/memdbg.pid`를 확인하세요.  파일에 더 이상 존재하지 않는 PID가 포함된 경우, 다음 시작 시 제거되고 정상적으로 시작됩니다.
