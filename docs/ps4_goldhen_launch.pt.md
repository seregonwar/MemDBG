# Notas de lançamento PS4 / GoldHEN

*Disponível em: [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

Quando você inicia o MemDBG pelo menu do GoldHEN, o payload pode ser injetado em um processo loader que já executou o MemDBG durante uma tentativa anterior. Se o payload anterior travou ou foi encerrado sem limpar, um arquivo `memdbg.pid` pode ser deixado na raiz dos dados. Como o kernel do PS4 reutiliza PIDs rapidamente, esse arquivo obsoleto pode coincidir acidentalmente com o novo processo loader e fazer o MemDBG pensar que já está em execução.

Nas compilações do GoldHEN, a raiz dos dados padrão é `/data/memdbg`;
portanto, o arquivo PID fica em `/data/memdbg/memdbg.pid`.

## O que o MemDBG faz na inicialização

1. **Lê o arquivo PID existente** (`/data/memdbg/memdbg.pid`).
2. **Compara o PID armazenado com `getpid()`**.
3. **Se os PIDs corresponderem, ele não assume que o daemon está vivo.** Em vez disso, envia uma sonda `HELLO` para a porta de debug configurada e aguarda uma resposta `HELLO` válida do MemDBG.
   - Se um daemon real responder com a magia, versão e nível de recurso corretos, o MemDBG sai com a notificação *"MemDBG is already running"*.
   - Se nada responder, o arquivo PID é tratado como **obsoleto**, é removido e a inicialização continua normalmente.

Isso significa que um arquivo PID obsoleto após uma falha é recuperado automaticamente; você não precisa removê-lo manualmente.

## Por que você ainda pode ver "MemDBG is already running"

Esta mensagem aparece apenas quando **outro daemon MemDBG ativo responde à sonda HELLO na porta de debug**. As causas comuns são:

- O MemDBG já estava em execução e você iniciou uma segunda cópia.
- Um payload anterior sobreviveu, mas seu arquivo PID foi sobrescrito ou perdido.
- Outro homebrew ou serviço está vinculado à mesma porta de debug e responde com uma resposta HELLO compatível com MemDBG (muito improvável).

## Logs

Quando o MemDBG sai cedo porque um daemon ativo foi detectado, ele intencionalmente **não inicializa seu próprio arquivo de log**. Abrir o sink de log perturbaria os sockets ou arquivos do daemon em execução. O único feedback é a notificação do SO.

Se você suspeitar de um problema de PID obsoleto, verifique `/data/memdbg/memdbg.pid`.  Se o arquivo contiver um PID que não existe mais, a próxima inicialização o removerá e iniciará normalmente.
