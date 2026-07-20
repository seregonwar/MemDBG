# PS4 / GoldHEN 起動時の注意事項

*対応言語: [English](ps4_goldhen_launch.en.md) · [Deutsch](ps4_goldhen_launch.de.md) · [Español](ps4_goldhen_launch.es.md) · [Français](ps4_goldhen_launch.fr.md) · [Italiano](ps4_goldhen_launch.it.md) · [日本語](ps4_goldhen_launch.ja.md) · [한국어](ps4_goldhen_launch.ko.md) · [Português](ps4_goldhen_launch.pt.md) · [Русский](ps4_goldhen_launch.ru.md)*

GoldHEN メニューから MemDBG を起動すると、ペイロードは以前の試行で MemDBG を実行した loader プロセスに注入される可能性があります。前回のペイロードがクラッシュしたり、クリーンアップされずに終了したりすると、データルートに `memdbg.pid` ファイルが残ることがあります。PS4 カーネルは PID を迅速に再利用するため、その古いファイルが新しい loader プロセスと偶然一致し、MemDBG が既に実行中であると誤認識することがあります。

GoldHEN ビルドでは、デフォルトのデータルートは `/data/memdbg` です。したがって、
PID ファイルは `/data/memdbg/memdbg.pid` になります。

## MemDBG の起動時の動作

1. **既存の PID ファイルを読み込みます** (`/data/memdbg/memdbg.pid`)。
2. **保存されている PID と `getpid()` を比較します**。
3. **PID が一致しても、デーモンが生存していると自動的には判断しません。** 代わりに、設定されたデバッグポートへ `HELLO` プローブを送信し、有効な MemDBG `HELLO` 応答を待ちます。
   - 実際のデーモンが正しいマジック、バージョン、機能レベルで応答した場合、MemDBG は *"MemDBG is already running"* の通知とともに終了します。
   - 何も応答しない場合、PID ファイルは **古いもの** として扱われ、削除され、起動は正常に続行されます。

これは、クラッシュ後の古い PID ファイルが自動的に回復することを意味します。手動で削除する必要はありません。

## 「MemDBG is already running」が表示される理由

このメッセージは、**別の生存中の MemDBG デーモンがデバッグポート上の HELLO プローブに応答した場合** にのみ表示されます。一般的な原因は以下の通りです。

- MemDBG が既に実行中で、2 番目のコピーを起動した。
- 前回のペイロードは生存していたが、PID ファイルが上書きまたは紛失した。
- 別の homebrew やサービスが同じデバッグポートにバインドされ、MemDBG 互換の HELLO 応答を返している（非常に稀）。

## ログ

MemDBG が生存中のデーモンを検出して早期に終了する場合、意図的に **独自のログファイルを初期化しません**。ログシンクを開くと、実行中のデーモンが所有するソケットやファイルが妨害されるためです。唯一のフィードバックは OS の通知です。古い PID が原因だと疑わしい場合は、`/data/memdbg/memdbg.pid` を確認してください。  ファイルに含まれる PID が存在しない場合、次回の起動時に削除され、正常に起動します。
