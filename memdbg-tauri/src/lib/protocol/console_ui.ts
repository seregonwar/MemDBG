/**
 * Console UI commands (spec §7.7) — gated by MEMDBG_CAP_CONSOLE_UI.
 *   CONSOLE_NOTIFY  0x0900 — user-visible toast on the console
 *   CONSOLE_PRINT   0x0901 — print to console kernel log
 *   CONSOLE_REBOOT  0x0902 — soft-reboot the console (mode dependent)
 *
 * Wire format: memdbg_console_text_request_t (8 bytes: length + reserved)
 * followed by UTF-8 text.
 */
import { BodyWriter, TEXT_ENC } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

async function sendText(cmd: number, text: string): Promise<void> {
  const bytes = TEXT_ENC.encode(text);
  const body = new BodyWriter().u32(bytes.length).u32(0).bytes(bytes).finish();
  await getClient().call(cmd as never, body);
}

export function consoleNotify(text: string): Promise<void> {
  return sendText(Cmd.CONSOLE_NOTIFY, text);
}

export function consolePrint(text: string): Promise<void> {
  return sendText(Cmd.CONSOLE_PRINT, text);
}

/**
 * `mode` — 0 soft reboot, 1 shutdown, 2 restart-to-safe-mode (platform dependent).
 */
export async function consoleReboot(mode = 0): Promise<void> {
  const body = new BodyWriter().u32(mode).finish();
  await getClient().call(Cmd.CONSOLE_REBOOT, body);
}
