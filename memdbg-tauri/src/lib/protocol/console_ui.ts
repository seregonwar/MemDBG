/**
 * Console UI commands (spec §7.7) — gated by MEMDBG_CAP_CONSOLE_UI.
 *   CONSOLE_NOTIFY  0x0900 — user-visible toast on the console
 *   CONSOLE_PRINT   0x0901 — print to console kernel log
 *   CONSOLE_REBOOT  0x0902 — soft-reboot the console (mode dependent)
 */
import { BodyWriter, TEXT_ENC } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

async function sendText(cmd: number, text: string, icon = 0): Promise<void> {
  const bytes = TEXT_ENC.encode(text);
  const body = new BodyWriter().u32(icon).u32(bytes.length).bytes(bytes).finish();
  await getClient().call(cmd as never, body);
}

export function consoleNotify(text: string, icon = 0): Promise<void> {
  return sendText(Cmd.CONSOLE_NOTIFY, text, icon);
}

export function consolePrint(text: string): Promise<void> {
  return sendText(Cmd.CONSOLE_PRINT, text, 0);
}

/**
 * `mode` — 0 soft reboot, 1 shutdown, 2 restart-to-safe-mode (platform dependent).
 */
export async function consoleReboot(mode = 0): Promise<void> {
  const body = new BodyWriter().u32(mode).finish();
  await getClient().call(Cmd.CONSOLE_REBOOT, body);
}
