/**
 * Session lifecycle helpers: PING, GOODBYE, GET_EXTENDED_CAPS.
 * (HELLO handshake lives inside {@link MdbgClient}.)
 */
import { BodyReader } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

/**
 * Keep-alive round-trip. Returns the RTT in milliseconds.
 * Spec §4.2 recommends every 5–15 s on idle connections.
 */
export async function ping(): Promise<number> {
  const t0 = performance.now();
  await getClient().call(Cmd.PING, new Uint8Array(0), 4000);
  return performance.now() - t0;
}

/** Ask the daemon to close the connection cleanly. */
export async function goodbye(): Promise<void> {
  try {
    await getClient().call(Cmd.GOODBYE, new Uint8Array(0), 2000);
  } catch {
    /* server may drop the socket immediately — non-fatal */
  }
}

/** Query extended capability bitmap words (feature level 2). */
export async function getExtendedCaps(): Promise<number[]> {
  const res = await getClient().call(Cmd.GET_EXTENDED_CAPS, new Uint8Array(0), 3000);
  const r = new BodyReader(res);
  const count = r.u32();
  const words: number[] = [];
  for (let i = 0; i < count && r.remaining >= 4; i++) words.push(r.u32());
  return words;
}
