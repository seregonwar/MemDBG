/**
 * Kernel commands (spec §7.5) — gated by MEMDBG_CAP_KERNEL_ACCESS.
 *   KERNEL_BASE   0x0800 — kernel image base
 *   KERNEL_READ   0x0801 — read kernel VA (unframed, no LZ4)
 *   KERNEL_WRITE  0x0802 — write kernel VA
 *
 * All wire layouts match canonical C structs in memdbg_protocol.h.
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

/** memdbg_kernel_base_response_t = 16 bytes: text_base(8) + data_base(8) */
export interface KernelBase {
  textBase: bigint;
  dataBase: bigint;
}

export async function kernelBase(): Promise<KernelBase> {
  const res = await getClient().call(Cmd.KERNEL_BASE, new Uint8Array(0));
  const r = new BodyReader(res);
  return { textBase: r.u64(), dataBase: r.u64() };
}

/** memdbg_kernel_memory_request_t = 16 bytes:
 *  address(8) + length(4) + reserved(4) */
export async function kernelRead(address: bigint, length: number): Promise<Uint8Array> {
  const body = new BodyWriter().u64(address).u32(length).u32(0).finish();
  return getClient().call(Cmd.KERNEL_READ, body, 15000);
}

export async function kernelWrite(address: bigint, data: Uint8Array): Promise<void> {
  const body = new BodyWriter().u64(address).u32(data.length).u32(0).bytes(data).finish();
  await getClient().call(Cmd.KERNEL_WRITE, body);
}
