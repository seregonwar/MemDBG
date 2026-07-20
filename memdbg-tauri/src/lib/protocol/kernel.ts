/**
 * Kernel commands (spec §7.5) — gated by MEMDBG_CAP_KERNEL_ACCESS.
 *   KERNEL_BASE   0x0800 — kernel image base + slide
 *   KERNEL_READ   0x0801 — read kernel VA (unframed, no LZ4)
 *   KERNEL_WRITE  0x0802 — write kernel VA
 */
import { BodyReader, BodyWriter } from "./codec";
import { Cmd } from "./constants";
import { getClient } from "./client";

export interface KernelBase {
  base: bigint;
  slide: bigint;
  textBase: bigint;
  size: bigint;
}

export async function kernelBase(): Promise<KernelBase> {
  const res = await getClient().call(Cmd.KERNEL_BASE, new Uint8Array(0));
  const r = new BodyReader(res);
  return { base: r.u64(), slide: r.u64(), textBase: r.u64(), size: r.u64() };
}

export async function kernelRead(address: bigint, length: number): Promise<Uint8Array> {
  const body = new BodyWriter().u64(address).u32(length).u32(0).finish();
  return getClient().call(Cmd.KERNEL_READ, body, 15000);
}

export async function kernelWrite(address: bigint, data: Uint8Array): Promise<void> {
  const body = new BodyWriter().u64(address).u32(data.length).u32(0).bytes(data).finish();
  await getClient().call(Cmd.KERNEL_WRITE, body);
}
