/**
 * Persistent storage for consoles, preferences, and session state.
 *
 * Uses Tauri fs plugin when running inside the desktop shell, falling back
 * to localStorage in the browser (development). All values are JSON. Files
 * live in the app's config dir (`~/Library/Application Support/MemDBG` on
 * macOS, `%APPDATA%/MemDBG` on Windows, `~/.config/MemDBG` on Linux).
 */
import { isTauriRuntime } from "./protocol/transport";

const APP_DIR = "MemDBG";

async function tauriFs() {
  // Lazy import so browser bundles don't try to resolve the plugin.
  const [{ BaseDirectory, exists, mkdir, readTextFile, writeTextFile }, { join }] =
    await Promise.all([
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      import(/* @vite-ignore */ "@tauri-apps/plugin-fs") as Promise<any>,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      import(/* @vite-ignore */ "@tauri-apps/api/path") as Promise<any>,
    ]);
  return { BaseDirectory, exists, mkdir, readTextFile, writeTextFile, join };
}

async function ensureDir(): Promise<void> {
  if (!isTauriRuntime()) return;
  const { BaseDirectory, exists, mkdir } = await tauriFs();
  const dir = APP_DIR;
  const ok = await exists(dir, { baseDir: BaseDirectory.AppConfig });
  if (!ok) await mkdir(dir, { baseDir: BaseDirectory.AppConfig, recursive: true });
}

function lsKey(name: string): string {
  return `mdbg.store.${name}`;
}

export async function readJson<T>(name: string, fallback: T): Promise<T> {
  try {
    if (isTauriRuntime()) {
      await ensureDir();
      const { BaseDirectory, exists, readTextFile } = await tauriFs();
      const path = `${APP_DIR}/${name}.json`;
      const ok = await exists(path, { baseDir: BaseDirectory.AppConfig });
      if (!ok) return fallback;
      const text = await readTextFile(path, { baseDir: BaseDirectory.AppConfig });
      return JSON.parse(text) as T;
    }
    if (typeof window === "undefined") return fallback;
    const raw = window.localStorage.getItem(lsKey(name));
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch (e) {
    console.warn(`storage: read ${name} failed`, e);
    return fallback;
  }
}

export async function writeJson<T>(name: string, value: T): Promise<void> {
  try {
    const json = JSON.stringify(value, null, 2);
    if (isTauriRuntime()) {
      await ensureDir();
      const { BaseDirectory, writeTextFile } = await tauriFs();
      await writeTextFile(`${APP_DIR}/${name}.json`, json, { baseDir: BaseDirectory.AppConfig });
      return;
    }
    if (typeof window === "undefined") return;
    window.localStorage.setItem(lsKey(name), json);
  } catch (e) {
    console.warn(`storage: write ${name} failed`, e);
  }
}

/** Debounced writer factory: coalesces bursts of updates into a single write. */
export function debouncedWriter<T>(name: string, ms = 500): (value: T) => void {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let pending: T;
  return (value: T) => {
    pending = value;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      void writeJson(name, pending);
    }, ms);
  };
}
