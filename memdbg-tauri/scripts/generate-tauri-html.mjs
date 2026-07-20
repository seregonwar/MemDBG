/**
 * generate-tauri-html.mjs
 *
 * Post-build script for Tauri builds.
 *
 * TanStack Start SSR produces `dist/client/` with hashed JS/CSS bundles
 * but NO index.html (HTML is normally rendered server-side).
 *
 * Tauri needs a static index.html entry point. This script:
 *  1. Scans `dist/client/assets/` for the main JS entry (index-*.js) and CSS.
 *  2. Writes `dist/client/index.html` with the correct hashed references.
 *  3. Copy favicon.ico if missing from dist/client root.
 */
import { readdir, writeFile, copyFile, access } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { constants } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const DIST = join(ROOT, "dist", "client");
const ASSETS = join(DIST, "assets");

async function fileExists(p) {
  try {
    await access(p, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function findAsset(pattern) {
  const files = await readdir(ASSETS);
  const re = new RegExp(pattern);
  const found = files.filter((f) => re.test(f)).sort();
  if (found.length === 0) {
    throw new Error(`No asset matching /${pattern}/ in ${ASSETS}`);
  }
  // Prefer shorter (earlier chunk) if multiple match.
  return `/assets/${found[0]}`;
}

async function main() {
  if (!(await fileExists(ASSETS))) {
    console.error(
      `[generate-tauri-html] ${ASSETS} not found — run 'vite build' first.`,
    );
    process.exit(1);
  }

  const mainJs = await findAsset(/^index-.+\.js$/);
  let mainCss = "";
  try {
    mainCss = await findAsset(/^styles-.+\.css$/);
  } catch {
    // CSS is inlined in the JS bundle (Tailwind v4 + Vite)
    console.log("  (no standalone CSS — inlined in JS bundle)");
  }

  const cssLink = mainCss ? `<link rel="stylesheet" href="${mainCss}" />` : "";

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>MemDBG — Memory Debugger Workspace</title>
    <meta name="description" content="Modern single-screen MemDBG workspace: scan, edit, freeze, monitor process memory and build trainer entries from one interface." />
    <meta property="og:title" content="MemDBG — Memory Debugger Workspace" />
    <meta property="og:description" content="Unified debugger UI for MemDBG: scanner, hex editor, freeze/lock, live telemetry and trainer." />
    <meta property="og:type" content="website" />
    <meta name="twitter:card" content="summary_large_image" />
    <link rel="icon" type="image/x-icon" href="/favicon.ico" />
    ${cssLink}
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="${mainJs}"></script>
  </body>
</html>
`;

  const outPath = join(DIST, "index.html");
  await writeFile(outPath, html, "utf-8");
  console.log(`[generate-tauri-html] wrote ${outPath}`);
  console.log(`  main JS : ${mainJs}`);
  console.log(`  main CSS: ${mainCss}`);

  // Ensure favicon.ico is at the client root (Vite copies it from public/).
  const faviconSrc = join(ROOT, "public", "favicon.ico");
  const faviconDst = join(DIST, "favicon.ico");
  if ((await fileExists(faviconSrc)) && !(await fileExists(faviconDst))) {
    await copyFile(faviconSrc, faviconDst);
    console.log(`  copied favicon.ico`);
  }
}

main().catch((err) => {
  console.error(`[generate-tauri-html] ${err.message}`);
  process.exit(1);
});
