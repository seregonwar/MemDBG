# MemDBG GitHub Pages guide

Static user guide for MemDBG, built for GitHub Pages.

## Structure

```
github-pages/
├── index.html          ← Shell: sidebar + fetch/marked.js loader
├── styles.css          ← Dark theme + markdown content styling
├── docs/               ← Markdown content files (one per section)
│   ├── quick-start.md
│   ├── setup.md
│   ├── frontend.md
│   ├── workflow.md
│   ├── memory.md
│   ├── dump.md
│   ├── scanner.md
│   ├── trainer.md
│   ├── batchcode.md
│   ├── troubleshooting.md
│   ├── best-practices.md
│   ├── ports.md
│   └── credits.md
└── README.md
```

## How it works

- **index.html** is a single-page shell with a fixed sidebar navigation and content sections.
- Each section loads its content from a **separate `.md` file** in `docs/` via `fetch()`.
- **marked.js** (CDN) converts the markdown to HTML client-side.
- A scroll-spy highlights the active sidebar link.
- Content is authored in **pure markdown** — no HTML needed except the shell.

## Deploying

Publish the contents of this folder as the GitHub Pages site root. If using GitHub Actions, set the upload path to `github-pages/`.

## Editing content

Edit any `.md` file in `docs/`. To add a new section:

1. Create a new `.md` file in `docs/`.
2. Add a `<section>` element in `index.html` with `id` and `data-md` attributes.
3. Add the corresponding nav link in the sidebar.
