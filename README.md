# VeriScanx

AI-powered travel document verification & fraud detection — Smart India Hackathon 2026.

This repo now contains everything for the project in one place:

- **`index.html`** — public pitch/demo site (static, no backend needed). Face liveness check, MRZ/ICAO checksum validation, document-type rules, zero-day anomaly detection, identity graph, mutation detector, AI investigation copilot, downloadable investigation report.
- **`server.js`** — the real officer panel backend (Node.js + SQLite), as a single self-contained file. `public/panel.html` / `public/login.html` are its frontend. See `PANEL-README.md` and `DEPLOY.md` for setup/deploy instructions.

Live demo (public site): (add your GitHub Pages / custom domain URL here once live)
Officer panel (real backend, currently live): https://veriscanx-yi0c.onrender.com

> Note: the live officer panel on Render is currently auto-deployed from the old `aegis-verify-panel` repo. To make Render deploy from this repo instead, reconnect the Render service to `amitvarmaa/VeriScanx` in the Render dashboard (Settings → Build & Deploy → repository).
