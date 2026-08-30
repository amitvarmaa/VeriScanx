# VeriScanx — Officer Panel (backend)

A real backend for the VeriScanx SIH 2026 prototype: login, a SQLite
database, and REST API behind the officer/admin dashboard, the verify-and-scan
flow, and blacklist/officer management.

**Zero npm dependencies.** It's built entirely on Node's built-in modules
(`http`, `crypto`, `node:sqlite`) — there is nothing to `npm install`. That
also means it needs a fairly recent Node version (see below).

## Requirements

- **Node.js 22.5 or newer** (uses the built-in `node:sqlite` module — no
  native compiling, no external database to install). Check your version
  with `node -v`; if it's older, install a current Node from
  [nodejs.org](https://nodejs.org) or with `nvm install 22`.

## Run it

```bash
node --experimental-sqlite server.js
```

Then open **http://localhost:4000**.

On first run it creates `data/veriscanx.db` and prints two seeded logins:

| Username    | Password       | Role    |
|-------------|----------------|---------|
| `admin`     | `VeriScanx@2026`   | admin   |
| `officer1`  | `Officer@2026` | officer |

**Change both passwords immediately** (Account → Change password once signed
in, or from the Officers page as admin) — these are public demo credentials
right now.

Use `PORT=5000 node --experimental-sqlite server.js` to run on a different port.

## What's in the panel

- **Dashboard** — live stat tiles and charts computed from the database
  (today's scan count, flag rate, 14-day volume, risk-band breakdown, top
  flag reasons).
- **Verify & scan** — upload a document (or use the two built-in fictional
  specimen documents) and it runs through the same pipeline as the public
  demo site: real client-side error-level-analysis tamper detection, plus
  simulated OCR/MRZ extraction. The result is POSTed to the backend, which
  authoritatively checks the live blacklist table and searches all prior
  scans for a duplicate identity, computes the risk score server-side (never
  trusting a client-sent score), and persists the record.
- **Scans log** — every saved scan, searchable and filterable by risk band
  and document type.
- **Officers** *(admin only)* — create/edit/deactivate/delete officer and
  admin accounts.
- **Blacklist** *(admin only)* — add or remove document numbers from the
  live watchlist that Verify & Scan checks against.

## How it's built

- `server.js` — plain `node:http` server + a small hand-rolled router (no
  Express). Serves the API under `/api/*` and the static panel under `/`.
- `server/db.js` — schema + seed data, using `node:sqlite`
  (`data/veriscanx.db`).
- `server/auth.js` — password hashing with `crypto.scryptSync`, and
  HMAC-SHA256 signed session tokens (a minimal JWT — no `jsonwebtoken`
  dependency).
- `server/risk.js` — the weighted risk-scoring formula, shared conceptually
  with the public demo site's client-side version, but this copy is the
  authoritative one the API actually uses.
- `server/routes/*.js` — REST endpoints for auth, scans, officers, blacklist,
  and dashboard stats.
- `public/` — the panel frontend: plain HTML/CSS/JS, no build step, styled to
  match the public VeriScanx site (same fonts/colors).

## Moving to a "real" production stack later

This is intentionally dependency-free so it's easy to run anywhere for a
hackathon demo. For a later round or an actual deployment, the natural
upgrade path (without changing the API shape much) is:

- Swap `node:sqlite` for PostgreSQL (the schema in `server/db.js` is plain
  SQL and translates directly).
- Swap the hand-rolled router for Express or Fastify if the route table
  grows.
- Put it behind HTTPS (a reverse proxy like Caddy or nginx is the easiest
  route) — right now it's plain HTTP, fine for `localhost` or a private
  demo, not for handling real travel documents in production.
- Move the JWT secret and seeded passwords into real environment-variable
  secrets management.

## Deploying so it's reachable outside your laptop

Because this needs a live Node process (unlike the static public site), it
needs a host that runs Node continuously — a static host like GitHub Pages
won't work for this piece. Free/simple options: **Render**, **Railway**, or
a small VPS. All of them just need: `node.js 22+ buildpack`, start command
`node --experimental-sqlite server.js`, and a persistent disk mounted at `data/` if you want the
database to survive redeploys.
