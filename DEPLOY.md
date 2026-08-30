# Deploying VeriScanx panel — live on the internet (Render, free)

This gets you a real, public URL running the actual Node.js + SQLite backend
(same code you've been testing locally) — not a mock.

## What to know before you start

- **Free tier caveats** (important, read this):
  1. **No persistent disk on the free plan.** The database resets to the
     seeded starting data every time the service restarts or redeploys.
     Fine for a demo/pitch; not fine if you need scans to survive forever.
     See "Want real persistence?" below to fix that for a few dollars/month.
  2. **Spins down after 15 minutes of no traffic**, and takes ~30–50 seconds
     to wake back up on the next request. If you're demoing to judges, open
     the URL a minute or two before you go up, so it's already awake.
- You'll need a free **GitHub** account (you almost certainly already have
  one for the SIH submission itself) and a free **Render** account
  (render.com — sign up with GitHub, takes 30 seconds).

## Steps

### 1. Push this project to a GitHub repo

This folder is already a git repo with one commit made. Create a new repo
on GitHub (github.com/new — can be private or public), then push:

```bash
git remote add origin https://github.com/<your-username>/<repo-name>.git
git branch -M main
git push -u origin main
```

### 2. Deploy on Render — one-click Blueprint (easiest)

This repo already includes `render.yaml`, so Render can set everything up
automatically:

1. Go to **render.com/deploy**, sign in with GitHub.
2. Pick **"New" → "Blueprint"**, select the repo you just pushed.
3. Render reads `render.yaml` and shows one service, `veriscanx`,
   on the **Free** plan — click **Apply**.
4. Wait ~1–2 minutes for the first deploy. Render gives you a URL like
   `https://veriscanx.onrender.com` (or whatever subdomain Render actually assigns — grab the real one from the Render dashboard).

That's it — open the URL, log in with the seeded accounts, **and change
both passwords immediately** (Officers page, or Account → Change password).

### 2b. Or set it up manually (if you skip the Blueprint)

New → Web Service → connect your repo → these settings:
- **Runtime:** Node
- **Build command:** (leave blank, or `echo "no build step"`)
- **Start command:** `node server.js`
- **Instance type:** Free
- Add an environment variable **`NODE_VERSION`** = `22.11.0` (this backend
  needs Node ≥22.5 for the built-in SQLite support — Render's default Node
  version is older, so this step matters).

## Want real persistence? (data survives restarts)

Upgrade the service to a **paid instance type** (Starter, ~$7/mo) and add a
**Disk** in the Render dashboard (Settings → Disks → Add Disk):
- Mount path: `/opt/render/project/src/data`
- Size: 1 GB is plenty

`render.yaml` already has this block written out, commented — uncomment it
and push again once you're on a paid plan, and Render will provision it
automatically next deploy.

## Updating the live site later

Any `git push` to `main` auto-redeploys (Blueprint sets `autoDeploy: true`).
