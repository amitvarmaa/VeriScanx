#!/usr/bin/env node
"use strict";
const http = require("http");
const path = require("path");
const { URL } = require("url");

const Router = require("./server/router");
const { serveStatic, sendJSON } = require("./server/http-helpers");
const { HttpError } = require("./server/context");

const router = new Router();
require("./server/routes/auth")(router);
require("./server/routes/scans")(router);
require("./server/routes/officers")(router);
require("./server/routes/blacklist")(router);
require("./server/routes/registry")(router);
require("./server/routes/stats")(router);

const publicDir = path.join(__dirname, "public");
const serveFile = serveStatic(publicDir);

const PORT = process.env.PORT || 4000;

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  if (req.method === "OPTIONS") { res.writeHead(204); res.end(); return; }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = decodeURIComponent(url.pathname);

  if (pathname.startsWith("/api/")) {
    const match = router.match(req.method, pathname);
    if (!match) return sendJSON(res, 404, { error: "Not found" });
    req.query = url.searchParams;
    try {
      await match.handler(req, res, match.params);
    } catch (err) {
      if (err instanceof HttpError) {
        sendJSON(res, err.statusCode, { error: err.message });
      } else {
        console.error(err);
        sendJSON(res, 500, { error: "Internal server error" });
      }
    }
    return;
  }

  const served = serveFile(req, res, pathname);
  if (!served) {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found");
  }
});

server.listen(PORT, () => {
  console.log(`\n  VeriScanx panel running → http://localhost:${PORT}\n`);
});
