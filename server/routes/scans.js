"use strict";
const db = require("../db");
const { computeRisk } = require("../risk");
const { HttpError, getUser } = require("../context");
const { sendJSON, readJSONBody } = require("../http-helpers");
const { checkRegistry } = require("../registry-check");

function serializeScan(row) {
  return {
    id: row.id,
    travelerName: row.traveler_name,
    dob: row.dob,
    docType: row.doc_type,
    docNumber: row.doc_number,
    nationality: row.nationality,
    tamperScore: row.tamper_score,
    blacklistHit: !!row.blacklist_hit,
    duplicateHit: !!row.duplicate_hit,
    mrzValid: !!row.mrz_valid,
    expired: !!row.expired,
    registryStatus: row.registry_status || null,
    riskScore: row.risk_score,
    riskBand: row.risk_band,
    reasons: JSON.parse(row.reasons || "[]"),
    source: row.source,
    officerId: row.officer_id,
    createdAt: row.created_at,
  };
}

module.exports = function registerScanRoutes(router) {
  router.get("/api/scans", async (req, res) => {
    getUser(req);
    const q = req.query;
    const band = q.get("band");
    const docType = q.get("docType");
    const search = (q.get("q") || "").trim();
    const limit = Math.min(100, Math.max(1, parseInt(q.get("limit") || "20", 10) || 20));
    const offset = Math.max(0, parseInt(q.get("offset") || "0", 10) || 0);

    const where = [];
    const params = [];
    if (band) { where.push("risk_band = ?"); params.push(band); }
    if (docType) { where.push("doc_type = ?"); params.push(docType); }
    if (search) { where.push("(traveler_name LIKE ? OR doc_number LIKE ?)"); params.push(`%${search}%`, `%${search}%`); }
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";

    const total = db.prepare(`SELECT COUNT(*) AS n FROM scans ${whereSql}`).get(...params).n;
    const rows = db
      .prepare(`SELECT * FROM scans ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .all(...params, limit, offset);
    sendJSON(res, 200, { items: rows.map(serializeScan), total, limit, offset });
  });

  router.get("/api/scans/:id", async (req, res, params) => {
    getUser(req);
    const row = db.prepare("SELECT * FROM scans WHERE id = ?").get(params.id);
    if (!row) throw new HttpError(404, "Scan not found");
    sendJSON(res, 200, { item: serializeScan(row) });
  });

  router.post("/api/scans", async (req, res) => {
    const user = getUser(req);
    const body = await readJSONBody(req);
    const travelerName = String(body.travelerName || "").trim();
    if (!travelerName) throw new HttpError(400, "travelerName is required");
    const dob = body.dob ? String(body.dob) : null;
    const docType = body.docType ? String(body.docType) : "Passport";
    const docNumber = body.docNumber ? String(body.docNumber).trim() : null;
    const nationality = body.nationality ? String(body.nationality) : null;
    const tamperScore = Math.max(0, Math.min(100, Number(body.tamperScore) || 0));
    const mrzValid = body.mrzValid !== false;
    const expired = !!body.expired;
    const source = body.source ? String(body.source) : "upload";
    // QR/chip decode happens client-side against the actual document image,
    // which the server never sees — trusted like mrzValid/expired above, but
    // constrained to a known set of values so an arbitrary client can't smuggle
    // anything else through into computeRisk.
    const QR_STATUSES = ["match", "mismatch", "found", "absent", "unsupported"];
    const qrStatus = QR_STATUSES.includes(body.qrStatus) ? body.qrStatus : null;

    // Authoritative server-side checks — never trust a client-sent verdict.
    const blacklistHit = docNumber
      ? !!db.prepare("SELECT 1 FROM blacklist WHERE doc_number = ?").get(docNumber)
      : false;
    const duplicateHit = dob
      ? !!db
          .prepare("SELECT 1 FROM scans WHERE lower(traveler_name) = lower(?) AND dob = ? LIMIT 1")
          .get(travelerName, dob)
      : false;
    const registry = checkRegistry(docNumber, travelerName, dob);
    const registryStatus = registry ? registry.status : null;

    const risk = computeRisk({ tamperScore, blacklistHit, duplicateHit, mrzValid, expired, registryStatus, qrStatus });

    const result = db
      .prepare(`
        INSERT INTO scans
          (traveler_name, dob, doc_type, doc_number, nationality, tamper_score,
           blacklist_hit, duplicate_hit, mrz_valid, expired, registry_status, risk_score, risk_band,
           reasons, source, officer_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `)
      .run(
        travelerName, dob, docType, docNumber, nationality, tamperScore,
        blacklistHit ? 1 : 0, duplicateHit ? 1 : 0, mrzValid ? 1 : 0, expired ? 1 : 0, registryStatus,
        risk.score, risk.band, JSON.stringify(risk.reasons), source, user.id
      );

    const row = db.prepare("SELECT * FROM scans WHERE id = ?").get(result.lastInsertRowid);
    // `registry` (with the matched entry + photo, when found) is returned
    // alongside the saved scan for immediate display — it isn't persisted
    // beyond the status string, since the registry table is the source of
    // truth for the entry itself.
    sendJSON(res, 201, { item: serializeScan(row), registry });
  });

  router.delete("/api/scans/:id", async (req, res, params) => {
    const user = getUser(req);
    const { requireAdmin } = require("../context");
    requireAdmin(user);
    const info = db.prepare("DELETE FROM scans WHERE id = ?").run(params.id);
    if (info.changes === 0) throw new HttpError(404, "Scan not found");
    sendJSON(res, 200, { ok: true });
  });
};
