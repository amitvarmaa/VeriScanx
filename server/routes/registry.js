"use strict";
const db = require("../db");
const { HttpError, getUser, requireAdmin } = require("../context");
const { sendJSON, readJSONBody } = require("../http-helpers");
const { normalizeDocNum, checkRegistry, serializeEntry } = require("../registry-check");

module.exports = function registerRegistryRoutes(router) {
  router.get("/api/registry", async (req, res) => {
    getUser(req); // any authenticated officer can browse/search
    const q = req.query;
    const search = (q.get("q") || "").trim();
    const limit = Math.min(200, Math.max(1, parseInt(q.get("limit") || "100", 10) || 100));
    const offset = Math.max(0, parseInt(q.get("offset") || "0", 10) || 0);

    const where = [];
    const params = [];
    if (search) {
      where.push("(name LIKE ? OR doc_number LIKE ? OR doc_id LIKE ?)");
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";
    const total = db.prepare(`SELECT COUNT(*) AS n FROM registry ${whereSql}`).get(...params).n;
    const rows = db
      .prepare(`SELECT * FROM registry ${whereSql} ORDER BY name ASC LIMIT ? OFFSET ?`)
      .all(...params, limit, offset);
    sendJSON(res, 200, { items: rows.map(serializeEntry), total, limit, offset });
  });

  router.get("/api/registry/lookup", async (req, res) => {
    getUser(req);
    const q = req.query;
    const result = checkRegistry(q.get("docNumber"), q.get("name"), q.get("dob"));
    sendJSON(res, 200, { result });
  });

  router.get("/api/registry/:id", async (req, res, params) => {
    getUser(req);
    const row = db.prepare("SELECT * FROM registry WHERE id = ?").get(params.id);
    if (!row) throw new HttpError(404, "Registry record not found");
    sendJSON(res, 200, { item: serializeEntry(row) });
  });

  router.post("/api/registry", async (req, res) => {
    const user = getUser(req);
    requireAdmin(user);
    const body = await readJSONBody(req);
    const name = String(body.name || "").trim();
    const docNumber = normalizeDocNum(body.docNumber);
    if (!name) throw new HttpError(400, "name is required");
    if (!docNumber) throw new HttpError(400, "docNumber is required");
    const dob = body.dob ? String(body.dob) : null;
    const gender = body.gender ? String(body.gender) : null;
    const city = body.city ? String(body.city).trim() : null;
    const state = body.state ? String(body.state).trim() : null;
    const photo = body.photo ? String(body.photo) : null;
    const docId = body.docId ? String(body.docId).trim() : "DOC" + Date.now();

    const existing = db.prepare("SELECT 1 FROM registry WHERE doc_number = ?").get(docNumber);
    if (existing) throw new HttpError(409, "A registry record with that document number already exists");

    const result = db
      .prepare(`
        INSERT INTO registry (doc_id, name, dob, gender, city, state, doc_number, photo, added_by)
        VALUES (?,?,?,?,?,?,?,?,?)
      `)
      .run(docId, name, dob, gender, city, state, docNumber, photo, user.id);
    const row = db.prepare("SELECT * FROM registry WHERE id = ?").get(result.lastInsertRowid);
    sendJSON(res, 201, { item: serializeEntry(row) });
  });

  router.delete("/api/registry/:id", async (req, res, params) => {
    const user = getUser(req);
    requireAdmin(user);
    const info = db.prepare("DELETE FROM registry WHERE id = ?").run(params.id);
    if (info.changes === 0) throw new HttpError(404, "Record not found");
    sendJSON(res, 200, { ok: true });
  });
};
