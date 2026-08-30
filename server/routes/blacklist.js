"use strict";
const db = require("../db");
const { HttpError, getUser, requireAdmin } = require("../context");
const { sendJSON, readJSONBody } = require("../http-helpers");

function serialize(row) {
  return { id: row.id, docNumber: row.doc_number, reason: row.reason, addedBy: row.added_by, createdAt: row.created_at };
}

module.exports = function registerBlacklistRoutes(router) {
  router.get("/api/blacklist", async (req, res) => {
    getUser(req); // any authenticated officer can view
    const rows = db.prepare("SELECT * FROM blacklist ORDER BY created_at DESC").all();
    sendJSON(res, 200, { items: rows.map(serialize) });
  });

  router.post("/api/blacklist", async (req, res) => {
    const user = getUser(req);
    requireAdmin(user);
    const body = await readJSONBody(req);
    const docNumber = String(body.docNumber || "").trim();
    const reason = body.reason ? String(body.reason).trim() : null;
    if (!docNumber) throw new HttpError(400, "docNumber is required");
    const existing = db.prepare("SELECT 1 FROM blacklist WHERE doc_number = ?").get(docNumber);
    if (existing) throw new HttpError(409, "That document number is already on the list");
    const result = db
      .prepare("INSERT INTO blacklist (doc_number, reason, added_by) VALUES (?,?,?)")
      .run(docNumber, reason, user.id);
    const row = db.prepare("SELECT * FROM blacklist WHERE id = ?").get(result.lastInsertRowid);
    sendJSON(res, 201, { item: serialize(row) });
  });

  router.delete("/api/blacklist/:id", async (req, res, params) => {
    const user = getUser(req);
    requireAdmin(user);
    const info = db.prepare("DELETE FROM blacklist WHERE id = ?").run(params.id);
    if (info.changes === 0) throw new HttpError(404, "Entry not found");
    sendJSON(res, 200, { ok: true });
  });
};
