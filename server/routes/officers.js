"use strict";
const db = require("../db");
const { hashPassword } = require("../auth");
const { HttpError, getUser, requireAdmin } = require("../context");
const { sendJSON, readJSONBody } = require("../http-helpers");

function serialize(row) {
  return { id: row.id, username: row.username, name: row.name, role: row.role, active: !!row.active, createdAt: row.created_at };
}

module.exports = function registerOfficerRoutes(router) {
  router.get("/api/officers", async (req, res) => {
    const user = getUser(req);
    requireAdmin(user);
    const rows = db.prepare("SELECT * FROM officers ORDER BY created_at ASC").all();
    sendJSON(res, 200, { items: rows.map(serialize) });
  });

  router.post("/api/officers", async (req, res) => {
    const user = getUser(req);
    requireAdmin(user);
    const body = await readJSONBody(req);
    const username = String(body.username || "").trim().toLowerCase();
    const name = String(body.name || "").trim();
    const password = String(body.password || "");
    const role = body.role === "admin" ? "admin" : "officer";
    if (!username || !name || password.length < 6) {
      throw new HttpError(400, "username, name, and a password of 6+ characters are required");
    }
    const existing = db.prepare("SELECT 1 FROM officers WHERE lower(username) = ?").get(username);
    if (existing) throw new HttpError(409, "That username is already taken");
    const result = db
      .prepare("INSERT INTO officers (username, password, name, role) VALUES (?,?,?,?)")
      .run(username, hashPassword(password), name, role);
    const row = db.prepare("SELECT * FROM officers WHERE id = ?").get(result.lastInsertRowid);
    sendJSON(res, 201, { item: serialize(row) });
  });

  router.patch("/api/officers/:id", async (req, res, params) => {
    const user = getUser(req);
    requireAdmin(user);
    const body = await readJSONBody(req);
    const row = db.prepare("SELECT * FROM officers WHERE id = ?").get(params.id);
    if (!row) throw new HttpError(404, "Officer not found");
    if (row.id === user.id && body.active === false) {
      throw new HttpError(400, "You can't deactivate your own account");
    }
    const name = body.name !== undefined ? String(body.name) : row.name;
    const role = body.role === "admin" || body.role === "officer" ? body.role : row.role;
    const active = body.active !== undefined ? (body.active ? 1 : 0) : row.active;
    const password = body.password ? hashPassword(String(body.password)) : row.password;
    db.prepare("UPDATE officers SET name=?, role=?, active=?, password=? WHERE id=?")
      .run(name, role, active, password, row.id);
    const updated = db.prepare("SELECT * FROM officers WHERE id = ?").get(row.id);
    sendJSON(res, 200, { item: serialize(updated) });
  });

  router.delete("/api/officers/:id", async (req, res, params) => {
    const user = getUser(req);
    requireAdmin(user);
    if (String(user.id) === String(params.id)) throw new HttpError(400, "You can't delete your own account");
    let info;
    try {
      info = db.prepare("DELETE FROM officers WHERE id = ?").run(params.id);
    } catch (err) {
      if (err && err.code === "ERR_SQLITE_ERROR" && /FOREIGN KEY/i.test(err.message)) {
        throw new HttpError(
          409,
          "This officer has scans on record and can't be deleted — deactivate the account instead to keep the scan history intact."
        );
      }
      throw err;
    }
    if (info.changes === 0) throw new HttpError(404, "Officer not found");
    sendJSON(res, 200, { ok: true });
  });
};
