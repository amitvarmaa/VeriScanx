"use strict";
const db = require("../db");
const { hashPassword, verifyPassword, signToken } = require("../auth");
const { HttpError, getUser } = require("../context");
const { sendJSON, readJSONBody } = require("../http-helpers");

function publicUser(row) {
  return { id: row.id, username: row.username, name: row.name, role: row.role };
}

module.exports = function registerAuthRoutes(router) {
  router.post("/api/auth/login", async (req, res) => {
    const body = await readJSONBody(req);
    const username = String(body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!username || !password) throw new HttpError(400, "Username and password are required");
    const row = db.prepare("SELECT * FROM officers WHERE lower(username) = ?").get(username);
    if (!row || !row.active || !verifyPassword(password, row.password)) {
      throw new HttpError(401, "Invalid username or password");
    }
    const token = signToken({ sub: row.id, role: row.role });
    sendJSON(res, 200, { token, user: publicUser(row) });
  });

  router.get("/api/auth/me", async (req, res) => {
    const user = getUser(req);
    sendJSON(res, 200, { user });
  });

  router.post("/api/auth/change-password", async (req, res) => {
    const user = getUser(req);
    const body = await readJSONBody(req);
    const row = db.prepare("SELECT * FROM officers WHERE id = ?").get(user.id);
    if (!verifyPassword(String(body.oldPassword || ""), row.password)) {
      throw new HttpError(400, "Current password is incorrect");
    }
    const next = String(body.newPassword || "");
    if (next.length < 6) throw new HttpError(400, "New password must be at least 6 characters");
    db.prepare("UPDATE officers SET password = ? WHERE id = ?").run(hashPassword(next), user.id);
    sendJSON(res, 200, { ok: true });
  });
};
