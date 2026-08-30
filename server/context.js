"use strict";
const db = require("./db");
const { verifyToken } = require("./auth");

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

function getUser(req) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) throw new HttpError(401, "Not authenticated");
  const payload = verifyToken(token);
  if (!payload) throw new HttpError(401, "Session expired — please log in again");
  const user = db.prepare("SELECT id, username, name, role, active FROM officers WHERE id = ?").get(payload.sub);
  if (!user || !user.active) throw new HttpError(401, "Account not found or disabled");
  return user;
}

function requireAdmin(user) {
  if (user.role !== "admin") throw new HttpError(403, "Admin access required");
}

module.exports = { HttpError, getUser, requireAdmin };
