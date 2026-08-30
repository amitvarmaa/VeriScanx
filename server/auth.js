// Password hashing (scrypt) and HMAC-signed session tokens — built entirely on
// Node's built-in `crypto` module. No bcrypt / jsonwebtoken dependency needed.
"use strict";
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const SECRET_PATH = path.join(__dirname, "..", "data", ".jwt-secret");

function getSecret() {
  if (process.env.VERISCANX_JWT_SECRET || process.env.AEGIS_JWT_SECRET) return process.env.VERISCANX_JWT_SECRET || process.env.AEGIS_JWT_SECRET;
  try {
    return fs.readFileSync(SECRET_PATH, "utf8").trim();
  } catch {
    const secret = crypto.randomBytes(32).toString("hex");
    fs.mkdirSync(path.dirname(SECRET_PATH), { recursive: true });
    fs.writeFileSync(SECRET_PATH, secret, { mode: 0o600 });
    return secret;
  }
}
const SECRET = getSecret();

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(":");
  if (!salt || !hash) return false;
  const hashBuf = Buffer.from(hash, "hex");
  const testBuf = crypto.scryptSync(String(password), salt, 64);
  return hashBuf.length === testBuf.length && crypto.timingSafeEqual(hashBuf, testBuf);
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function signToken(payload, expiresInSec = 60 * 60 * 12) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + expiresInSec };
  const h = b64url(JSON.stringify(header));
  const b = b64url(JSON.stringify(body));
  const sig = crypto.createHmac("sha256", SECRET).update(`${h}.${b}`).digest("base64url");
  return `${h}.${b}.${sig}`;
}

function verifyToken(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, b, sig] = parts;
  const expected = crypto.createHmac("sha256", SECRET).update(`${h}.${b}`).digest("base64url");
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const payload = JSON.parse(Buffer.from(b, "base64url").toString("utf8"));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

module.exports = { hashPassword, verifyPassword, signToken, verifyToken };
