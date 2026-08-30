// Shared national-registry cross-check, used by both the registry CRUD
// routes and the scan-submission route (server-side, authoritative — a
// client can't just claim a document is registered).
"use strict";
const db = require("./db");

function normalizeDocNum(s) {
  return String(s || "").replace(/[^0-9]/g, "");
}

function serializeEntry(row) {
  return {
    id: row.id,
    docId: row.doc_id,
    name: row.name,
    dob: row.dob,
    gender: row.gender,
    city: row.city,
    state: row.state,
    docNumber: row.doc_number,
    photo: row.photo || null,
    createdAt: row.created_at,
  };
}

// Returns null when there's no document number to check, otherwise
// { status: 'verified'|'mismatch'|'unregistered', entry }.
function checkRegistry(docNumber, name, dob) {
  const norm = normalizeDocNum(docNumber);
  if (!norm) return null;
  const row = db.prepare("SELECT * FROM registry WHERE doc_number = ?").get(norm);
  if (!row) return { status: "unregistered", entry: null };
  const nameOk = !name || String(name).trim().toLowerCase() === row.name.toLowerCase();
  const dobOk = !dob || dob === row.dob;
  const entry = serializeEntry(row);
  if (!nameOk || !dobOk) return { status: "mismatch", entry };
  return { status: "verified", entry };
}

module.exports = { checkRegistry, normalizeDocNum, serializeEntry };
