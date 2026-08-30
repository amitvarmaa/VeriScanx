// Server-side risk engine — authoritative copy of the same weighted formula
// used in the public demo, so a client can't just send a fake low score.
"use strict";

function bandFor(score) {
  if (score >= 75) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function computeRisk({ tamperScore, blacklistHit, duplicateHit, mrzValid, expired, registryStatus, qrStatus }) {
  const t = Math.max(0, Math.min(100, Number(tamperScore) || 0));
  let score = 0;
  score += t * 0.25;
  score += blacklistHit ? 30 : 0;
  score += duplicateHit ? 25 : 0;
  score += mrzValid ? 0 : 12;
  score += expired ? 8 : 0;
  score += registryStatus === "mismatch" ? 28 : registryStatus === "unregistered" ? 26 : 0;
  score += qrStatus === "mismatch" ? 24 : 0;
  score = Math.round(Math.max(0, Math.min(100, score)));
  const band = bandFor(score);
  const reasons = [];
  if (t >= 45) reasons.push("Tamper suspected");
  if (blacklistHit) reasons.push("Blacklist match");
  if (duplicateHit) reasons.push("Duplicate identity");
  if (!mrzValid) reasons.push("MRZ / field mismatch");
  if (expired) reasons.push("Expired document");
  if (registryStatus === "mismatch") reasons.push("Registry identity mismatch");
  else if (registryStatus === "unregistered") reasons.push("Not found in national registry");
  if (qrStatus === "mismatch") reasons.push("QR / chip data contradicts printed identity");
  return { score, band, reasons };
}

module.exports = { computeRisk, bandFor };
