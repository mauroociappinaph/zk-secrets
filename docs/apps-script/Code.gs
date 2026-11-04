/**
 * zks audit mirror - Google Apps Script web app.
 *
 * Receives HMAC-signed batches of metadata-only audit records from `zks audit sync`
 * and appends them to the "audit" sheet. No record field can hold a secret value.
 *
 * Script Properties: ZKS_HMAC_KEY (the same value stored with `zks auth set sheets-hmac`).
 */
var SHEET_NAME = "audit";
var MAX_AGE_MS = 10 * 60 * 1000;
var COLUMNS = [
  "auditId", "ts", "actorHuman", "actorAgent", "project", "provider", "target", "environment",
  "variableName", "action", "sensitive", "sourceKind", "result", "providerVersion", "errorCode",
  "prevHash", "hash"
];

function doPost(e) {
  try {
    var envelope = JSON.parse(e.postData.contents);
    var key = PropertiesService.getScriptProperties().getProperty("ZKS_HMAC_KEY");
    if (!key) return reply({ ok: false, error: "not configured" });
    if (typeof envelope.payload !== "string" || typeof envelope.signature !== "string") {
      return reply({ ok: false, error: "bad request" });
    }
    if (!constantTimeEquals(hmacHex(key, envelope.payload), envelope.signature)) {
      return reply({ ok: false, error: "bad signature" });
    }
    var payload = JSON.parse(envelope.payload);
    var sentAt = Date.parse(payload.sentAt);
    if (!(Math.abs(Date.now() - sentAt) <= MAX_AGE_MS)) return reply({ ok: false, error: "stale" });

    var lock = LockService.getScriptLock();
    lock.waitLock(20000);
    try {
      var sheet = auditSheet();
      var existing = {};
      var last = sheet.getLastRow();
      if (last > 1) {
        sheet.getRange(2, 1, last - 1, 1).getValues().forEach(function (row) { existing[row[0]] = true; });
      }
      var accepted = [];
      var rows = [];
      (payload.records || []).forEach(function (record) {
        if (typeof record.auditId !== "string") return;
        accepted.push(record.auditId);
        if (existing[record.auditId]) return;
        existing[record.auditId] = true;
        rows.push(COLUMNS.map(function (c) { return record[c] === undefined ? "" : String(record[c]); }));
      });
      if (rows.length > 0) sheet.getRange(sheet.getLastRow() + 1, 1, rows.length, COLUMNS.length).setValues(rows);
      return reply({ ok: true, accepted: accepted });
    } finally {
      lock.releaseLock();
    }
  } catch (err) {
    return reply({ ok: false, error: "server error" });
  }
}

function auditSheet() {
  var book = SpreadsheetApp.getActiveSpreadsheet();
  var sheet = book.getSheetByName(SHEET_NAME) || book.insertSheet(SHEET_NAME);
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(COLUMNS);
    sheet.setFrozenRows(1);
  }
  return sheet;
}

function hmacHex(key, message) {
  var bytes = Utilities.computeHmacSha256Signature(message, key, Utilities.Charset.UTF_8);
  return bytes.map(function (b) { return ("0" + (b & 0xff).toString(16)).slice(-2); }).join("");
}

function constantTimeEquals(a, b) {
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function reply(body) {
  return ContentService.createTextOutput(JSON.stringify(body)).setMimeType(ContentService.MimeType.JSON);
}
