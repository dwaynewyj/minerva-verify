#!/usr/bin/env node
// verify.mjs — checks a MINERVA evidence packet with nothing but Node.js (18+).
//
//   node verify.mjs [folder]      folder defaults to the one this script sits in
//
// 1. Recomputes every ledger row's hash from ledger/ledger.json and walks the
//    chain (each row's prev_hash must name the row before it), then checks
//    ledger/head.json names the last row.
// 2. Recomputes the SHA-256 of every file listed in SHA256SUMS.
// 3. For each receipt in anchors/ (an RFC 3161 TimeStampResp, DER), reads the
//    hash the authority signed (TSTInfo.messageImprint) and its time out of
//    the bytes, finds the ledger row that carries that hash, checks
//    anchors/index.json agrees, and checks the <id>.receipt.json beside it
//    (the SCITT-shaped record: issuer, subject, statement hash, time, nonce)
//    says what the token says. The SIGNATURE is not checked here — that is
//    OpenSSL's, against the authority's own chain; the command is printed.
// 4. Walks the observed book in observations/ (the connectors' second chain)
//    with the same canonical form, and checks observations/head.json.
// 5. Walks the validation runs in runs/ (the SDK's third chain): each run's
//    results hash is recomputed from the results inside it, then the run's
//    own hash, then the link to the run before; checks runs/head.json.
// 6. For each checkpoint in checkpoints/ (a day's ledger head signed with the
//    deployment's Ed25519 key), verifies the signature under the public key
//    the file carries, checks the key id, and finds the ledger row whose hash
//    the checkpoint names. For a checkpoint whose copy reached a public
//    transparency log, prints the one command that fetches the entry and what
//    to compare it with — the fetch is the reader's, this script makes no
//    network call.
// Prints one "ok:" line per section, or names the first break. When nothing
// failed it ends with ONE LINE —
//   verified: mnv-verify/1 head <seq> <hash> manifest <sha256 of manifest.json> at <ISO UTC> on <hostname>
// — the line a reader hands back; the institution matches it to the export by
// the manifest's hash on the packet.exported row. On any failure it prints
// "not verified" and exits with status 1.
//
// The canonical form (mnv-canon/1), exactly as the software computes it:
//   object keys sorted by UTF-16 code unit; no whitespace; strings NFC-
//   normalised then JSON-quoted; finite numbers as JSON numbers, non-finite
//   as null; null and undefined as null; an object key whose value is
//   undefined is dropped; arrays in order.
// A row's hash is SHA-256 (hex) over the canonical form of
//   { id, org_id, at, kind, actor_id, actor_kind, subject_kind, subject_id,
//     payload, prev_hash, canon_version }.

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const CANON_VERSION = "mnv-canon/1";
const VERIFY_FORMAT = "mnv-verify/1";
const RECEIPT_FORMAT = "mnv-receipt/1";

function canon(v) {
  if (v === null || v === undefined) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      return Number.isFinite(v) ? JSON.stringify(v) : "null";
    case "string":
      return JSON.stringify(v.normalize("NFC"));
    case "object": {
      if (Array.isArray(v)) return "[" + v.map((x) => canon(x)).join(",") + "]";
      const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
    }
    default:
      return "null";
  }
}

const sha256 = (data) => createHash("sha256").update(data).digest("hex");

function eventHash(e) {
  return sha256(canon({
    id: e.id, org_id: e.org_id, at: e.at, kind: e.kind, actor_id: e.actor_id, actor_kind: e.actor_kind,
    subject_kind: e.subject_kind, subject_id: e.subject_id, payload: e.payload, prev_hash: e.prev_hash, canon_version: e.canon_version,
  }));
}

const root = resolve(process.argv[2] || dirname(fileURLToPath(import.meta.url)));
let failed = false;
const fail = (msg) => { failed = true; console.error("FAIL: " + msg); };
/** The ledger rows once read, for the anchor section. */
let ledgerRows = null;
/** The head as the ledger section found it, for the verification line. */
let headSeq = null, headHash = null;

// ── 1. the ledger ──────────────────────────────────────────────────────────
const ledgerPath = join(root, "ledger", "ledger.json");
if (!existsSync(ledgerPath)) {
  fail("ledger/ledger.json is missing");
} else {
  let rows;
  try { rows = JSON.parse(readFileSync(ledgerPath, "utf8")); } catch (e) { rows = null; fail("ledger/ledger.json is not JSON: " + e.message); }
  if (Array.isArray(rows)) {
    ledgerRows = rows;
    let prev = null, lastSeq = null, count = 0, withheld = 0, broke = null;
    for (const e of rows) {
      if (lastSeq !== null && !(e.seq > lastSeq)) { broke = { e, reason: "seq " + e.seq + " does not follow seq " + lastSeq }; break; }
      if (e.prev_hash !== prev) { broke = { e, reason: "prev_hash does not name the previous row (" + (prev ? prev.slice(0, 8) : "none") + ")" }; break; }
      if (e.withheld === true) {
        withheld += 1;
      } else {
        if (e.canon_version !== CANON_VERSION) { broke = { e, reason: "canonical form " + JSON.stringify(e.canon_version) + " is not one this script knows (" + CANON_VERSION + ")" }; break; }
        const h = eventHash(e);
        if (h !== e.hash) { broke = { e, reason: "recomputed hash " + h.slice(0, 12) + "… differs from the stored hash " + String(e.hash).slice(0, 12) + "…" }; break; }
      }
      prev = e.hash; lastSeq = e.seq; count += 1;
    }
    if (broke) {
      fail("ledger row seq " + broke.e.seq + " (" + broke.e.id + "): " + broke.reason);
    } else {
      const headPath = join(root, "ledger", "head.json");
      if (existsSync(headPath)) {
        try {
          const head = JSON.parse(readFileSync(headPath, "utf8"));
          if (head.hash !== prev || head.seq !== lastSeq) fail("ledger/head.json names seq " + head.seq + " hash " + String(head.hash).slice(0, 12) + "…, but the last row is seq " + lastSeq + " hash " + String(prev).slice(0, 12) + "…");
        } catch (e) { fail("ledger/head.json is not JSON: " + e.message); }
      }
      headSeq = lastSeq; headHash = prev;
      console.log("ok: " + count + " events" + (withheld ? " (" + withheld + " withheld from this reader, carried by hash only)" : "") + ", head " + (prev || "none"));
    }
  }
}

// ── 2. every file in SHA256SUMS ────────────────────────────────────────────
const sumsPath = join(root, "SHA256SUMS");
if (!existsSync(sumsPath)) {
  fail("SHA256SUMS is missing");
} else {
  const lines = readFileSync(sumsPath, "utf8").split("\n").filter((l) => l.trim() !== "");
  let good = 0;
  for (const line of lines) {
    const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
    if (!m) { fail("SHA256SUMS: cannot read line " + JSON.stringify(line)); continue; }
    const file = join(root, m[2]);
    if (!existsSync(file)) { fail(m[2] + ": missing"); continue; }
    const h = sha256(readFileSync(file));
    if (h !== m[1]) fail(m[2] + ": SHA-256 " + h.slice(0, 12) + "… differs from the recorded " + m[1].slice(0, 12) + "…");
    else good += 1;
  }
  if (good === lines.length) console.log("ok: " + good + " files match SHA256SUMS");
}
// the manifest's own hash — what the verification line names; manifest.json is in SHA256SUMS, so it was checked above
const manifestPath = join(root, "manifest.json");
let manifestSha = null;
if (!existsSync(manifestPath)) fail("manifest.json is missing");
else manifestSha = sha256(readFileSync(manifestPath));

// ── 3. every anchor receipt names a ledger row ─────────────────────────────
//
// The little DER that is needed: a TLV walker, OIDs, INTEGER hex, and the
// path TimeStampResp → ContentInfo → SignedData → encapContentInfo →
// eContent (OCTET STRING) → TSTInfo { version, policy, messageImprint
// { alg, hashedMessage }, serialNumber, genTime, … nonce }. Nothing here
// verifies the signature over the token; it reads what the token says.
const TAG_INTEGER = 0x02, TAG_OCTET = 0x04, TAG_OID = 0x06, TAG_GENTIME = 0x18, TAG_SEQ = 0x30, TAG_CTX0 = 0xa0;
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";

function readTlv(buf, at) {
  if (at + 2 > buf.length) throw new Error("truncated DER");
  const tag = buf[at];
  let len = buf[at + 1];
  let p = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > buf.length) throw new Error("unsupported DER length");
    len = 0;
    for (let i = 0; i < n; i += 1) len = len * 256 + buf[p + i];
    p += n;
  }
  if (p + len > buf.length) throw new Error("truncated DER");
  return { tag, at, start: p, end: p + len };
}
function childrenOf(buf, t) {
  const out = [];
  let at = t.start;
  while (at < t.end) { const c = readTlv(buf, at); out.push(c); at = c.end; }
  return out;
}
function want(t, tag, what) {
  if (!t || t.tag !== tag) throw new Error("expected " + what);
  return t;
}
function intOf(buf, t) { let v = 0; for (let i = t.start; i < t.end; i += 1) v = v * 256 + buf[i]; return v; }
function intHex(buf, t) { let s = t.start; while (s < t.end - 1 && buf[s] === 0) s += 1; return buf.subarray(s, t.end).toString("hex"); }
function oidOf(buf, t) {
  const b = buf.subarray(t.start, t.end);
  if (b.length === 0) return "";
  const arcs = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i += 1) { v = v * 128 + (b[i] & 0x7f); if ((b[i] & 0x80) === 0) { arcs.push(v); v = 0; } }
  return arcs.join(".");
}
function genTimeIso(s) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(s);
  return m ? m[1] + "-" + m[2] + "-" + m[3] + "T" + m[4] + ":" + m[5] + ":" + m[6] + (m[7] || "") + "Z" : s;
}
/** { status, imprint, genTime, nonce } out of a TimeStampResp, or a throw naming what is missing. */
function readReceipt(der) {
  const resp = want(readTlv(der, 0), TAG_SEQ, "a TimeStampResp SEQUENCE");
  const top = childrenOf(der, resp);
  const info = want(top[0], TAG_SEQ, "PKIStatusInfo");
  const status = intOf(der, want(childrenOf(der, info)[0], TAG_INTEGER, "PKIStatus"));
  if (!top[1]) return { status, imprint: null, genTime: null, nonce: null };
  const ci = childrenOf(der, want(top[1], TAG_SEQ, "ContentInfo"));
  if (oidOf(der, want(ci[0], TAG_OID, "contentType")) !== OID_SIGNED_DATA) throw new Error("the token is not SignedData");
  const sd = want(childrenOf(der, want(ci[1], TAG_CTX0, "content [0]"))[0], TAG_SEQ, "SignedData");
  const eci = want(childrenOf(der, sd)[2], TAG_SEQ, "encapContentInfo");
  const eciKids = childrenOf(der, eci);
  if (oidOf(der, want(eciKids[0], TAG_OID, "eContentType")) !== OID_TST_INFO) throw new Error("the content is not a TSTInfo");
  const eContent = want(childrenOf(der, want(eciKids[1], TAG_CTX0, "eContent [0]"))[0], TAG_OCTET, "eContent OCTET STRING");
  const tst = der.subarray(eContent.start, eContent.end);
  const t = childrenOf(tst, want(readTlv(tst, 0), TAG_SEQ, "TSTInfo"));
  const imprint = childrenOf(tst, want(t[2], TAG_SEQ, "messageImprint"));
  const hashed = want(imprint[1], TAG_OCTET, "hashedMessage");
  const gt = want(t[4], TAG_GENTIME, "genTime");
  let nonce = null;
  for (const k of t.slice(5)) if (k.tag === TAG_INTEGER) nonce = intHex(tst, k);
  return { status, imprint: tst.subarray(hashed.start, hashed.end).toString("hex"), genTime: genTimeIso(tst.subarray(gt.start, gt.end).toString("ascii")), nonce };
}

const anchorsDir = join(root, "anchors");
if (!existsSync(anchorsDir)) {
  console.log("ok: no anchor receipts in this packet — the chain stands on its own arithmetic (README, What this proves)");
} else if (!Array.isArray(ledgerRows)) {
  fail("anchors/ is present but the ledger could not be read, so no receipt can be tied to a row");
} else {
  const files = readdirSync(anchorsDir).filter((f) => f.endsWith(".tsr")).sort();
  let index = [];
  const indexPath = join(anchorsDir, "index.json");
  if (existsSync(indexPath)) {
    try { index = JSON.parse(readFileSync(indexPath, "utf8")); } catch (e) { fail("anchors/index.json is not JSON: " + e.message); }
  } else fail("anchors/index.json is missing");
  const byHash = new Map(ledgerRows.map((r) => [r.hash, r]));
  let tied = 0, records = 0;
  // a .receipt.json with no token beside it describes nothing
  for (const f of readdirSync(anchorsDir).filter((f) => f.endsWith(".receipt.json")).sort()) {
    if (!files.includes(f.slice(0, -".receipt.json".length) + ".tsr")) fail("anchor " + f + ": no " + f.slice(0, -".receipt.json".length) + ".tsr stands beside it");
  }
  for (const file of files) {
    let r;
    try { r = readReceipt(readFileSync(join(anchorsDir, file))); } catch (e) { fail("anchor " + file + ": " + e.message); continue; }
    if (r.status !== 0 && r.status !== 1) { fail("anchor " + file + ": the authority did not grant it (PKIStatus " + r.status + ")"); continue; }
    if (!r.imprint) { fail("anchor " + file + ": the receipt carries no token"); continue; }
    const row = byHash.get(r.imprint);
    if (!row) { fail("anchor " + file + ": no ledger row carries the hash the receipt names (" + r.imprint.slice(0, 12) + "…)"); continue; }
    const entry = Array.isArray(index) ? index.find((x) => x && x.file === file) : null;
    if (!entry) { fail("anchor " + file + ": not named in anchors/index.json"); continue; }
    if (entry.hash !== r.imprint || entry.head_seq !== row.seq) { fail("anchor " + file + ": anchors/index.json says seq " + entry.head_seq + " hash " + String(entry.hash).slice(0, 12) + "…, the receipt names seq " + row.seq + " hash " + r.imprint.slice(0, 12) + "…"); continue; }
    tied += 1;
    console.log("anchor " + file + ": imprint matches row seq " + row.seq + " (" + entry.authority + ", " + r.genTime + ") — the signature is not checked here; run: openssl ts -verify -digest " + r.imprint + " -in anchors/" + file + " -CAfile <the authority's certificate chain, PEM>");
    // the SCITT-shaped record beside the token (2026-10-26): every word in it must be what the token and the index say
    const recFile = file.slice(0, -".tsr".length) + ".receipt.json";
    const recPath = join(anchorsDir, recFile);
    if (!existsSync(recPath)) continue;
    let rec;
    try { rec = JSON.parse(readFileSync(recPath, "utf8")); } catch (e) { fail("anchor " + recFile + ": not JSON: " + e.message); continue; }
    const says = [];
    if (!rec || rec.format !== RECEIPT_FORMAT) says.push("format " + JSON.stringify(rec && rec.format) + " is not " + RECEIPT_FORMAT);
    else {
      if (rec.tsr !== file) says.push("names token " + JSON.stringify(rec.tsr) + ", stands beside " + file);
      if (rec.statement_sha256 !== r.imprint) says.push("statement_sha256 " + String(rec.statement_sha256).slice(0, 12) + "… is not the token's imprint " + r.imprint.slice(0, 12) + "…");
      if (rec.registered_at !== r.genTime) says.push("registered_at " + JSON.stringify(rec.registered_at) + " is not the token's time " + r.genTime);
      if ((rec.nonce || null) !== (r.nonce || null)) says.push("nonce " + JSON.stringify(rec.nonce) + " is not the token's " + JSON.stringify(r.nonce));
      if (rec.issuer !== entry.authority) says.push("issuer " + JSON.stringify(rec.issuer) + " is not the index's authority " + JSON.stringify(entry.authority));
      if (!rec.subject || rec.subject.head_hash !== r.imprint || rec.subject.head_seq !== row.seq) says.push("subject names seq " + (rec.subject && rec.subject.head_seq) + " hash " + String(rec.subject && rec.subject.head_hash).slice(0, 12) + "…, the row is seq " + row.seq + " hash " + r.imprint.slice(0, 12) + "…");
      if (rec.subject && ledgerRows[0] && rec.subject.org_id !== ledgerRows[0].org_id && ledgerRows[0].org_id !== undefined) says.push("subject names workspace " + JSON.stringify(rec.subject.org_id) + ", the ledger is " + JSON.stringify(ledgerRows[0].org_id));
    }
    if (says.length) { fail("anchor " + recFile + ": " + says.join("; ")); continue; }
    records += 1;
  }
  if (tied === files.length) console.log("ok: " + tied + " anchor " + (tied === 1 ? "receipt names" : "receipts name") + " a ledger row" + (records ? ", " + records + " receipt record" + (records === 1 ? "" : "s") + " agree" + (records === 1 ? "s" : "") + " with the token beside it" : ""));
}

// ── 4. the observed book ───────────────────────────────────────────────────
// The connectors' chain: each observation's hash is SHA-256 over the
// canonical form of { id, org_id, connector_id, node_id, external_id, title,
// observed_at, facts, prev_hash, canon_version } — the same form as the
// ledger's, over that row's own fields.
function observationHash(o) {
  return sha256(canon({
    id: o.id, org_id: o.org_id, connector_id: o.connector_id, node_id: o.node_id, external_id: o.external_id, title: o.title,
    observed_at: o.observed_at, facts: o.facts, prev_hash: o.prev_hash, canon_version: CANON_VERSION,
  }));
}
const obsPath = join(root, "observations", "observations.json");
if (!existsSync(obsPath)) {
  console.log("ok: no observations in this packet — no connector has written to the observed book");
} else {
  let obs;
  try { obs = JSON.parse(readFileSync(obsPath, "utf8")); } catch (e) { obs = null; fail("observations/observations.json is not JSON: " + e.message); }
  if (Array.isArray(obs)) {
    let prev = null, broke = null, count = 0;
    for (const o of obs) {
      if (o.prev_hash !== prev) { broke = { o, reason: "prev_hash does not name the previous observation (" + (prev ? prev.slice(0, 8) : "none") + ")" }; break; }
      const h = observationHash(o);
      if (h !== o.hash) { broke = { o, reason: "recomputed hash " + h.slice(0, 12) + "… differs from the stored hash " + String(o.hash).slice(0, 12) + "…" }; break; }
      prev = o.hash; count += 1;
    }
    if (broke) {
      fail("observation " + broke.o.id + ": " + broke.reason);
    } else {
      const headPath = join(root, "observations", "head.json");
      if (existsSync(headPath)) {
        try {
          const head = JSON.parse(readFileSync(headPath, "utf8"));
          if (head.hash !== prev) fail("observations/head.json names hash " + String(head.hash).slice(0, 12) + "…, but the last observation's is " + String(prev).slice(0, 12) + "…");
        } catch (e) { fail("observations/head.json is not JSON: " + e.message); }
      }
      console.log("ok: " + count + " observations, head " + (prev || "none"));
    }
  }
}

// ── 5. the validation runs ─────────────────────────────────────────────────
// The SDK's chain: a run's results_hash is SHA-256 over the canonical form of
// its results in order, each as { id, run_id, org_id, node_id, of, metric,
// value, threshold, direction, verdict, meets, method, segment, detail } —
// file_id is stamped after the run lands and is outside the hash. The run's
// hash is SHA-256 over { id, org_id, node_id, suite, started_at, finished_at,
// by_id, by_name, method, sample, data_hash, code_version, env, status,
// counts, tables, note, results_hash, prev_hash, canon_version }.
function resultsHash(results) {
  return sha256(canon(results.map((r) => ({
    id: r.id, run_id: r.run_id, org_id: r.org_id, node_id: r.node_id, of: r.of, metric: r.metric, value: r.value, threshold: r.threshold,
    direction: r.direction, verdict: r.verdict, meets: r.meets, method: r.method, segment: r.segment, detail: r.detail,
  }))));
}
function runHash(r) {
  return sha256(canon({
    id: r.id, org_id: r.org_id, node_id: r.node_id, suite: r.suite, started_at: r.started_at, finished_at: r.finished_at, by_id: r.by_id, by_name: r.by_name,
    method: r.method, sample: r.sample, data_hash: r.data_hash, code_version: r.code_version, env: r.env, status: r.status, counts: r.counts, tables: r.tables,
    note: r.note, results_hash: r.results_hash, prev_hash: r.prev_hash, canon_version: CANON_VERSION,
  }));
}
const runsPath = join(root, "runs", "runs.json");
if (!existsSync(runsPath)) {
  console.log("ok: no validation runs in this packet — no suite has been recorded");
} else {
  let runs;
  try { runs = JSON.parse(readFileSync(runsPath, "utf8")); } catch (e) { runs = null; fail("runs/runs.json is not JSON: " + e.message); }
  if (Array.isArray(runs)) {
    let prev = null, broke = null, count = 0;
    for (const r of runs) {
      if (r.prev_hash !== prev) { broke = { r, reason: "prev_hash does not name the previous run (" + (prev ? prev.slice(0, 8) : "none") + ")" }; break; }
      const rh = resultsHash(Array.isArray(r.results) ? r.results : []);
      if (rh !== r.results_hash) { broke = { r, reason: "recomputed results hash " + rh.slice(0, 12) + "… differs from the stored results_hash " + String(r.results_hash).slice(0, 12) + "…" }; break; }
      const h = runHash(r);
      if (h !== r.hash) { broke = { r, reason: "recomputed hash " + h.slice(0, 12) + "… differs from the stored hash " + String(r.hash).slice(0, 12) + "…" }; break; }
      prev = r.hash; count += 1;
    }
    if (broke) {
      fail("validation run " + broke.r.id + ": " + broke.reason);
    } else {
      const headPath = join(root, "runs", "head.json");
      if (existsSync(headPath)) {
        try {
          const head = JSON.parse(readFileSync(headPath, "utf8"));
          if (head.hash !== prev) fail("runs/head.json names hash " + String(head.hash).slice(0, 12) + "…, but the last run's is " + String(prev).slice(0, 12) + "…");
        } catch (e) { fail("runs/head.json is not JSON: " + e.message); }
      }
      console.log("ok: " + count + " validation runs, head " + (prev || "none"));
    }
  }
}

// ── 6. the checkpoints ─────────────────────────────────────────────────────
// A checkpoint is the ledger head of a day signed with the deployment's
// Ed25519 key over the UTF-8 bytes of "<org_id>\n<head_seq>\n<head_hash>"
// (three lines, LF, no trailing newline). Each checkpoints/<day>.json carries
// the signature and the public key; key_id is the first 16 hex of SHA-256
// over the key's DER; the head it names must be a ledger row with that hash.
const cpDir = join(root, "checkpoints");
if (!existsSync(cpDir)) {
  console.log("ok: no checkpoints in this packet — no day's head has been signed and handed outside yet");
} else if (!Array.isArray(ledgerRows)) {
  fail("checkpoints/ is present but the ledger could not be read, so no checkpoint can be tied to a row");
} else {
  const files = readdirSync(cpDir).filter((f) => f.endsWith(".json")).sort();
  const byHash = new Map(ledgerRows.map((r) => [r.hash, r]));
  let good = 0;
  for (const file of files) {
    let c;
    try { c = JSON.parse(readFileSync(join(cpDir, file), "utf8")); } catch (e) { fail("checkpoint " + file + ": not JSON: " + e.message); continue; }
    const row = byHash.get(c.head_hash);
    if (!row) { fail("checkpoint " + file + ": no ledger row carries the hash it names (" + String(c.head_hash).slice(0, 12) + "…)"); continue; }
    if (row.seq !== c.head_seq) { fail("checkpoint " + file + ": names seq " + c.head_seq + " but the row carrying that hash is seq " + row.seq); continue; }
    const message = Buffer.from(c.org_id + "\n" + c.head_seq + "\n" + c.head_hash, "utf8");
    let okSig = false;
    try { okSig = verifySignature(null, message, c.public_key_pem, Buffer.from(c.signature, "base64")); } catch (e) { okSig = false; }
    if (!okSig) { fail("checkpoint " + file + ": the signature does not verify under the public key it carries"); continue; }
    let keyId = null;
    try { keyId = createHash("sha256").update(createPublicKey(c.public_key_pem).export({ type: "spki", format: "der" })).digest("hex").slice(0, 16); } catch (e) { keyId = null; }
    if (c.key_id && keyId !== c.key_id) { fail("checkpoint " + file + ": key id " + c.key_id + " does not match the public key it carries (" + keyId + ")"); continue; }
    good += 1;
    console.log("checkpoint " + file + ": signature verifies, head seq " + row.seq + " (" + c.day + ", key " + keyId + ")");
    // the public log's copy (2026-10-26): the entry is fetched by the READER, never by this script — print the command and what to compare
    const entry = c.delivered && c.delivered.log_entry;
    if (entry && typeof entry === "object" && typeof entry.uuid === "string") {
      const base = typeof entry.url === "string" ? entry.url.replace(/\/api\/v1\/log\/entries\/?$/, "") : "https://rekor.sigstore.dev";
      const messageSha = sha256(message);
      console.log("checkpoint " + file + ": a copy reached the public log (entry " + (entry.logIndex !== undefined && entry.logIndex !== null ? entry.logIndex : entry.uuid) + "). Fetch it yourself — this script makes no network call:");
      console.log("    curl -s " + base + "/api/v1/log/entries/" + entry.uuid);
      console.log("    then base64-decode the entry's \"body\": its spec.data.hash.value must be " + messageSha + " (SHA-256 of the signed bytes), its spec.signature.content must be the file's signature (" + String(c.signature).slice(0, 16) + "…), and its spec.signature.publicKey.content base64-decodes to the key in checkpoints/key.pem; the entry's integratedTime is the log's own clock" + (entry.integratedTime ? " (" + new Date(Number(entry.integratedTime) * 1000).toISOString() + " when the post landed)" : "") + ".");
    }
  }
  if (good === files.length) console.log("ok: " + good + " checkpoint" + (good === 1 ? " names" : "s name") + " a ledger row and verif" + (good === 1 ? "ies" : "y") + " under the key in checkpoints/key.pem");
}

// ── the verification line ──────────────────────────────────────────────────
// One line when nothing failed: the format, the head the ledger section
// found, the manifest's SHA-256 (what the packet.exported row carries as
// manifest_sha256), the reader's clock in UTC and the host's name — no
// username, nothing else about the reader. "not verified" otherwise.
if (failed) {
  console.log("not verified");
  process.exit(1);
}
console.log("verified: " + VERIFY_FORMAT + " head " + (headSeq === null ? "none" : headSeq) + " " + (headHash || "none") + " manifest " + (manifestSha || "none") + " at " + new Date().toISOString() + " on " + hostname());
process.exit(0);
