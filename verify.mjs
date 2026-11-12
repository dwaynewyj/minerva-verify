#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Minerva Software Inc. Published under the Apache License, Version 2.0 — the
// LICENSE beside the copy at https://minerva.studio/verify/verify.mjs, or
// https://www.apache.org/licenses/LICENSE-2.0. Anyone may read, run, copy, change and
// reimplement this script; the packet's copy and the site's are one text.
// verify.mjs — checks a MINERVA evidence packet with nothing but Node.js (18+).
//
//   node verify.mjs [folder]      folder defaults to the one this script sits in
//
// 1. Recomputes every ledger row's hash from ledger/ledger.json and walks the
//    chain (each row's prev_hash must name the row before it), then checks
//    ledger/head.json names the last row and that the number of rows carried
//    by hash only (withheld from this reader) is the number it states —
//    manifest.json must state the same. A row carried by hash only keeps its
//    kind and its time.
// 2. Recomputes the SHA-256 of every file listed in SHA256SUMS, then of every
//    file listed in manifest.json (whose own hash the last line names), and
//    checks the two lists name the same files with the same figures — a file
//    edited with its SHA256SUMS line rewritten still breaks here. Then walks
//    the folder: a file manifest.json does not list (an added agent folder, a
//    runtime's chain, a receipt) or a symbolic link fails, named. Every later
//    section reads only the files manifest.json lists, never what else lies
//    on disk; the files an operating system writes into a folder it shows
//    (.DS_Store, Thumbs.db, desktop.ini, ._*) are counted as ignored, since
//    nothing here reads them. A manifest.json that is not an object with its
//    list of files fails the run: without it nothing in the folder is trusted.
//    Then weighs what was withheld: manifest.json names who exported the
//    packet, in which role, and the window an examiner's grant narrowed it to;
//    an owner or an admin opens every row, so their packet carries none by
//    hash only outside such a window; a row that only names people and roles
//    is never withheld but by a window; the exporter's role is held to the
//    ledger's rows about them, and every name people.json gives a person to
//    the name the ledger's own rows last give them.
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
// 7. For the AI agents in agents/: walks every runtime's chain of decision
//    records (each hash recomputed from the record's packed fields, each link,
//    seq from 1), checks every seal's Merkle root and the runtime's Ed25519
//    signature on it; requires agents/issuer.pem to be the deployment key
//    every checkpoint was signed with and the ledger's checkpoint rows name;
//    checks every approved policy's signature under it, reads the ledger row
//    that decided it, its window and what it replaced out of the signed bytes
//    and requires keys.json to say the same — that row a decision that
//    approved it (a proposal accepted, or the kill switch pressed by its
//    holder), about this agent, written by the person keys.json names — and
//    requires the ledger's own record of the approval (its policy.decided
//    row) to name the same policy, revision, layers, time and retirement; a
//    rulebook floor names no decider; finds each agent's decisions on its
//    runtime's chain, compared field by field with the record the chain
//    holds, each record claimed by one agent only; requires every call the
//    product's own runtime released to be named in approvals.json, and every
//    release of a call named there, on any runtime, to carry the approver key
//    of the person it names. Every approval the ledger records, where this
//    reader holds the row, must have its policy here (a folder or a keys.json
//    left out fails); every record this reader holds must be claimed by the
//    agent whose approved policy it ran under; a retirement must rest on the
//    decision that replaced it; a rulebook floor's revision and retirement
//    are held to its signed bytes and the floor that replaced it; and the
//    counts manifest.json states are the folders and chains here. It says
//    what it cannot check.
// 8. For every MINERVA Benchmark Statement on the ledger (a benchmark.issued
//    row): recomputes the SHA-256 of the statement's canonical body, checks
//    the Ed25519 signature over its four signed lines under the key the row
//    carries, holds that key to the deployment key the checkpoints were
//    signed with, finds the head it read in the chain before it, and reports
//    a later benchmark.revoked row naming it. A statement is a reading of the
//    record against MINERVA's published criteria, never a certification.
// Prints one "ok:" line per section, or names the first break. When nothing
// failed it ends with ONE LINE —
//   verified: mnv-verify/1 head <seq> <hash> manifest <sha256 of manifest.json> at <ISO UTC> on <hostname>
// — the line a reader hands back; the institution matches it to the export by
// the manifest's hash on the packet.exported row. On any failure it prints
// "not verified" and exits with status 1. What this script proves is that the
// files agree with each other and with the chain they carry; that the folder
// is the packet the record exported is proven by that line, pasted back.
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
/** A public key's id as the checkpoints and the ledger's checkpoint rows name it: the first 16 hex of SHA-256 over its DER. */
const spkiKeyId = (pem) => createHash("sha256").update(createPublicKey(pem).export({ type: "spki", format: "der" })).digest("hex").slice(0, 16);

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
/** How many rows ledger/ledger.json carries by hash only, once the whole chain walked (null otherwise): head.json and manifest.json must state the same. */
let ledgerWithheld = null;
/** Those rows themselves, once the whole chain walked — each keeps its seq, its kind and its time (round seven). */
let ledgerStubs = null;
/** manifest.json once read as an object with its list of files (2b): who exported the packet, the window, the counts. */
let manifestObj = null;
/** The deployment key wherever the packet carries it — checkpoints/key.pem, each checkpoint — by key id: agents/issuer.pem must be that key. */
const deploymentKeys = [];

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
    const stubs = [];
    for (const e of rows) {
      if (lastSeq !== null && !(e.seq > lastSeq)) { broke = { e, reason: "seq " + e.seq + " does not follow seq " + lastSeq }; break; }
      if (e.prev_hash !== prev) { broke = { e, reason: "prev_hash does not name the previous row (" + (prev ? prev.slice(0, 8) : "none") + ")" }; break; }
      if (e.withheld === true) {
        withheld += 1;
        stubs.push(e);
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
      // (2026-10-26) head.json is required, and it states how many rows the export carried by hash only: a row turned into a withheld
      // stub after the export keeps the chain whole and hides who wrote it — a deciding row among them — so the count must be the file's
      if (!existsSync(headPath)) fail("ledger/head.json is missing — the head and the number of rows withheld from this reader cannot be compared; verify the packet as it was exported");
      else {
        try {
          const head = JSON.parse(readFileSync(headPath, "utf8"));
          if (!head || typeof head !== "object" || Array.isArray(head)) fail("ledger/head.json is not an object naming the head");
          else {
            if (head.hash !== prev || head.seq !== lastSeq) fail("ledger/head.json names seq " + head.seq + " hash " + String(head.hash).slice(0, 12) + "…, but the last row is seq " + lastSeq + " hash " + String(prev).slice(0, 12) + "…");
            if (head.withheld !== withheld) fail("ledger/head.json says " + JSON.stringify(head.withheld === undefined ? null : head.withheld) + " rows were withheld from this reader, but ledger/ledger.json carries " + withheld + " by hash only — a row carried by hash only hides who wrote it; verify the packet as it was exported");
          }
        } catch (e) { fail("ledger/head.json is not JSON: " + e.message); }
      }
      headSeq = lastSeq; headHash = prev; ledgerWithheld = withheld; ledgerStubs = stubs;
      // (round seven) a row carried by hash only keeps its kind and its time, so what was withheld can be weighed; a stub with neither hides
      // what it was
      const bare = stubs.filter((s) => typeof s.kind !== "string" || s.kind === "" || typeof s.at !== "number");
      if (bare.length) fail("ledger row seq " + bare[0].seq + (bare.length > 1 ? " and " + (bare.length - 1) + " more" : "") + " carried by hash only " + (bare.length > 1 ? "keep" : "keeps") + " no kind or no time — a row withheld from a reader keeps both, so what was withheld can be weighed; verify the packet as it was exported");
      console.log("ok: " + count + " events" + (withheld ? " (" + withheld + " withheld from this reader, carried by hash only)" : "") + ", head " + (prev || "none"));
    }
  }
}

// ── 2. every file in SHA256SUMS ────────────────────────────────────────────
const sumsPath = join(root, "SHA256SUMS");
/** A file's bytes, or null with the reason named — a listed file replaced by a folder is a FAIL line, never a stack trace (2026-10-26). */
const readOr = (path, label, encoding) => { try { return readFileSync(path, encoding); } catch (e) { fail(label + ": cannot be read: " + e.message); return null; } };
const sumsText = existsSync(sumsPath) ? readOr(sumsPath, "SHA256SUMS", "utf8") : null;
if (!existsSync(sumsPath)) {
  fail("SHA256SUMS is missing");
} else if (sumsText !== null) {
  const lines = sumsText.split("\n").filter((l) => l.trim() !== "");
  let good = 0;
  for (const line of lines) {
    const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
    if (!m) { fail("SHA256SUMS: cannot read line " + JSON.stringify(line)); continue; }
    const file = join(root, m[2]);
    if (!existsSync(file)) { fail(m[2] + ": missing"); continue; }
    const buf = readOr(file, m[2]);
    if (buf === null) continue;
    const h = sha256(buf);
    if (h !== m[1]) fail(m[2] + ": SHA-256 " + h.slice(0, 12) + "… differs from the recorded " + m[1].slice(0, 12) + "…");
    else good += 1;
  }
  if (good === lines.length) console.log("ok: " + good + " files match SHA256SUMS");
}
// the manifest's own hash — what the verification line names; manifest.json is in SHA256SUMS, so it was checked above
const manifestPath = join(root, "manifest.json");
let manifestSha = null;
/** Every path manifest.json lists, once it was read (null until then): the later sections read these and nothing else on disk. */
let listedPaths = null;
if (!existsSync(manifestPath)) fail("manifest.json is missing");
else { const buf = readOr(manifestPath, "manifest.json"); if (buf !== null) manifestSha = sha256(buf); }

// ── 2b. every file in manifest.json, and SHA256SUMS against it ─────────────
//
// SHA256SUMS alone proves nothing against an edit: whoever changes a file can
// rewrite its line. manifest.json lists every file with its own SHA-256, and
// the manifest's hash is the one the verification line names and the
// packet.exported row carries — so a file is checked against the manifest
// too, and the two lists must name the same files with the same figures.
if (manifestSha !== null) {
  let man = null, parsed = false;
  try { man = JSON.parse(readFileSync(manifestPath, "utf8")); parsed = true; } catch (e) { fail("manifest.json is not JSON: " + e.message); }
  // (2026-10-26) a manifest that parses but is no object with its list of files — null, 0, false, "", an array — skipped this section and
  // every later one that reads the listed files, and the run still ended "verified": it fails, closed
  const listed = man && typeof man === "object" && !Array.isArray(man) && Array.isArray(man.entries) ? man.entries : null;
  if (parsed && !listed) fail("manifest.json is not an object with its list of files (entries), so no file in the folder can be trusted — verify the packet as it was exported");
  if (listed) {
    const byPath = new Map();
    let good = 0;
    for (const en of listed) {
      if (!en || typeof en.path !== "string" || !/^[0-9a-f]{64}$/.test(String(en.sha256))) { fail("manifest.json: cannot read entry " + JSON.stringify(en)); continue; }
      // a listed path stays inside the folder: relative, "/" between its parts, no empty, "." or ".." part
      if (en.path.startsWith("/") || en.path.includes("\\") || en.path.split("/").some((s) => s === "" || s === "." || s === "..")) { fail(en.path + ": manifest.json names a place outside the packet's folder"); continue; }
      byPath.set(en.path, en.sha256);
      const file = join(root, en.path);
      if (!existsSync(file)) { fail(en.path + ": listed in manifest.json but missing"); continue; }
      let buf;
      try { buf = readFileSync(file); } catch (e) { fail(en.path + ": listed in manifest.json but cannot be read: " + e.message); continue; }
      const h = sha256(buf);
      if (h !== en.sha256) { fail(en.path + ": SHA-256 " + h.slice(0, 12) + "… differs from manifest.json's " + en.sha256.slice(0, 12) + "…"); continue; }
      if (typeof en.bytes === "number" && en.bytes !== buf.length) { fail(en.path + ": " + buf.length + " bytes, manifest.json says " + en.bytes); continue; }
      good += 1;
    }
    let agree = true;
    if (sumsText !== null) {
      const sums = new Map();
      for (const line of sumsText.split("\n")) {
        const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
        if (m) sums.set(m[2], m[1]);
      }
      for (const [path, h] of sums) {
        if (path === "manifest.json") continue;
        if (!byPath.has(path)) { agree = false; fail(path + ": in SHA256SUMS but not in manifest.json"); }
        else if (byPath.get(path) !== h) { agree = false; fail(path + ": SHA256SUMS and manifest.json record different SHA-256s"); }
      }
      for (const path of byPath.keys()) if (!sums.has(path)) { agree = false; fail(path + ": in manifest.json but not in SHA256SUMS"); }
    }
    if (good === listed.length && agree) console.log("ok: " + good + " files match manifest.json, and SHA256SUMS agrees with it");
    listedPaths = new Set(byPath.keys());
    manifestObj = man;
    // the rows the export carried by hash only, as manifest.json states them (2026-10-26) — the file's own count must be the same
    if (ledgerWithheld !== null && man.withheld_rows !== ledgerWithheld) fail("manifest.json says " + JSON.stringify(man.withheld_rows === undefined ? null : man.withheld_rows) + " ledger rows were withheld from this reader, but ledger/ledger.json carries " + ledgerWithheld + " by hash only — verify the packet as it was exported");
  }
}

// ── 2c. nothing in the folder that manifest.json does not list ────────────
//
// (2026-10-26) The sections below used to read whatever lay in anchors/,
// checkpoints/ and agents/: a folder added after the export — a forged agent
// with every control "met", a runtime's chain under a key nobody registered —
// was counted as verified, and the verification line still named the genuine
// export's manifest. So every file in the folder must be one manifest.json
// lists (manifest.json and SHA256SUMS apart), a symbolic link fails wherever
// it stands, and the later sections read only the listed paths. The files an
// operating system writes into a folder it shows are counted and ignored:
// nothing reads them, and a packet opened in a file browser must still verify.
const OS_LITTER = /^(\.DS_Store|Thumbs\.db|desktop\.ini|\._.+)$/;
if (listedPaths !== null) {
  let added = 0, litter = 0;
  const walk = (rel) => {
    let entries;
    try { entries = readdirSync(rel ? join(root, rel) : root, { withFileTypes: true }); } catch (e) { added += 1; fail((rel || ".") + ": the folder cannot be read: " + e.message); return; }
    for (const d of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const path = rel ? rel + "/" + d.name : d.name;
      if (d.isSymbolicLink()) { added += 1; fail(path + ": a symbolic link — a packet holds files only; replace it with the file itself, or verify the packet as it was unzipped"); continue; }
      if (d.isDirectory()) { walk(path); continue; }
      if (!rel && (d.name === "manifest.json" || d.name === "SHA256SUMS")) continue;
      if (listedPaths.has(path)) continue;
      if (OS_LITTER.test(d.name)) { litter += 1; continue; }
      added += 1;
      fail(path + ": in the folder but not listed in manifest.json — a file added after the export; remove it, or verify the packet as it was unzipped");
    }
  };
  walk("");
  if (!added) console.log("ok: every file in the folder is one manifest.json lists" + (litter ? " (" + litter + " file" + (litter === 1 ? "" : "s") + " an operating system writes into a folder it shows ignored — nothing reads " + (litter === 1 ? "it" : "them") + ")" : ""));
}
/** The listed files directly inside a folder of the packet ("anchors", "agents/runtimes"), by name, sorted — what a section reads. */
const listedIn = (dir) => (listedPaths === null ? [] : [...listedPaths].filter((p) => p.startsWith(dir + "/") && !p.slice(dir.length + 1).includes("/")).map((p) => p.slice(dir.length + 1)).sort());
const isListed = (path) => listedPaths !== null && listedPaths.has(path);
const anyListedUnder = (dir) => listedPaths !== null && [...listedPaths].some((p) => p.startsWith(dir + "/"));
const unread = (dir) => console.log("not read: " + dir + "/ — manifest.json could not be read, so no file in the folder is trusted");

// ── 2d. who exported the packet, what was withheld from them, who the people are ──
//
// (2026-10-26, round seven) The rows carried by hash only were counted against
// ledger/head.json and manifest.json, and both are files whoever re-hashes the
// manifest can rewrite: the row that decided a policy turned into a stub, both
// counts restated, and who decided it was no longer checked. And people.json's
// names were trusted as written: two people's names swapped, every name beside
// them renamed to match, and the packet still verified. So: manifest.json names
// who exported the packet, in which role, and the window an examiner's grant
// narrowed it to. An owner or an admin opens every row, so their packet carries
// none by hash only outside such a window. A row that only renames a person,
// changes a role, grants an examiner's access, or removes or erases an account
// names no sheet, so no gate withholds it — only a window. So the only row about
// who people are a gate can withhold is a member's joining (it names their
// sheet), and it can follow a row the reader holds only after a removal. The exporter's role is held to the ledger's
// own rows about them, and every name people.json gives a person to the name
// the ledger's rows last give them, where this reader holds those rows.
const isoMs = (ms) => { const d = new Date(ms); return Number.isNaN(d.getTime()) ? String(ms) : d.toISOString(); };
const said = (v) => JSON.stringify(v === undefined ? null : v);
/** The ledger rows that give an account its name, or its role in this workspace. An erased account is named "Former member". */
const NAME_ROWS = ["member.joined", "member.role_changed", "member.removed", "user.renamed", "account.deleted"];
const ROLE_ROWS = ["member.joined", "member.role_changed", "examiner.granted", "member.removed", "account.deleted"];
const SHEETLESS_ROWS = ["user.renamed", "member.role_changed", "member.removed", "account.deleted", "examiner.granted"];
const FORMER_MEMBER = "Former member";
let win = null, exporter = null;
/** A row or a record carried by hash only that the stated window explains: one that falls outside it. */
const windowExplains = (at) => win !== null && typeof at === "number" && (at < win.from || at > win.to);
const firstRows = (list) => "ledger row seq " + list[0].seq + " (" + (typeof list[0].kind === "string" ? list[0].kind : "no kind") + ")" + (list.length > 1 ? " and " + (list.length - 1) + " more" : "");
let weighed = 0;
if (manifestObj) {
  const by = manifestObj.exported_by;
  if (!by || typeof by !== "object" || typeof by.id !== "string" || typeof by.role !== "string") { weighed += 1; fail("manifest.json does not name who exported the packet and in which role (exported_by: id, name, role), so what was withheld from them cannot be weighed — verify the packet as it was exported"); }
  else exporter = by;
  if (!Object.prototype.hasOwnProperty.call(manifestObj, "window")) { weighed += 1; fail("manifest.json does not say whether an examiner's window narrowed the export (window: null, or its from and to), so what was withheld cannot be weighed — verify the packet as it was exported"); }
  else if (manifestObj.window !== null) {
    const w = manifestObj.window;
    if (!w || typeof w !== "object" || typeof w.from !== "number" || typeof w.to !== "number" || !(w.from <= w.to)) { weighed += 1; fail("manifest.json's window is not a from and a to, in milliseconds"); }
    else win = w;
  }
}
let people = null;
if (listedPaths !== null) {
  // (2026-10-26) people.json is required: without it every name check was skipped and the success line still said the person was checked
  if (!isListed("people.json")) fail("people.json is missing — it names every person the agents' files name and every person a ledger row names, so who decided a policy, released a call or wrote a row cannot be checked; verify the packet as it was exported");
  else {
    const raw = readOr(join(root, "people.json"), "people.json", "utf8");
    let pj = null, read = false;
    if (raw !== null) { try { pj = JSON.parse(raw); read = true; } catch (e) { fail("people.json: not JSON: " + e.message); } }
    if (read && pj && typeof pj === "object" && !Array.isArray(pj)) people = pj;
    else if (read) fail("people.json is not a list of people by id");
  }
}
if (Array.isArray(ledgerRows) && Array.isArray(ledgerStubs) && manifestObj && exporter) {
  const stubs = ledgerStubs;
  if (win) {
    const out = ledgerRows.filter((r) => r && r.withheld !== true && (typeof r.at !== "number" || r.at < win.from || r.at > win.to));
    if (out.length) { weighed += 1; fail(firstRows(out) + " " + (out.length === 1 ? "is" : "are") + " carried whole but " + (out.length === 1 ? "falls" : "fall") + " outside the window manifest.json states (" + isoMs(win.from) + " to " + isoMs(win.to) + ") — a row outside the window is carried by hash only"); }
  }
  if (exporter.role === "owner" || exporter.role === "admin") {
    const unexplained = stubs.filter((s) => !windowExplains(s.at));
    if (unexplained.length) { weighed += 1; fail("manifest.json says " + said(exporter.name) + " exported the packet as " + exporter.role + " — who may open every row — yet " + firstRows(unexplained) + " " + (unexplained.length === 1 ? "is" : "are") + " carried by hash only" + (win ? " inside the window it states" : "") + "; verify the packet as it was exported"); }
  }
  const sheetless = stubs.filter((s) => SHEETLESS_ROWS.includes(s.kind) && !windowExplains(s.at));
  if (sheetless.length) { weighed += 1; fail(firstRows(sheetless) + " " + (sheetless.length === 1 ? "is" : "are") + " carried by hash only, but a row that renames a person, changes a role, grants an examiner's access, or removes or erases an account names no sheet, so no gate withholds it — only a window" + (win ? ", and " + (sheetless.length === 1 ? "it falls" : "they fall") + " inside the one manifest.json states" : ", and manifest.json states none") + "; verify the packet as it was exported"); }
  // the last name and the last role the ledger's own rows give each account, and the last row carried by hash only that could have moved one
  const lastName = new Map(), lastRole = new Map();
  const nameStubs = [], roleStubs = [];
  for (const r of ledgerRows) {
    if (!r || typeof r !== "object") continue;
    if (r.withheld === true) { if (NAME_ROWS.includes(r.kind)) nameStubs.push(r.seq); if (ROLE_ROWS.includes(r.kind)) roleStubs.push(r.seq); continue; }
    if (r.subject_kind !== "user" || typeof r.subject_id !== "string") continue;
    const pl = r.payload && typeof r.payload === "object" ? r.payload : {};
    const name = r.kind === "user.renamed" ? pl.to : r.kind === "account.deleted" ? FORMER_MEMBER : r.kind === "member.joined" || r.kind === "member.role_changed" || r.kind === "member.removed" ? pl.name : undefined;
    if (typeof name === "string" && name) lastName.set(r.subject_id, { seq: r.seq, kind: r.kind, name });
    const role = r.kind === "member.joined" ? pl.role : r.kind === "member.role_changed" ? pl.to : r.kind === "examiner.granted" ? "viewer" : r.kind === "member.removed" || r.kind === "account.deleted" ? null : undefined;
    if (role === null || (typeof role === "string" && role)) lastRole.set(r.subject_id, { seq: r.seq, kind: r.kind, role });
  }
  // a row carried by hash only could have moved what the last row the reader holds says: inside a window any such row; without one only a
  // joining, and only after a removal (every other row about people is never withheld but by a window, above)
  const movedSince = (seen, seqs) => seqs.some((s) => s > seen.seq && (win !== null || seen.kind === "member.removed"));
  if (people) {
    let held = 0, later = 0, unnamed = 0, wrong = 0;
    for (const id of Object.keys(people).sort()) {
      const who = people[id];
      const seen = lastName.get(id);
      // every id the ledger's rows name an account by is held to them, whatever kind people.json gives it (a person re-labelled an agent
      // is still the account the rows name); a person no row names is counted
      if (!seen) { if (who && typeof who === "object" && who.kind === "person") unnamed += 1; continue; }
      if (movedSince(seen, nameStubs)) { later += 1; continue; }
      if (!who || typeof who !== "object" || who.name !== seen.name) { wrong += 1; fail("people.json names " + id + " " + said(who && typeof who === "object" ? who.name : who) + ", but ledger row seq " + seen.seq + " (" + seen.kind + ") — the last row about them this reader holds — names them " + said(seen.name) + "; verify the packet as it was exported"); continue; }
      held += 1;
    }
    if (!wrong) console.log("ok: people.json names " + held + " " + (held === 1 ? "person" : "people") + " as the ledger's own rows last name " + (held === 1 ? "them" : "each") + (later ? "; for " + later + " a later row about who people are is carried by hash only, so " + (later === 1 ? "that name is" : "those names are") + " not checked here" : "") + (unnamed ? "; " + unnamed + " " + (unnamed === 1 ? "is" : "are") + " named by no row this reader holds, so " + (unnamed === 1 ? "that name is" : "those names are") + " not checked here" : ""));
    const listed = people[exporter.id];
    if (listed && typeof listed === "object" && listed.role !== exporter.role) { weighed += 1; fail("manifest.json says " + exporter.id + " exported the packet as " + said(exporter.role) + ", but people.json gives their role as " + said(listed.role)); }
  }
  const seenRole = lastRole.get(exporter.id);
  let roleChecked = false;
  if (seenRole && !movedSince(seenRole, roleStubs)) {
    roleChecked = true;
    if (seenRole.role !== exporter.role) { weighed += 1; fail("manifest.json says " + exporter.id + " exported the packet as " + said(exporter.role) + ", but ledger row seq " + seenRole.seq + " (" + seenRole.kind + ") — the last row about their role this reader holds — gives " + said(seenRole.role) + "; verify the packet as it was exported"); }
  }
  if (!weighed) console.log("ok: manifest.json names who exported the packet (" + exporter.role + (roleChecked ? ", as the ledger's own rows give it" : ", which no row this reader holds gives, so it is not checked against the ledger here") + ")" + (win ? " and the window " + isoMs(win.from) + " to " + isoMs(win.to) + ", every row carried whole inside it" : ", and no window") + "; " + (stubs.length ? stubs.length + " row" + (stubs.length === 1 ? "" : "s") + " carried by hash only, each with its kind and time" + (exporter.role === "owner" || exporter.role === "admin" ? ", each outside the window" : "") : "no row carried by hash only"));
}

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

// (2026-10-26) The receipts are the files manifest.json lists under anchors/ — never whatever else lies in the folder (2c names that).
const anchorsDir = join(root, "anchors");
if (listedPaths === null) {
  unread("anchors");
} else if (!anyListedUnder("anchors")) {
  console.log("ok: no anchor receipts in this packet — the chain stands on its own arithmetic (README, What this proves)");
} else if (!Array.isArray(ledgerRows)) {
  fail("anchors/ is present but the ledger could not be read, so no receipt can be tied to a row");
} else {
  const names = listedIn("anchors");
  const files = names.filter((f) => f.endsWith(".tsr"));
  let index = [];
  const indexPath = join(anchorsDir, "index.json");
  if (names.includes("index.json")) {
    try { index = JSON.parse(readFileSync(indexPath, "utf8")); } catch (e) { fail("anchors/index.json is not JSON: " + e.message); }
  } else fail("anchors/index.json is missing");
  const byHash = new Map(ledgerRows.map((r) => [r.hash, r]));
  let tied = 0, records = 0;
  // a .receipt.json with no token beside it describes nothing
  for (const f of names.filter((f) => f.endsWith(".receipt.json"))) {
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
    if (!names.includes(recFile) || !existsSync(recPath)) continue;
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
if (listedPaths === null) {
  unread("checkpoints");
} else if (!anyListedUnder("checkpoints")) {
  console.log("ok: no checkpoints in this packet — no day's head has been signed and handed outside yet");
} else if (!Array.isArray(ledgerRows)) {
  fail("checkpoints/ is present but the ledger could not be read, so no checkpoint can be tied to a row");
} else {
  const files = listedIn("checkpoints").filter((f) => f.endsWith(".json"));
  const byHash = new Map(ledgerRows.map((r) => [r.hash, r]));
  let good = 0;
  // (2026-10-26) checkpoints/key.pem was never read: each checkpoint verified under the key it carries, whatever key that was. Every
  // checkpoint is signed by the one deployment key, so each must be the key checkpoints/key.pem holds — and agents/issuer.pem too (7)
  let cpKeyId = null;
  if (isListed("checkpoints/key.pem")) {
    const pem = readOr(join(cpDir, "key.pem"), "checkpoints/key.pem", "utf8");
    if (pem !== null) {
      try { cpKeyId = spkiKeyId(pem); } catch (e) { fail("checkpoints/key.pem is not a public key: " + e.message); }
      if (cpKeyId) deploymentKeys.push({ where: "checkpoints/key.pem", id: cpKeyId });
    }
  }
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
    try { keyId = spkiKeyId(c.public_key_pem); } catch (e) { keyId = null; }
    if (c.key_id && keyId !== c.key_id) { fail("checkpoint " + file + ": key id " + c.key_id + " does not match the public key it carries (" + keyId + ")"); continue; }
    if (cpKeyId && keyId !== cpKeyId) { fail("checkpoint " + file + ": signed under key " + keyId + ", not the deployment key in checkpoints/key.pem (" + cpKeyId + ")"); continue; }
    if (keyId) deploymentKeys.push({ where: "checkpoint " + file, id: keyId });
    // the public log's copy (2026-10-26): the entry is fetched by the READER, never by this script — print the command and what to compare
    const entry = c.delivered && c.delivered.log_entry;
    const hasEntry = entry && typeof entry === "object" && typeof entry.uuid === "string";
    const messageSha = sha256(message);
    // since 2026-11-12 the log holds a DSSE envelope of the signed bytes, signed by the same key: its signature is checked here, offline
    if (hasEntry && entry.kind === "dsse") {
      const type = String(entry.payload_type || "");
      const pae = Buffer.concat([Buffer.from("DSSEv1 " + Buffer.byteLength(type, "utf8") + " " + type + " " + message.length + " ", "utf8"), message]);
      let okEnv = false;
      try { okEnv = verifySignature(null, pae, c.public_key_pem, Buffer.from(String(entry.dsse_signature || ""), "base64")); } catch (e) { okEnv = false; }
      if (!okEnv) { fail("checkpoint " + file + ": the public log's envelope signature does not verify over the checkpoint's bytes under the key it carries"); continue; }
      if (entry.payload_sha256 !== messageSha) { fail("checkpoint " + file + ": the public log's entry names payload " + String(entry.payload_sha256).slice(0, 12) + "…, not the SHA-256 of the checkpoint's bytes (" + messageSha.slice(0, 12) + "…)"); continue; }
    }
    good += 1;
    console.log("checkpoint " + file + ": signature verifies, head seq " + row.seq + " (" + c.day + ", key " + keyId + ")");
    if (hasEntry) {
      const base = typeof entry.url === "string" ? entry.url.replace(/\/api\/v1\/log\/entries\/?$/, "") : "https://rekor.sigstore.dev";
      const named = entry.logIndex !== undefined && entry.logIndex !== null ? entry.logIndex : entry.uuid;
      const landed = entry.integratedTime ? " (" + new Date(Number(entry.integratedTime) * 1000).toISOString() + " when the post landed — the log witnesses the head from then, which for an entry posted after its day is later than the day)" : "";
      if (entry.kind === "dsse") {
        console.log("checkpoint " + file + ": a copy reached the public log (entry " + named + ") as a DSSE envelope of the signed bytes (" + entry.payload_type + "); the envelope's signature verifies under the same key. Fetch the entry yourself — this script makes no network call:");
        console.log("    curl -s " + base + "/api/v1/log/entries/" + entry.uuid);
        console.log("    then base64-decode the entry's \"body\": its kind is dsse, its spec.payloadHash.value must be " + messageSha + " (SHA-256 of the signed bytes), its spec.signatures[0].signature must be the envelope signature (" + String(entry.dsse_signature).slice(0, 16) + "…, checked above), and its spec.signatures[0].verifier base64-decodes to the key in checkpoints/key.pem; the entry's integratedTime is the log's own clock" + landed + ".");
      } else {
        console.log("checkpoint " + file + ": a copy reached the public log (entry " + named + "). Fetch it yourself — this script makes no network call:");
        console.log("    curl -s " + base + "/api/v1/log/entries/" + entry.uuid);
        console.log("    then base64-decode the entry's \"body\": its spec.data.hash.value must be " + messageSha + " (SHA-256 of the signed bytes), its spec.signature.content must be the file's signature (" + String(c.signature).slice(0, 16) + "…), and its spec.signature.publicKey.content base64-decodes to the key in checkpoints/key.pem; the entry's integratedTime is the log's own clock" + landed + ".");
      }
    }
  }
  if (good === files.length) console.log("ok: " + good + " checkpoint" + (good === 1 ? " names" : "s name") + " a ledger row and verif" + (good === 1 ? "ies" : "y") + " under the key in checkpoints/key.pem");
}

// ── 7. the AI agents' decision records ─────────────────────────────────────
// Every enforcer keeps ONE chain of decision records (agents/runtimes/<id>.json)
// and signs the Merkle root of each batch of records (a seal). A record's hash
// is SHA-256 over its 190 packed bytes, integers little-endian:
//   seq u64 · at u64 (ms) · runtime 8 · session 8 · agent 32 · bundle 32 ·
//   tool index u16 · scope index u16 · decision u8 · rule u8 · trace 16 (the
//   first 16 bytes of SHA-256 over the trace id) · calls u32 · spend u32
//   (cents) · approver 32 (zeros when none) · prev 32 (zeros before seq 1).
// A seal's root: each leaf SHA-256(0x00 ‖ record hash), each node
// SHA-256(0x01 ‖ left ‖ right), an odd one out paired with itself; the
// runtime's Ed25519 key signs SHA-256(runtime 8 ‖ batch u32 ‖ from u64 ‖ to
// u64 ‖ root 32 ‖ at u64). A runtime's id is the first 8 bytes of SHA-256
// over its raw public key. An approved policy (agents/<agent>/keys.json and
// agents/layers.json) is its signed body followed by a 64-byte Ed25519
// signature by the key in agents/issuer.pem; its hash is SHA-256 over the
// body, and the ledger row that decided it is named by seq and hash.
// A record carries the hash of the policy it ran under (the agent's approved
// policy, or with layers SHA-256("MNVC" ‖ the sorted hashes of the policy and
// its layers)) and the INDEX of its tool and scope class in that policy's
// signed dictionary; the tool's NAME beside it is not in the record's hash, so
// it is resolved here against the signed bytes, and the agent the policy was
// decided for against the record's own.
// The key's header, as compileKey writes it (offsets in the signed body,
// integers little-endian): "MNVK" 0 · version 4 · flags 5 · issuer key id
// 6..14 · tools u16 14 · scopes u16 16 · roles u8 18 · refused approvers u16
// 19 · the agent (SHA-256 of its identity) 21..53 · the deciding ledger
// row's seq u64 53 and hash 61..93 · the window's opening u64 93 and close
// u64 101 (seconds) · the revision it replaces 109..141 · the roster
// 141..173 · the limits 173..181; then the dictionary.
// What is NOT checked here: whether each decision is what the approved
// policy decides for that call (the product's monitor replays that), which
// scope class a resource's path falls in (the enforcer's prefix rule),
// whether a bank's runtime key is the key its own enforcer holds, who a
// bank's runtime named as a release's approver when approvals.json does not
// (the bank confirms both), and that the person sheet approvals.json names
// for a release is the approver's own (the workspace links each account to
// one sheet). A release's 32 approver bytes are SHA-256 over the 32 bytes of
// SHA-256("person:" ‖ that sheet's id) — the key a release through the
// product's door presents. The document beside an agent's policy is a
// readable copy: the signed bytes are what a runtime enforces.
const DECISION_CODES = ["PERMIT", "FORBID", "HOLD"];
/** The ledger rows a policy's header may name (server/policy/inspect.ts KEY_ROW_KINDS): a proposal accepted, and the kill switch pressed by its holder. */
const KEY_ROW_KINDS = ["proposal.decided", "policy.suspended"];
const RULE_CODES = ["permitted", "no-policy", "window", "unregistered", "not-permitted", "budget", "consent", "approval-required", "approval-invalid", "declined"];
const ZERO32 = "0".repeat(64);
const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b; };
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
const hexBuf = (h) => Buffer.from(String(h), "hex");
const sha256Buf = (...parts) => { const h = createHash("sha256"); for (const p of parts) h.update(p); return h.digest(); };
function recordHashOf(r) {
  return sha256Buf(Buffer.concat([
    u64(r.seq), u64(r.at), hexBuf(r.runtime), hexBuf(r.session), hexBuf(r.agent), hexBuf(r.bundle), u16(r.ti), u16(r.si),
    Buffer.from([Math.max(0, DECISION_CODES.indexOf(r.decision))]), Buffer.from([Math.max(0, RULE_CODES.indexOf(r.rule))]),
    sha256Buf(Buffer.from(String(r.trace))).subarray(0, 16), u32(r.calls), u32(r.spend_cents), r.approver ? hexBuf(r.approver) : Buffer.alloc(32), hexBuf(r.prev),
  ])).toString("hex");
}
function merkleRootOf(hashes) {
  if (!hashes.length) return ZERO32;
  let level = hashes.map((h) => sha256Buf(Buffer.from([0]), hexBuf(h)));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256Buf(Buffer.from([1]), level[i], level[i + 1] || level[i]));
    level = next;
  }
  return level[0].toString("hex");
}
/** The signed dictionary of an approved policy: the agent it was decided for, its tools and its scope classes, read from its bytes. */
function keyDictionary(bytes) {
  const body = bytes.subarray(0, bytes.length - 64);
  if (body.length < 181 || body.subarray(0, 4).toString("latin1") !== "MNVK") return null;
  const T = body.readUInt16LE(14), S = body.readUInt16LE(16);
  let o = 181;
  const str = () => { if (o + 2 > body.length) throw new Error("truncated"); const n = body.readUInt16LE(o); o += 2; if (o + n > body.length) throw new Error("truncated"); const v = body.subarray(o, o + n).toString("utf8"); o += n; return v; };
  try {
    const tools = [];
    for (let i = 0; i < T; i += 1) { tools.push(str()); str(); }
    const scopes = [];
    for (let i = 0; i < S; i += 1) scopes.push(str());
    return { agent: body.subarray(21, 53).toString("hex"), tools, scopes };
  } catch (e) { return null; }
}
/** The approver field a release through the product's door carries for a person sheet: SHA-256 over the 32 bytes of SHA-256("person:" ‖ its id). */
const approverKeyOf = (sheet) => sha256Buf(sha256Buf(Buffer.from("person:" + sheet))).toString("hex");
function rawKeyId(pem) {
  const x = createPublicKey(pem).export({ format: "jwk" }).x;
  return sha256Buf(Buffer.from(String(x), "base64url")).subarray(0, 8).toString("hex");
}
/** What a policy's signed header names (body offsets, little-endian): the deciding row, the window, the revision it replaces — or null. */
function headerOf(k) {
  const bytes = Buffer.from(String((k && k.bytes_base64) || ""), "base64");
  if (bytes.length < 64 + 181) return null;
  const body = bytes.subarray(0, bytes.length - 64);
  if (body.subarray(0, 4).toString("latin1") !== "MNVK") return null;
  return { seq: body.readBigUInt64LE(53).toString(), rowHash: body.subarray(61, 93).toString("hex"), opens: Number(body.readBigUInt64LE(93)), closes: Number(body.readBigUInt64LE(101)), replaces: body.subarray(109, 141).toString("hex") };
}
const agentsDir = join(root, "agents");
/** The rows this reader holds whole, the last deletion or restoration of each sheet, and every approval of a policy the ledger records (round seven). */
const visibleRows = (Array.isArray(ledgerRows) ? ledgerRows : []).filter((r) => r && typeof r === "object" && r.withheld !== true);
const byLedgerSeq = new Map((Array.isArray(ledgerRows) ? ledgerRows : []).filter((r) => r && typeof r === "object").map((r) => [r.seq, r]));
const lastSheetMove = new Map();
for (const r of visibleRows) if ((r.kind === "node.deleted" || r.kind === "node.restored") && r.subject_kind === "node") lastSheetMove.set(r.subject_id, r);
const approvalsOnLedger = visibleRows.filter((r) => r.kind === "policy.decided" && r.payload && typeof r.payload === "object" && typeof r.payload.hash === "string");
if (listedPaths === null) {
  unread("agents");
} else if (!anyListedUnder("agents")) {
  // (round seven) agents/ left out of the packet whole: every approval the ledger records still names a policy that must be here
  if (approvalsOnLedger.length) fail("agents/ is not in this packet, but " + approvalsOnLedger.length + " ledger row" + (approvalsOnLedger.length === 1 ? " records" : "s record") + " a policy approved (first: seq " + approvalsOnLedger[0].seq + ") — the agents' files were left out of the packet; verify the packet as it was exported");
  else if (manifestObj && (manifestObj.agents || manifestObj.agents_off_register || manifestObj.agent_records)) fail("manifest.json says the export carried " + said(manifestObj.agents) + " agent" + (manifestObj.agents === 1 ? "" : "s") + " and " + said(manifestObj.agent_records) + " decision record" + (manifestObj.agent_records === 1 ? "" : "s") + ", but agents/ is not in this packet — verify the packet as it was exported");
  else console.log("ok: no AI agents in this packet — no agent stands on the record this reader may open");
} else {
  const chains = new Map();
  const labels = new Map();
  let records = 0, withheldRecords = 0, seals = 0, chainsOk = 0, recordsListed = 0, withheldListed = 0;
  /** The decision records carried by hash only, each with its time (round seven): an owner's packet carries none outside a window. */
  const recordStubs = [];
  // (2026-10-26) the chains, the agents and their files are the ones manifest.json lists — a runtime's chain or an agent folder added
  // after the export is never read here (2c names it)
  const rtFiles = listedIn("agents/runtimes").filter((f) => f.endsWith(".json"));
  for (const file of rtFiles) {
    let c;
    try { c = JSON.parse(readFileSync(join(agentsDir, "runtimes", file), "utf8")); } catch (e) { fail("agents/runtimes/" + file + ": not JSON: " + e.message); continue; }
    const name = String(c.runtime).slice(0, 8);
    const recs = Array.isArray(c.records) ? c.records : [];
    recordsListed += recs.length;
    for (const r of recs) if (r && r.withheld === true) { withheldListed += 1; recordStubs.push({ runtime: String(c.runtime), seq: r.seq, at: r.at }); }
    let id = null;
    try { id = rawKeyId(c.public_key_pem); } catch (e) { id = null; }
    if (id !== c.runtime) { fail("runtime " + name + ": its public key gives the id " + id + ", not " + c.runtime); continue; }
    let prev = ZERO32, expect = 1, broke = null;
    const bySeq = new Map();
    for (const r of recs) {
      if (r.seq !== expect) { broke = "seq " + r.seq + (r.seq > expect ? ": records " + expect + "…" + (r.seq - 1) + " are missing" : ": out of order (expected " + expect + ")"); break; }
      if (r.prev !== prev) { broke = "seq " + r.seq + ": prev does not name the hash of the record before it"; break; }
      if (r.withheld === true) withheldRecords += 1;
      else {
        const h = recordHashOf(r);
        if (h !== r.hash) { broke = "seq " + r.seq + ": recomputed hash " + h.slice(0, 12) + "… differs from the stored hash " + String(r.hash).slice(0, 12) + "…"; break; }
      }
      bySeq.set(r.seq, r);
      prev = r.hash; expect += 1;
    }
    if (broke) { fail("runtime " + name + " (" + c.label + "): " + broke); continue; }
    let covered = 0, sealBroke = null;
    for (const s of (Array.isArray(c.seals) ? c.seals : []).slice().sort((a, b) => a.batch - b.batch)) {
      if (s.from !== covered + 1 || s.to < s.from) { sealBroke = "seal " + s.batch + " covers seq " + s.from + "…" + s.to + ", but the next unsealed record is seq " + (covered + 1); break; }
      const leaves = [];
      for (let q = s.from; q <= s.to; q += 1) { const r = bySeq.get(q); if (!r) break; leaves.push(r.hash); }
      if (leaves.length !== s.to - s.from + 1) { sealBroke = "seal " + s.batch + " covers records that are not in the chain"; break; }
      if (merkleRootOf(leaves) !== s.root) { sealBroke = "seal " + s.batch + ": its root is not the root of the records it covers"; break; }
      const message = sha256Buf(hexBuf(c.runtime), u32(s.batch), u64(s.from), u64(s.to), hexBuf(s.root), u64(s.at));
      let okSig = false;
      try { okSig = verifySignature(null, message, c.public_key_pem, hexBuf(s.sig)); } catch (e) { okSig = false; }
      if (!okSig) { sealBroke = "seal " + s.batch + ": the runtime's signature on its root does not verify"; break; }
      covered = s.to; seals += 1;
    }
    if (sealBroke) { fail("runtime " + name + " (" + c.label + "): " + sealBroke); continue; }
    chains.set(c.runtime, bySeq);
    labels.set(c.runtime, String(c.label));
    records += recs.length; chainsOk += 1;
    console.log("runtime " + name + " (" + c.label + "): " + recs.length + " records chain and recompute, " + (covered ? "sealed up to seq " + covered : "no seal yet") + (recs.length > covered ? ", " + (recs.length - covered) + " in the open tail" : ""));
  }
  if (chainsOk === rtFiles.length) console.log("ok: " + records + " decision record" + (records === 1 ? "" : "s") + " on " + chainsOk + " runtime" + (chainsOk === 1 ? "" : "s") + " chain and recompute" + (withheldRecords ? " (" + withheldRecords + " withheld from this reader, carried by hash only)" : "") + "; " + seals + " seal" + (seals === 1 ? "" : "s") + " verif" + (seals === 1 ? "ies" : "y") + " under the runtime's key");
  // (round seven) an owner or an admin opens every agent's record: their packet carries no decision record by hash only outside a window
  if (exporter && (exporter.role === "owner" || exporter.role === "admin")) {
    const unexplained = recordStubs.filter((s) => !windowExplains(s.at));
    if (unexplained.length) fail("manifest.json says " + said(exporter.name) + " exported the packet as " + exporter.role + " — who may open every agent's record — yet decision seq " + unexplained[0].seq + " on runtime " + unexplained[0].runtime.slice(0, 8) + (unexplained.length > 1 ? " and " + (unexplained.length - 1) + " more" : "") + " " + (unexplained.length === 1 ? "is" : "are") + " carried by hash only" + (win ? " inside the window it states" : "") + "; verify the packet as it was exported");
  }

  // the approved policies: hash over the body, the issuer's signature, and what the signature covers — the deciding ledger row and the window
  const readJson = (rel) => { try { return JSON.parse(readFileSync(join(root, rel), "utf8")); } catch (e) { fail(rel + ": not JSON: " + e.message); return null; } };
  let issuerPem = null;
  if (isListed("agents/issuer.pem")) { try { issuerPem = readFileSync(join(agentsDir, "issuer.pem"), "utf8"); } catch (e) { fail("agents/issuer.pem cannot be read: " + e.message); } }
  else fail("agents/issuer.pem is missing");
  const issuerId = issuerPem ? (() => { try { return rawKeyId(issuerPem); } catch (e) { return null; } })() : null;
  const byLedgerHash = new Map((Array.isArray(ledgerRows) ? ledgerRows : []).map((r) => [r.hash, r]));
  // (2026-10-26) the issuer was trusted on its own word: whoever held the packet could make a key, re-sign every policy with it and point a
  // policy at another decision, and it still verified. One deployment key signs every approved policy and every checkpoint — and each
  // checkpoint left the building the day it was signed, and the ledger's checkpoint rows name its key — so the issuer must be that key
  const issuerSpki = issuerPem ? (() => { try { return spkiKeyId(issuerPem); } catch (e) { return null; } })() : null;
  for (const r of visibleRows) if (r.kind === "checkpoint.recorded" && r.payload && typeof r.payload.key_id === "string") deploymentKeys.push({ where: "ledger row seq " + r.seq + " (a checkpoint recorded)", id: r.payload.key_id });
  if (issuerSpki) {
    const off = deploymentKeys.filter((k) => k.id !== issuerSpki);
    if (off.length) fail("agents/issuer.pem (key " + issuerSpki + ") is not the deployment key " + off[0].where + " carries (key " + off[0].id + ")" + (off.length > 1 ? ", nor the one " + (off.length - 1) + " other place" + (off.length === 2 ? "" : "s") + " name" + (off.length === 2 ? "s" : "") : "") + " — one deployment key signs every approved policy and every checkpoint; verify the packet as it was exported");
    else {
      // (round seven) the line names only the places that were there to compare: a checkpoint file, a checkpoint row this reader holds
      const where = [];
      if (deploymentKeys.some((k) => k.where.startsWith("checkpoint"))) where.push("every checkpoint here was signed with");
      if (deploymentKeys.some((k) => k.where.startsWith("ledger row"))) where.push("the ledger's checkpoint rows name");
      console.log(where.length ? "ok: agents/issuer.pem is the deployment key " + where.join(" and ") + " (key " + issuerSpki + ")" : "ok: agents/issuer.pem (key " + issuerSpki + ") — no checkpoint in this packet, and no checkpoint row this reader holds, to compare it with, so the key is taken as the packet states it; each policy below is held to the ledger rows that approved it where this reader holds them");
    }
  }
  // the ledger's own record of every approval (2026-10-26): a policy.decided row names the policy's hash, the row that decided it, the
  // revision, what it replaced and the layers it was decided over — in the chain the time-stamp authorities witnessed
  const approvedBy = new Map(), replacedBy = new Map();
  for (const r of visibleRows) {
    if (r.kind !== "policy.decided" || !r.payload || typeof r.payload !== "object") continue;
    if (typeof r.payload.hash === "string") { const a = approvedBy.get(r.payload.hash) || []; a.push(r); approvedBy.set(r.payload.hash, a); }
    if (typeof r.payload.replaces === "string") { const a = replacedBy.get(r.payload.replaces) || []; a.push(r); replacedBy.set(r.payload.replaces, a); }
  }
  /** The approvals carried by hash only (round seven): a retirement may rest on one only where the window explains it. */
  const policyStubs = (Array.isArray(ledgerStubs) ? ledgerStubs : []).filter((s) => s.kind === "policy.decided");
  const iso = (s) => { const d = new Date(s * 1000); return Number.isNaN(d.getTime()) ? s + " (seconds)" : d.toISOString(); };
  let keys = 0, keysBad = 0, unseenDeciders = 0, decidedHeld = 0, floorsHeld = 0, retiredUnseen = 0;
  // (2026-10-26) keys.json beside the bytes said who decided a policy, by which ledger row and for how long, and nothing held those words
  // to the bytes: a policy could be re-pointed at a row the developer wrote, or at the developer's name, and still verify. The header
  // the issuer signed names the deciding row's seq and hash and the window (body offsets 53, 61, 93, 101, little-endian); keys.json must
  // say the same, and the row must be a decision that APPROVED it — a proposal accepted, or the kill switch pressed by its holder (the
  // two rows a key may name) — about this agent, written by the person keys.json names. A rulebook floor names no row: its header
  // carries the SHA-256 of its own text, which the document beside it must reproduce.
  const checkKey = (where, k, about, siblings) => {
    const bytes = Buffer.from(String(k.bytes_base64 || ""), "base64");
    if (bytes.length <= 64 + 14) { keysBad += 1; return fail(where + " rev " + k.rev + ": its bytes are missing"); }
    const body = bytes.subarray(0, bytes.length - 64), sig = bytes.subarray(bytes.length - 64);
    if (sha256Buf(body).toString("hex") !== k.hash) { keysBad += 1; return fail(where + " rev " + k.rev + ": SHA-256 over its body is not the hash it carries"); }
    const issuer = body.subarray(6, 14).toString("hex");
    if (issuerId && issuer !== issuerId) { keysBad += 1; return fail(where + " rev " + k.rev + ": issued by key " + issuer + ", not the key in agents/issuer.pem (" + issuerId + ")"); }
    let okSig = false;
    try { okSig = verifySignature(null, body, issuerPem, sig); } catch (e) { okSig = false; }
    if (!okSig) { keysBad += 1; return fail(where + " rev " + k.rev + ": the signature does not verify under agents/issuer.pem"); }
    if (body.length < 181 || body.subarray(0, 4).toString("latin1") !== "MNVK") { keysBad += 1; return fail(where + " rev " + k.rev + ": its signed bytes are not a policy in the format this script reads"); }
    const seq = body.readBigUInt64LE(53).toString(), rowHash = body.subarray(61, 93).toString("hex");
    const opens = Number(body.readBigUInt64LE(93)), closes = Number(body.readBigUInt64LE(101));
    const signedReplaces = body.subarray(109, 141).toString("hex");
    const says = [];
    const kw = k.window && typeof k.window === "object" ? k.window : {};
    if (Date.parse(kw.not_before) !== opens * 1000) says.push("keys.json says its window opens " + JSON.stringify(kw.not_before === undefined ? null : kw.not_before) + ", the signed bytes say " + iso(opens));
    if (Date.parse(kw.expires) !== closes * 1000) says.push("keys.json says its window closes " + JSON.stringify(kw.expires === undefined ? null : kw.expires) + ", the signed bytes say " + iso(closes));
    // what it replaced (2026-10-26): the header names the revision before it, all zeros for a first one — keys.json must say the same
    const replacesSaid = k.replaces === null || k.replaces === undefined ? ZERO32 : String(k.replaces);
    if (replacesSaid !== signedReplaces) says.push("keys.json says it replaces " + (replacesSaid === ZERO32 ? "nothing" : replacesSaid.slice(0, 12) + "…") + ", the signed bytes say " + (signedReplaces === ZERO32 ? "nothing" : signedReplaces.slice(0, 12) + "…"));
    const decided = k.decided_seq !== null && k.decided_seq !== undefined;
    if (k.kind === "floor") {
      if (decided) says.push("keys.json names a decision, but a rulebook floor is issued from its own text, never decided on the ledger");
      else if (seq !== "0") says.push("its signed bytes name ledger row seq " + seq + ", but a rulebook floor names no row");
      else if (sha256(typeof k.document === "string" ? k.document : JSON.stringify(k.document, null, 2)) !== rowHash) says.push("its document is not the text its signed bytes name (SHA-256 " + rowHash.slice(0, 12) + "…)");
      // (2026-10-26) nobody decides a floor: a decider or a decision time beside one names a decision that never was
      if ([k.decided_by, k.decided_by_name, k.decided_at].some((v) => v !== null && v !== undefined)) says.push("keys.json names who decided it or when (" + [k.decided_by_name, k.decided_by, k.decided_at].filter((v) => v !== null && v !== undefined).map((v) => JSON.stringify(v)).join(", ") + "), but a rulebook floor is issued from its own text and decided by no one");
    } else if (!decided) says.push("keys.json names no decision, but its signed bytes name ledger row seq " + seq);
    else if (String(k.decided_seq) !== seq || k.decided_hash !== rowHash) says.push("keys.json names the decision at seq " + k.decided_seq + " (" + String(k.decided_hash).slice(0, 12) + "…), its signed bytes name seq " + seq + " (" + rowHash.slice(0, 12) + "…)");
    if (says.length) { keysBad += 1; return fail(where + " rev " + k.rev + ": " + says.join("; ")); }
    let unseen = false;
    if (k.kind !== "floor") {
      const row = byLedgerHash.get(rowHash);
      if (!row || String(row.seq) !== seq) { keysBad += 1; return fail(where + " rev " + k.rev + ": no ledger row seq " + seq + " carries the hash of the decision it names"); }
      const why = [];
      // the sheet it governs: the agent's folder, or for a layer the sheet keys.json names (the root for a ceiling, the vendor for a passport)
      const target = about !== null ? about : typeof k.node === "string" ? k.node : null;
      // (2026-10-26) the ledger's own record of this approval: the policy.decided row the same decision wrote, naming this policy's hash and
      // that deciding row. keys.json's revision, what it replaced, its layers, when it was decided and when it was retired were plain words
      // beside the bytes, and a swapped revision, a dropped retirement or a moved date still verified. The two rows are written together
      // about one sheet at one moment, so a reader holds both or neither: a deciding row carried by hash only beside a record the reader
      // does hold is checked against the record
      const rec = (approvedBy.get(String(k.hash)) || []).find((r) => r.payload && String(r.payload.decided_seq) === seq && r.payload.decided_hash === rowHash);
      if (row.kind !== undefined && !KEY_ROW_KINDS.includes(row.kind)) why.push("ledger row seq " + seq + " is a " + row.kind + " row, not a decision");
      else {
        if (row.withheld === true) {
          if (!rec) { unseenDeciders += 1; unseen = true; }
          // (round seven) a decision and the window its policy opens are one moment: the signed window opens the second the deciding row was
          // written, so a row carried by hash only keeps that time — moved, it no longer is the decision the policy names
          if (typeof row.at === "number" && Math.floor(row.at / 1000) !== opens) why.push("ledger row seq " + seq + ", the decision that approved it, carried by hash only, says it was written at " + isoMs(row.at) + ", but the policy's signed window opens " + iso(opens) + " — a decision and the window it opens are one moment");
          // (round seven) the packet carries this policy, so its reader may open the sheet it governs: only a window withholds its decision
          if (!windowExplains(row.at)) why.push("ledger row seq " + seq + ", the decision that approved it, is carried by hash only — but the packet carries this policy, so its reader may open the sheet it governs, and only a window withholds such a row" + (win ? "; the row falls inside the window manifest.json states" : "; manifest.json states none"));
        } else {
          if (row.kind === "proposal.decided" && !(row.payload && row.payload.decision === "accept")) why.push("ledger row seq " + seq + " turned its proposal down, so nothing was approved there");
          if (row.actor_id !== k.decided_by) why.push("keys.json says " + JSON.stringify(k.decided_by === undefined ? null : k.decided_by) + " decided it, but ledger row seq " + seq + " was written by " + JSON.stringify(row.actor_id));
          if (target !== null && (row.subject_kind !== "node" || row.subject_id !== target)) why.push("ledger row seq " + seq + " is about " + JSON.stringify(row.subject_id) + ", not " + (about !== null ? "this agent" : JSON.stringify(target)));
          if (!rec) why.push("no policy.decided row on the ledger records that ledger row seq " + seq + " approved this policy (" + String(k.hash).slice(0, 12) + "…)");
          else if (Date.parse(k.decided_at) !== row.at) why.push("keys.json says it was decided at " + said(k.decided_at) + ", ledger row seq " + seq + " was written at " + isoMs(row.at));
        }
        if (rec) {
          if (rec.actor_id !== k.decided_by) why.push("keys.json says " + said(k.decided_by) + " decided it, but the ledger's record of the approval, row seq " + rec.seq + ", was written by " + JSON.stringify(rec.actor_id));
          if (target !== null && rec.subject_id !== target) why.push("the ledger's record of the approval, row seq " + rec.seq + ", is about " + JSON.stringify(rec.subject_id) + ", not " + (about !== null ? "this agent" : JSON.stringify(target)));
          if (rec.payload.rev !== k.rev) why.push("keys.json says rev " + said(k.rev) + ", ledger row seq " + rec.seq + " recorded rev " + said(rec.payload.rev));
          const recReplaces = typeof rec.payload.replaces === "string" ? rec.payload.replaces : null;
          const keyReplaces = k.replaces === null || k.replaces === undefined ? null : String(k.replaces);
          if (recReplaces !== keyReplaces) why.push("keys.json says it replaces " + (keyReplaces ? keyReplaces.slice(0, 12) + "…" : "nothing") + ", ledger row seq " + rec.seq + " recorded " + (recReplaces ? recReplaces.slice(0, 12) + "…" : "nothing"));
          if (canon(Array.isArray(rec.payload.layers) ? rec.payload.layers : []) !== canon(Array.isArray(k.layers) ? k.layers : [])) why.push("keys.json names other layers than the ones ledger row seq " + rec.seq + " recorded it was decided over");
          if (Date.parse(k.decided_at) !== rec.at) why.push("keys.json says it was decided at " + said(k.decided_at) + ", ledger row seq " + rec.seq + " recorded the approval at " + isoMs(rec.at));
          // when it was retired: the decision that replaced it, on the same sheet — or, when no row the reader holds replaced it, never.
          // (round seven) A retirement used to go unchecked whenever ANY row was carried by hash only: one unrelated stub switched it off.
          // Now it rests only on the approval that replaced it, carried by hash only at that very moment after this one — and the window
          // must explain that stub — and, for an agent's policy, on a later revision in the same keys.json whose signed bytes replace it
          const next = (replacedBy.get(String(k.hash)) || []).find((r) => r.subject_id === rec.subject_id);
          const retired = k.retired_at === null || k.retired_at === undefined ? null : k.retired_at;
          if (next && Date.parse(retired) !== next.at) why.push("keys.json says " + (retired === null ? "it still stands" : "it was retired at " + JSON.stringify(retired)) + ", but ledger row seq " + next.seq + " replaced it at " + isoMs(next.at));
          else if (!next && retired !== null) {
            const stub = policyStubs.find((s) => s.seq > rec.seq && s.at === Date.parse(retired));
            const successor = about === null || (Array.isArray(siblings) && siblings.some((k2) => k2 !== k && (headerOf(k2) || {}).replaces === String(k.hash)));
            if (!stub || !windowExplains(stub.at)) why.push("keys.json says it was retired at " + JSON.stringify(retired) + ", but no decision on the ledger replaced it" + (stub ? " — the approval carried by hash only at that moment, seq " + stub.seq + ", is one this reader may open, and only a window withholds such a row" : ""));
            else if (!successor) why.push("keys.json says it was retired at " + JSON.stringify(retired) + ", but no later revision in keys.json names it as the one it replaces");
            else retiredUnseen += 1;
          }
        }
      }
      if (why.length) { keysBad += 1; return fail(where + " rev " + k.rev + ": " + why.join("; ")); }
    }
    if (people && k.decided_by_name !== null && k.decided_by_name !== undefined) {
      const named = people[k.decided_by];
      if (!named || named.name !== k.decided_by_name) { keysBad += 1; return fail(where + " rev " + k.rev + ": keys.json names the decider " + JSON.stringify(k.decided_by_name) + ", people.json names " + JSON.stringify(named ? named.name : null) + " for " + JSON.stringify(k.decided_by)); }
    }
    keys += 1;
    if (k.kind !== "floor" && !unseen) decidedHeld += 1;
  };
  const layers = isListed("agents/layers.json") ? readJson("agents/layers.json") : [];
  if (!isListed("agents/layers.json")) fail("agents/layers.json is missing — the rulebook floors, the ceiling and the passports the policies were decided over cannot be checked; verify the packet as it was exported");
  for (const k of Array.isArray(layers) ? layers : []) checkKey("layer " + k.kind, k, null, layers);
  // (round seven) a rulebook floor's revision and retirement were plain words: rev 9 and a retirement nobody made both verified. The packet
  // carries every revision of every floor; each one's signed bytes name the revision it replaced (zeros for the first), and its window
  // opens the second it was issued — so its revision is the one it replaced plus one, it was issued when its window opens, and it was
  // retired the moment the revision that replaced it was issued, or never
  const floors = (Array.isArray(layers) ? layers : []).filter((k) => k && k.kind === "floor");
  for (const f of floors) {
    const h = headerOf(f);
    if (!h) continue; // its own check above named it
    const says = [];
    const issued = Date.parse(f.issued_at);
    if (!(Math.floor(issued / 1000) === h.opens)) says.push("keys.json says it was issued at " + said(f.issued_at) + ", but its signed window opens " + iso(h.opens));
    if (h.replaces === ZERO32) { if (f.rev !== 1) says.push("keys.json says rev " + said(f.rev) + ", but its signed bytes replace no earlier floor, so it is rev 1"); }
    else {
      const prev = floors.find((g) => String(g.hash) === h.replaces);
      if (!prev) says.push("its signed bytes say it replaces " + h.replaces.slice(0, 12) + "…, a floor revision agents/layers.json does not carry");
      else if (f.rev !== prev.rev + 1) says.push("keys.json says rev " + said(f.rev) + ", but it replaces rev " + said(prev.rev) + ", so it is rev " + (Number(prev.rev) + 1));
    }
    const next = floors.find((g) => g !== f && (headerOf(g) || {}).replaces === String(f.hash));
    const retired = f.retired_at === null || f.retired_at === undefined ? null : f.retired_at;
    if (next && Date.parse(retired) !== Date.parse(next.issued_at)) says.push("keys.json says " + (retired === null ? "it still stands" : "it was retired at " + JSON.stringify(retired)) + ", but rev " + said(next.rev) + " replaced it when it was issued, " + said(next.issued_at));
    else if (!next && retired !== null) says.push("keys.json says it was retired at " + JSON.stringify(retired) + ", but no floor revision in agents/layers.json replaced it");
    if (says.length) { keysBad += 1; fail("layer floor rev " + f.rev + ": " + says.join("; ")); }
    else floorsHeld += 1;
  }
  // the product's own runtime signs its seals with the deployment's key, so its id is the issuer's
  const builtin = issuerId;
  const claimed = new Map();
  let agents = 0, offAgents = 0, placed = 0, misplaced = 0, resolved = 0, unresolved = 0, misnamed = 0, released = 0, unnamedOwn = 0, unnamedBank = 0, approvalsBad = 0;
  const NONE = 0xffff;
  // (round seven) an agent's folder carries controls.json when the agent is on the register, off-register.json when it is not (deleted, or
  // a sheet an expert or the built-in analyst acts through) — and always its approved policies, decisions, approvals, declines and runtimes:
  // a file left out hid what it held (its decisions read as drift, its releases as unnamed)
  const FOLDER_FILES = ["keys.json", "decisions.json", "approvals.json", "declines.json", "runtimes.json"];
  const dirs = new Map();
  for (const p of listedPaths) {
    const m = /^agents\/([^/]+)\/([^/]+)$/.exec(p);
    if (!m || m[1] === "runtimes") continue;
    const set = dirs.get(m[1]) || new Set();
    set.add(m[2]);
    dirs.set(m[1], set);
  }
  const folders = [];
  for (const d of [...dirs.keys()].sort()) {
    const files = dirs.get(d);
    const reg = files.has("controls.json"), off = files.has("off-register.json");
    if (reg && off) { fail("agents/" + d + "/ carries both controls.json and off-register.json — an agent stands on the register or off it"); continue; }
    if (!reg && !off) { fail("agents/" + d + "/ carries " + [...files].sort().join(", ") + " but neither controls.json nor off-register.json — verify the packet as it was exported"); continue; }
    const missing = FOLDER_FILES.filter((f) => !files.has(f));
    if (missing.length) fail("agents/" + d + "/ is missing " + missing.join(", ") + " — every agent's folder carries its approved policies, decisions, approvals, declines and runtimes, and a file left out hides what it holds; verify the packet as it was exported");
    folders.push({ d, off });
  }
  // (round seven) a runtime the ledger registered for an agent carried here: its whole chain is carried too — a chain left out took every
  // record on it, and its releases, with it
  const chainsListed = new Set(rtFiles.map((f) => f.replace(/\.json$/, "")));
  const folderIds = new Set(folders.map((f) => f.d));
  const chainsMissing = visibleRows.filter((r) => r.kind === "policy.runtime" && r.payload && typeof r.payload.runtime === "string" && folderIds.has(r.subject_id) && !chainsListed.has(r.payload.runtime));
  for (const r of chainsMissing.slice(0, 3)) fail("ledger row seq " + r.seq + " registered runtime " + String(r.payload.runtime).slice(0, 8) + " for agent " + r.subject_id + ", but agents/runtimes/" + r.payload.runtime + ".json is not in the packet — a runtime's chain left out hides every record on it; verify the packet as it was exported");
  if (chainsMissing.length > 3) fail((chainsMissing.length - 3) + " more runtime" + (chainsMissing.length === 4 ? "" : "s") + " the ledger registered for agents here " + (chainsMissing.length === 4 ? "is" : "are") + " not in the packet");
  // the approved policies each folder carries, and whose each signed policy is — what the approvals and the records are held to below
  const keptKeys = new Map();
  const ownerOfPolicy = new Map(), ownerOfAgent = new Map();
  // a deletion the reader holds stands unless a restoration carried by hash only could follow it (a window may leave the restoration out)
  const restoredLater = (move) => (Array.isArray(ledgerStubs) ? ledgerStubs : []).some((s) => s.kind === "node.restored" && s.seq > move.seq);
  for (const { d, off } of folders) {
    if (off) offAgents += 1; else agents += 1;
    const inFolder = (f) => "agents/" + d + "/" + f;
    const move = lastSheetMove.get(d);
    if (!off && move && move.kind === "node.deleted" && !restoredLater(move)) fail("ledger row seq " + move.seq + " deleted agent " + d + ", yet its folder carries controls.json as if it stood on the register — verify the packet as it was exported");
    if (off) {
      const o = readJson(inFolder("off-register.json"));
      if (!o || typeof o !== "object" || o.agent_id !== d) fail(inFolder("off-register.json") + " does not name agent " + d);
      else if (o.deleted && typeof o.deleted === "object") {
        const row = byLedgerSeq.get(o.deleted.seq);
        if (!row || row.hash !== o.deleted.hash) fail(inFolder("off-register.json") + " names its deletion at ledger row seq " + said(o.deleted.seq) + ", but the ledger's row there carries another hash or none");
        else if (row.withheld !== true && (row.kind !== "node.deleted" || row.subject_id !== d)) fail(inFolder("off-register.json") + " names ledger row seq " + row.seq + " as its deletion, but that row is a " + row.kind + " about " + said(row.subject_id));
        else if (move && move.seq > row.seq) fail(inFolder("off-register.json") + " names its deletion at seq " + row.seq + ", but ledger row seq " + move.seq + (move.kind === "node.restored" ? " brought it back" : " deleted it later") + " — verify the packet as it was exported");
      } else if (move && move.kind === "node.deleted" && !restoredLater(move)) fail(inFolder("off-register.json") + " names no deletion, but ledger row seq " + move.seq + " deleted agent " + d);
    }
    const ks = isListed(inFolder("keys.json")) ? readJson(inFolder("keys.json")) : [];
    for (const k of Array.isArray(ks) ? ks : []) checkKey("agent " + d + " policy", k, d, ks);
    keptKeys.set(d, new Set((Array.isArray(ks) ? ks : []).map((k) => String(k && k.hash))));
    // the policy each record ran under, by the hash the record carries: the approved policy's own, or its composite with its layers
    const byBundle = new Map();
    const own = (map, key) => { if (map.has(key) && map.get(key) !== d) map.set(key, null); else map.set(key, d); };
    for (const k of Array.isArray(ks) ? ks : []) {
      const dict = keyDictionary(Buffer.from(String(k.bytes_base64 || ""), "base64"));
      if (!dict) continue;
      byBundle.set(String(k.hash), dict);
      own(ownerOfPolicy, String(k.hash));
      own(ownerOfAgent, dict.agent);
      if (Array.isArray(k.layers) && k.layers.length) {
        const composite = sha256Buf(Buffer.from("MNVC"), ...[k.hash, ...k.layers].map((h) => hexBuf(h)).sort(Buffer.compare)).toString("hex");
        byBundle.set(composite, dict);
        own(ownerOfPolicy, composite);
      }
    }
    // who released each held call, by trace — the name beside each the one people.json gives that person, and (2026-10-26) the approver
    // key the release carries: SHA-256 over the 32 bytes of SHA-256("person:" ‖ the person sheet the release was read from)
    const aps = isListed(inFolder("approvals.json")) ? readJson(inFolder("approvals.json")) : [];
    const releasedBy = new Map();
    for (const a of Array.isArray(aps) ? aps : []) {
      if (!a || typeof a !== "object") continue;
      releasedBy.set(String(a.trace), a);
      if (people && a.approver_name !== null && a.approver_name !== undefined && (!people[a.approver_id] || people[a.approver_id].name !== a.approver_name)) { approvalsBad += 1; fail(inFolder("approvals.json") + ": trace " + a.trace + " names the approver " + JSON.stringify(a.approver_name) + ", people.json names " + JSON.stringify(people[a.approver_id] ? people[a.approver_id].name : null) + " for " + JSON.stringify(a.approver_id)); }
      if (typeof a.approver_sheet === "string" && a.approver_key !== approverKeyOf(a.approver_sheet)) { approvalsBad += 1; fail(inFolder("approvals.json") + ": trace " + a.trace + " names the approver key " + said(a.approver_key) + ", but a release by person sheet " + JSON.stringify(a.approver_sheet) + " carries " + approverKeyOf(a.approver_sheet)); }
    }
    const ds = isListed(inFolder("decisions.json")) ? readJson(inFolder("decisions.json")) : [];
    for (const r of Array.isArray(ds) ? ds : []) {
      const on = chains.get(r.runtime) && chains.get(r.runtime).get(r.seq);
      const where = "agent " + d + ": decision seq " + r.seq + " on runtime " + String(r.runtime).slice(0, 8);
      if (!on || on.withheld === true || on.hash !== r.hash) { misplaced += 1; fail(where + " is not the record its runtime's chain holds"); continue; }
      // the WHOLE record, field by field, against the one the chain holds — a stored hash alone would let a flipped decision word, tool,
      // resource or approver beside it pass
      const differs = [...new Set([...Object.keys(r), ...Object.keys(on)])].sort().find((k) => canon(r[k]) !== canon(on[k]));
      if (differs !== undefined) { misplaced += 1; fail(where + " says " + differs + " " + JSON.stringify(r[differs] === undefined ? null : r[differs]) + ", but its runtime's chain holds " + JSON.stringify(on[differs] === undefined ? null : on[differs])); continue; }
      // one record, one agent (2026-10-26): a record copied into a second folder, or the record of another agent's sheet, is named
      const place = on.runtime + "#" + on.seq;
      if (claimed.has(place)) { misplaced += 1; fail(where + " is claimed by agent " + claimed.get(place) + " too — a record belongs to one agent"); continue; }
      claimed.set(place, d);
      if (on.node_id !== undefined && on.node_id !== d) { misplaced += 1; fail(where + " is a record of agent " + JSON.stringify(on.node_id) + ", not of this one"); continue; }
      placed += 1;
      // a release (2026-10-26): a record that carries an approver must be named in approvals.json. The product's own runtime writes the
      // approval before it resumes the held call, so a release it recorded with no row there fails. A bank's runtime can release on an
      // approval its own enforcer verified, which this packet never saw: that is a warning, named, never a pass in silence.
      if (on.approver && on.approver !== ZERO32) {
        const a = releasedBy.get(String(on.trace));
        // (2026-10-26) a release was matched by its trace alone: a bank's runtime could record its own PERMIT for a call the officer released
        // through the door, naming an approver nobody on file had, and it was counted as the officer's. On every runtime, a release of a
        // call approvals.json names must carry the approver key on file for it
        if (a) {
          if (typeof a.approver_key !== "string" || !/^[0-9a-f]{64}$/.test(a.approver_key)) { approvalsBad += 1; fail(where + " was released, but approvals.json names no approver key for trace " + on.trace + ", so the release cannot be tied to the person on file"); }
          else if (a.approver_key !== on.approver) { approvalsBad += 1; fail(where + " carries the approver key " + String(on.approver).slice(0, 12) + "…, but approvals.json names " + JSON.stringify(a.approver_name === undefined || a.approver_name === null ? a.approver_id : a.approver_name) + " (key " + a.approver_key.slice(0, 12) + "…) for trace " + on.trace + " — the release is not the one on file"); }
          else released += 1;
        }
        else if (builtin && on.runtime === builtin) { unnamedOwn += 1; fail(where + " was released by an approver approvals.json does not name — the product's own runtime records every call it releases there"); }
        else { unnamedBank += 1; console.log("warning: " + where + " (" + (labels.get(on.runtime) || "a bank's runtime") + "): approver not named in the packet — a release the bank's runtime recorded under an approval this packet does not carry; the bank's own approval record names who"); }
      }
      const dict = byBundle.get(String(on.bundle));
      if (!dict) { unresolved += 1; continue; }
      let bad = null;
      if (on.agent !== dict.agent) bad = "names another agent than the one its policy was decided for";
      else if (on.ti !== NONE && dict.tools[on.ti] !== on.tool) bad = "says tool " + JSON.stringify(on.tool) + ", but its policy lists " + (on.ti < dict.tools.length ? JSON.stringify(dict.tools[on.ti]) : "no tool") + " at index " + on.ti;
      else if (on.si !== NONE && on.si >= dict.scopes.length) bad = "names scope class index " + on.si + ", but its policy lists " + dict.scopes.length;
      if (bad) { misnamed += 1; fail(where + " " + bad); } else resolved += 1;
    }
  }
  // (round seven) EVERY APPROVAL THE LEDGER RECORDS HAS ITS POLICY HERE: a folder, or its keys.json, left out of the packet took its
  // policies, its decisions and its failures with it, and the run still ended verified. Every policy.decided row this reader holds names
  // the policy it approved; an agent's must be in that agent's keys.json, a layer's in agents/layers.json
  const layerHashes = new Set((Array.isArray(layers) ? layers : []).map((k) => String(k && k.hash)));
  const notCarried = approvalsOnLedger.filter((r) => !(r.payload.kind === "agent" ? (keptKeys.get(String(r.subject_id)) || new Set()).has(r.payload.hash) : layerHashes.has(r.payload.hash)));
  for (const r of notCarried.slice(0, 3)) fail("ledger row seq " + r.seq + " records the approval of " + (r.payload.kind === "agent" ? "a policy for agent " + r.subject_id : "a " + String(r.payload.kind) + " layer on " + r.subject_id) + " (rev " + said(r.payload.rev) + ", " + String(r.payload.hash).slice(0, 12) + "…), but " + (r.payload.kind === "agent" ? "agents/" + r.subject_id + "/keys.json" : "agents/layers.json") + " does not carry it — an agent's folder, its keys.json or a layer left out of the packet hides what was approved; verify the packet as it was exported");
  if (notCarried.length > 3) fail((notCarried.length - 3) + " more approval" + (notCarried.length === 4 ? "" : "s") + " the ledger records " + (notCarried.length === 4 ? "has" : "have") + " no policy in the packet");
  // (round seven) EVERY RECORD THIS READER HOLDS IS CLAIMED BY ITS AGENT: a record a folder no longer claims (a release taken out of
  // decisions.json and approvals.json) still stands on its runtime's chain. The approved policy a record ran under is signed, and names
  // whose it is: that agent's folder must claim it; a record under no policy carried here must be claimed by some folder
  let held = 0, unclaimed = 0;
  for (const [rt, bySeq] of chains) {
    for (const r of bySeq.values()) {
      if (r.withheld === true) continue;
      const by = claimed.get(rt + "#" + r.seq);
      const owner = ownerOfPolicy.has(String(r.bundle)) ? ownerOfPolicy.get(String(r.bundle)) : ownerOfAgent.get(String(r.agent)) || null;
      if (owner && by !== owner) { unclaimed += 1; fail("decision seq " + r.seq + " on runtime " + rt.slice(0, 8) + " ran under an approved policy of agent " + owner + ", but " + (by ? "agent " + by + " claims it" : "agents/" + owner + "/decisions.json does not carry it") + " — a record left out of its agent's decisions hides what it decided; verify the packet as it was exported"); }
      else if (!owner && !by) { unclaimed += 1; fail("decision seq " + r.seq + " on runtime " + rt.slice(0, 8) + " is claimed by no agent in this packet — every record this reader holds belongs to an agent's folder here; verify the packet as it was exported"); }
      else held += 1;
    }
  }
  // (round seven) the counts manifest.json states are the folders and chains carried here
  if (manifestObj) {
    const says = [];
    if (manifestObj.agents !== agents) says.push(said(manifestObj.agents) + " agent" + (manifestObj.agents === 1 ? "" : "s") + " on the register, but " + agents + " folder" + (agents === 1 ? " carries" : "s carry") + " controls.json");
    if ((manifestObj.agents_off_register === undefined ? null : manifestObj.agents_off_register) !== offAgents) says.push(said(manifestObj.agents_off_register) + " off it, but " + offAgents + " folder" + (offAgents === 1 ? " carries" : "s carry") + " off-register.json");
    if (manifestObj.agent_records !== recordsListed) says.push(said(manifestObj.agent_records) + " decision records, but the chains carry " + recordsListed);
    if ((manifestObj.agent_records_withheld === undefined ? null : manifestObj.agent_records_withheld) !== withheldListed) says.push(said(manifestObj.agent_records_withheld) + " of them carried by hash only, but the chains carry " + withheldListed + " so");
    if (says.length) fail("manifest.json says the export carried " + says.join("; ") + " — a folder or a chain left out of the packet, or added to it; verify the packet as it was exported");
    else console.log("ok: manifest.json's counts are the folders and chains carried here — " + agents + " agent" + (agents === 1 ? "" : "s") + " on the register" + (offAgents ? ", " + offAgents + " off it" : "") + ", " + recordsListed + " decision record" + (recordsListed === 1 ? "" : "s") + (withheldListed ? ", " + withheldListed + " carried by hash only" : ""));
  }
  if (!keysBad) console.log("ok: " + keys + " approved polic" + (keys === 1 ? "y" : "ies") + " (the agents' and the layers they were decided over) verif" + (keys === 1 ? "ies" : "y") + " under agents/issuer.pem, and keys.json names the ledger row, the window and the person its signed bytes and the ledger give for " + decidedHeld + " of them" + (floorsHeld ? "; " + floorsHeld + " rulebook floor revision" + (floorsHeld === 1 ? " is" : "s are") + " held to " + (floorsHeld === 1 ? "its" : "their") + " own signed text, revision and retirement" : "") + (unseenDeciders ? "; for " + unseenDeciders + " the deciding row is withheld from this reader, so who decided " + (unseenDeciders === 1 ? "it" : "them") + " is not checked here" : "") + (retiredUnseen ? "; for " + retiredUnseen + " the retirement rests on an approval this reader holds by hash only, so when it was retired is not checked here" : "") + " — the document beside each is a readable copy; the signed bytes are what a runtime enforces");
  if (!notCarried.length) console.log("ok: every approval of a policy on the ledger this reader holds (" + approvalsOnLedger.length + ") has its policy in the packet");
  if (!misplaced) console.log("ok: " + (agents + offAgents) + " agent" + (agents + offAgents === 1 ? "" : "s") + ", " + placed + " decision" + (placed === 1 ? "" : "s") + " each found on its runtime's chain, each claimed by one agent — not checked here: whether each decision is what its policy decides (the product's monitor replays that) and whether a bank's runtime key is its enforcer's (the bank confirms that)");
  if (!unclaimed) console.log("ok: every decision record this reader holds (" + held + ") is claimed by an agent's folder here — the agent whose approved policy it ran under, where that policy is carried" + (offAgents ? "; " + offAgents + " of the folders " + (offAgents === 1 ? "is an agent" : "are agents") + " off the register" : ""));
  if (!misnamed) console.log("ok: " + resolved + " decision" + (resolved === 1 ? "" : "s") + " name the agent and the tool their approved policy's signed dictionary lists" + (unresolved ? "; " + unresolved + " ran under a policy not among the approved ones carried here (the product's monitor reports that as drift)" : "") + " — not checked here: which scope class a resource's path falls in");
  if (!unnamedOwn && !approvalsBad && (released || unnamedBank)) console.log("ok: " + released + " released call" + (released === 1 ? "" : "s") + " each named in approvals.json (who, in which role) and carrying the approver key of the person named there" + (unnamedBank ? "; " + unnamedBank + " on a bank's runtime name" + (unnamedBank === 1 ? "s" : "") + " an approver this packet does not (the warning" + (unnamedBank === 1 ? "" : "s") + " above)" : "") + " — not checked here: that the person sheet approvals.json names is the approver's own (the workspace links each account to one sheet)");
}

// ── 8. the MINERVA Benchmark Statements ────────────────────────────────────
// A statement is a benchmark.issued row: its payload carries the statement's
// body, the SHA-256 of the body's canonical form, an Ed25519 signature over
// four lines joined by LF (mnv-benchmark/1, the institution's id, the
// statement's id, that SHA-256) and the public key. Each is recomputed here,
// its key held to the deployment key the checkpoints were signed with, the
// head it read found in the chain before it, and a later benchmark.revoked
// row naming it reported.
{
  const rowsAll = Array.isArray(ledgerRows) ? ledgerRows : [];
  const issued = rowsAll.filter((r) => r && r.kind === "benchmark.issued");
  const hidden = issued.filter((r) => r.withheld === true).length;
  const shown = issued.filter((r) => r.withheld !== true);
  if (!issued.length) console.log("ok: no MINERVA Benchmark Statement on the ledger this packet carries");
  else {
    const bySeq = new Map(rowsAll.map((r) => [r.seq, r]));
    const revokedBy = new Map();
    for (const r of visibleRows) if (r.kind === "benchmark.revoked" && r.payload && typeof r.payload.statement_id === "string" && !revokedBy.has(r.payload.statement_id)) revokedBy.set(r.payload.statement_id, r);
    const knownKeys = new Set(deploymentKeys.map((k) => k.id));
    let good = 0;
    for (const r of shown) {
      const pl = r.payload || {};
      const st = pl.statement;
      const where = "statement at ledger row seq " + r.seq;
      if (!st || typeof st !== "object" || typeof st.id !== "string") { fail(where + ": the row carries no statement body"); continue; }
      const sha = sha256(canon(st));
      if (sha !== pl.statement_sha256) { fail(where + " (" + st.id + "): the body's SHA-256 is " + sha.slice(0, 12) + "…, the row says " + String(pl.statement_sha256).slice(0, 12) + "… — the body was edited after it was signed"); continue; }
      if (st.org && st.org.id !== r.org_id) { fail(where + " (" + st.id + "): names institution " + st.org.id + ", but the row is " + r.org_id + "'s"); continue; }
      let okSig = false;
      try { okSig = verifySignature(null, Buffer.from("mnv-benchmark/1\n" + r.org_id + "\n" + st.id + "\n" + sha, "utf8"), String(pl.public_pem), Buffer.from(String(pl.signature), "base64")); } catch { okSig = false; }
      if (!okSig) { fail(where + " (" + st.id + "): the signature does not verify under the public key the row carries"); continue; }
      let keyId = null;
      try { keyId = spkiKeyId(String(pl.public_pem)); } catch (e) { fail(where + " (" + st.id + "): the public key cannot be read: " + e.message); continue; }
      if (pl.key_id && keyId !== pl.key_id) { fail(where + " (" + st.id + "): key id " + pl.key_id + " does not match the key it carries (" + keyId + ")"); continue; }
      if (knownKeys.size && !knownKeys.has(keyId)) { fail(where + " (" + st.id + "): signed under key " + keyId + ", not the deployment key the checkpoints here were signed with"); continue; }
      const read = st.read || {};
      if (typeof read.head_seq === "number") {
        if (read.head_seq >= r.seq) { fail(where + " (" + st.id + "): says it read head seq " + read.head_seq + ", which is not before its own row"); continue; }
        const at = bySeq.get(read.head_seq);
        if (at && at.hash !== read.head_hash) { fail(where + " (" + st.id + "): says head seq " + read.head_seq + " had hash " + String(read.head_hash).slice(0, 12) + "…, the chain says " + String(at.hash).slice(0, 12) + "…"); continue; }
      }
      good += 1;
      const rv = revokedBy.get(st.id);
      console.log("statement " + st.id + ": signature verifies (key " + keyId + "), criteria " + String(st.criteria && st.criteria.version) + ", read at head seq " + read.head_seq + (rv ? "; REVOKED at seq " + rv.seq + (rv.payload.reason ? " (" + String(rv.payload.reason).slice(0, 120) + ")" : "") : "; not revoked on the ledger this packet carries"));
    }
    if (good === shown.length) console.log("ok: " + good + " MINERVA Benchmark Statement" + (good === 1 ? " verifies" : "s verify") + ": each body's hash, its signature " + (knownKeys.size ? "under the deployment key" : "under the key its row carries (no checkpoint here to compare that key with)") + " and the head it read" + (hidden ? "; " + hidden + " carried by hash only, not checked here" : "") + " — a statement is a reading of the record against MINERVA's published criteria, never a certification");
  }
}

// ── the verification line ──────────────────────────────────────────────────
// One line when nothing failed: the format, the head the ledger section
// found, the manifest's SHA-256 (what the packet.exported row carries as
// manifest_sha256), the reader's clock in UTC and the host's name — no
// username, nothing else about the reader. "not verified" otherwise.
// (round seven) what the checks above prove, said before the verdict: the files agree with each other and with the chain they carry; that
// this folder is the packet the record exported is proven by the line below, pasted back where the record keeps its exports
console.log("note: this script proves the files in this folder agree with each other and with the chain of rows they carry; that this folder is the packet the record exported is proven by pasting the verification line on the institution's Evidence desk, which matches the manifest's SHA-256 in it to the export's own row");
if (failed) {
  console.log("not verified");
  process.exit(1);
}
console.log("verified: " + VERIFY_FORMAT + " head " + (headSeq === null ? "none" : headSeq) + " " + (headHash || "none") + " manifest " + (manifestSha || "none") + " at " + new Date().toISOString() + " on " + hostname());
process.exit(0);
