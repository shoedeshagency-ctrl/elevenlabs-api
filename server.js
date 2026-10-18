require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const OTPAuth = require("otpauth");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");

const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || "";
const INTERNAL_SECRET = process.env.INTERNAL_SECRET || "";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const JWT_TTL_SEC = 60;
// Self-persistence: backend writes its own ACCOUNTS_JSON to Render env var after every mutation
const RENDER_API_KEY = process.env.RENDER_API_KEY || "";
const RENDER_SVC_ID  = process.env.RENDER_SVC_ID  || "";  // this service's own ID

// ── One-time-use nonce store ──────────────────────────────────────────────────
// Nonces expire at the same time as the JWT (60s), cleaned up every 90s
const usedNonces = new Map(); // nonce → expires_at (ms)
setInterval(() => {
  const now = Date.now();
  for (const [k, exp] of usedNonces) if (exp < now) usedNonces.delete(k);
}, 90_000).unref();

// ── Firebase / ElevenLabs constants ──────────────────────────────────────────
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || "AIzaSyDm5AQrmfZpIiQ1TAJjS6AOijGZQ6LOZL4";
const FIREBASE_LOGIN_URL = `https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=${FIREBASE_API_KEY}`;
const FIREBASE_REFRESH_URL = `https://securetoken.googleapis.com/v1/token?key=${FIREBASE_API_KEY}`;
const API_BASE = "https://api.elevenlabs.io/v1/coreapp";
const TOKEN_EXPIRY_BUFFER_MS = 5 * 60 * 1000; // refresh 5 min before expiry

const APP_HEADERS = {
  "device-fingerprint": "a3a029b73c013e0f17d86488b4078d95",
  "language": "en",
  "user-timezone": "Asia/Kolkata",
  "app-version": "0.0.109",
  "app-version-code": "242",
  "user-agent": "okhttp core android 0.0.109 242",
  "mobile-platform": "android",
};

// ── In-memory job store ───────────────────────────────────────────────────────
const jobs = new Map(); // job_id → job object
const MAX_JOBS = 500;
const JOB_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

function makeJobId() { return "job_" + crypto.randomBytes(10).toString("hex"); }

function createJob(type, meta = {}) {
  const id = makeJobId();
  const job = { id, type, status: "queued", result: null, error: null, account: null,
    created_at: Date.now(), updated_at: Date.now(), retry_after: 3, ...meta };
  jobs.set(id, job);
  // evict oldest when over limit
  if (jobs.size > MAX_JOBS) {
    const oldest = [...jobs.keys()][0];
    jobs.delete(oldest);
  }
  return job;
}

function updateJob(id, patch) {
  const job = jobs.get(id);
  if (!job) return;
  Object.assign(job, patch, { updated_at: Date.now() });
}

// Purge expired jobs every 10 min
setInterval(() => {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of jobs) {
    if (job.created_at < cutoff) jobs.delete(id);
  }
}, 10 * 60 * 1000).unref();

// ── Account management ────────────────────────────────────────────────────────
// Stored as ACCOUNTS_JSON env var — array of account objects.
// Each: { email, refresh_token, id_token, token_expires_at, credits_cached, credits_checked_at, active }
let accounts = [];

function loadAccounts() {
  try {
    const raw = process.env.ACCOUNTS_JSON;
    if (raw) accounts = JSON.parse(raw);
  } catch (e) {
    console.error("[accounts] Failed to parse ACCOUNTS_JSON:", e.message);
  }
}
loadAccounts();

// Warm up credits_cached after startup so pickAccount() has real data
async function warmUpCredits() {
  for (const acct of accounts) {
    try {
      const token = await getActiveToken(acct);
      const sub = await getSubscription(token);
      if (sub !== null) {
        acct.sub_cached = sub;
        acct.credits_cached = sub.credits_remaining ?? 0;
      }
    } catch (e) {
      console.error(`[warmup] ${acct.email}: ${e.message}`);
    }
  }
}
setTimeout(warmUpCredits, 2000);

// Persist current accounts to Render env var (self-write).
// Called after every mutation so restarts always load the latest state.
// Does NOT trigger a redeploy — Render only redeploys on env-var changes when
// "auto-deploy on env change" is enabled; we keep that OFF on the backend service.
async function persistAccounts() {
  if (!RENDER_API_KEY || !RENDER_SVC_ID) return;
  try {
    const safe = accounts.map(a => ({
      email:         a.email,
      refresh_token: a.refresh_token,
      active:        a.active !== false,
    }));
    const listRes = await fetch(`https://api.render.com/v1/services/${RENDER_SVC_ID}/env-vars`, {
      headers: { "Authorization": `Bearer ${RENDER_API_KEY}` },
    });
    const existing = await listRes.json();
    const envVars = (existing || [])
      .map(e => e.envVar || e)
      .filter(e => e.key && e.key !== "ACCOUNTS_JSON");
    envVars.push({ key: "ACCOUNTS_JSON", value: JSON.stringify(safe) });
    await fetch(`https://api.render.com/v1/services/${RENDER_SVC_ID}/env-vars`, {
      method: "PUT",
      headers: { "Authorization": `Bearer ${RENDER_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(envVars),
    });
    slog("INFO", `[persist] Saved ${safe.length} account(s) to Render env var`);
  } catch (e) {
    slog("ERROR", `[persist] Failed: ${e.message}`);
  }
}

async function refreshToken(account) {
  const res = await fetch(FIREBASE_REFRESH_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "refresh_token", refresh_token: account.refresh_token }),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Token refresh failed (${res.status}): ${err}`);
  }
  const data = await res.json();
  account.id_token = data.id_token;
  account.refresh_token = data.refresh_token; // Firebase may rotate this
  account.token_expires_at = Date.now() + (Number(data.expires_in) * 1000);
  console.log(`[auth] Refreshed token for ${account.email}`);
  return account;
}

async function getActiveToken(account) {
  if (!account.id_token || !account.token_expires_at ||
      Date.now() >= account.token_expires_at - TOKEN_EXPIRY_BUFFER_MS) {
    await refreshToken(account);
  }
  return account.id_token;
}

function getHeaders(idToken, extra = {}) {
  return {
    ...APP_HEADERS,
    "authorization": `Bearer ${idToken}`,
    "content-type": "application/json",
    ...extra,
  };
}

// Pick a random active account — prefer accounts with known credits > 0
function pickAccount(minCredits = 0) {
  const active = accounts.filter(a => a.active !== false);
  if (!active.length) return null;
  const withCredits = active.filter(a => (a.credits_cached || 0) > (minCredits || 0));
  if (withCredits.length) return withCredits[Math.floor(Math.random() * withCredits.length)];
  if (minCredits === 0) {
    const unknown = active.filter(a => (a.credits_cached || 0) === 0);
    if (unknown.length) return unknown[Math.floor(Math.random() * unknown.length)];
  }
  return null;
}

// Try fn(account) across all active accounts until one succeeds.
// Skips an account on 401/403 and tries the next one.
async function tryWithFallback(fn) {
  const active = accounts.filter(a => a.active !== false);
  if (!active.length) throw new Error("No active accounts");
  // shuffle so we don't always hammer the same account first
  const shuffled = active.slice().sort(() => Math.random() - 0.5);
  let lastErr;
  for (const acct of shuffled) {
    try {
      return await fn(acct);
    } catch (e) {
      const status = e.status;
      if (status === 401 || status === 403) {
        slog("WARN", `account ${acct.email} returned ${status}, trying next`);
        lastErr = e;
        continue;
      }
      throw e; // non-auth error — propagate immediately
    }
  }
  throw lastErr || new Error("All accounts failed");
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
async function apiPost(url, body, headers) {
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = { _raw: text }; }
  if (!res.ok) throw Object.assign(new Error(`API error ${res.status}`), { status: res.status, data });
  return data;
}

async function apiGet(url, headers) {
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw Object.assign(new Error(`API error ${res.status}`), { status: res.status });
  return res.json();
}

// Read SSE stream until completion or timeout, returns completed event data
async function readSSE(url, headers, timeoutMs = 180000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { ...headers, "accept": "text/event-stream" },
      signal: controller.signal,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw Object.assign(new Error(`SSE ${res.status}`), { status: res.status, data: body });
    }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    let eventType = null;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop();
      for (const line of lines) {
        const trimmed = line.trimEnd();
        if (trimmed.startsWith("event:")) {
          eventType = trimmed.slice(6).trim();
        } else if (trimmed.startsWith("data:")) {
          const dataStr = trimmed.slice(5).trim();
          let data;
          try { data = JSON.parse(dataStr); } catch { continue; }
          const status = data.status;
          if (status === "completed") return data;
          if (status === "failed") throw new Error(data.error_message || data.failure_reason || "Generation failed");
          eventType = null;
        }
      }
    }
    throw new Error("SSE stream ended without completion");
  } finally {
    clearTimeout(timer);
  }
}

// ── ElevenLabs API calls ──────────────────────────────────────────────────────
async function generateImage(idToken, { prompt, model_id, aspect_ratio, generations_count, ref_asset_id }) {
  const model_params = { aspect_ratio };
  if (ref_asset_id) {
    model_params.images = [{ content_asset_id: ref_asset_id }];
  }
  const body = {
    prompt,
    model_id,
    generations_count: generations_count || 1,
    model_parameters: model_params,
  };
  const resp = await apiPost(`${API_BASE}/projects/content/generate`, body, getHeaders(idToken));
  return {
    project_id: resp.project_id,
    session_id: resp.last_generation_session_id,
    gen_id: resp.last_generation_session?.generations?.[0]?.id,
  };
}

async function waitForImageCompletion(idToken, project_id) {
  const url = `${API_BASE}/projects/content/${project_id}/generation-status`;
  const headers = { ...APP_HEADERS, "authorization": `Bearer ${idToken}` };
  return readSSE(url, headers, 180000);
}

async function generateVideo(idToken, { prompt, model_id, aspect_ratio, duration_secs, generate_audio, start_asset_id, end_asset_id }) {
  const model_params = { aspect_ratio };
  if (duration_secs) model_params.duration_secs = duration_secs;
  if (generate_audio !== undefined) model_params.generate_audio = generate_audio;
  if (start_asset_id) model_params.start_frame = { content_asset_id: start_asset_id };
  if (end_asset_id) model_params.end_frame = { content_asset_id: end_asset_id };
  const body = { prompt, model_id, generations_count: 1, model_parameters: model_params };
  const resp = await apiPost(`${API_BASE}/projects/content/generate`, body, getHeaders(idToken));
  return {
    project_id: resp.project_id,
    session_id: resp.last_generation_session_id,
    gen_id: resp.last_generation_session?.generations?.[0]?.id,
  };
}

async function uploadAsset(idToken, fileBuffer, filename, mimeType) {
  const boundary = crypto.randomUUID();
  const namePart = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="name"\r\n\r\n${filename}\r\n`
  );
  const filePart = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="asset"; filename="${filename}"\r\nContent-Type: ${mimeType}\r\n\r\n`
  );
  const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body = Buffer.concat([namePart, filePart, fileBuffer, footer]);
  const hdrs = {
    ...APP_HEADERS,
    "authorization": `Bearer ${idToken}`,
    "content-type": `multipart/form-data; boundary=${boundary}`,
  };
  const res = await fetch(`${API_BASE}/assets`, {
    method: "POST", headers: hdrs, body,
    signal: AbortSignal.timeout(60000),
  });
  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    throw Object.assign(new Error(`Upload failed: ${res.status}`), { status: res.status, data: errBody });
  }
  return res.json();
}

async function getSubscription(idToken) {
  try {
    const resp = await apiGet(`${API_BASE}/user/customer`, getHeaders(idToken));
    const c = resp.credits || {};
    const remaining = c.remaining_credits ?? 0;
    const used      = c.used_credits      ?? 0;
    const limit     = c.total_credits     ?? 0;
    return {
      credits_remaining: remaining,
      credits_limit:     limit,
      credits_used:      used,
      plan:   (resp.subscription?.tier)   || c.tier   || "unknown",
      status: (resp.subscription?.status) || c.status || "unknown",
    };
  } catch { return null; }
}

async function getModels(idToken) {
  return apiGet(`${API_BASE}/projects/content/models`, getHeaders(idToken));
}

// ── Express app ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "webui")));

// Server logs ring buffer
const serverLogs = [];
function slog(level, msg) {
  const entry = { ts: new Date().toISOString(), level, msg };
  serverLogs.push(entry);
  if (serverLogs.length > 500) serverLogs.shift();
  console.log(`[${level}] ${msg}`);
}

// ── Internal secret check — rejects requests not from the frontend ────────────
function checkInternalSecret(req, res) {
  if (!INTERNAL_SECRET) return true; // not configured — open
  if (req.headers["x-internal-secret"] === INTERNAL_SECRET) return true;
  res.status(403).json({ error: "Forbidden." });
  return false;
}

// ── API key middleware (used only for /v1/auth/token) ─────────────────────────
function requireApiKey(req, res, next) {
  if (!checkInternalSecret(req, res)) return;
  if (!API_SECRET) return next();
  const key = req.headers["x-api-key"] || req.query.api_key;
  if (key === API_SECRET) return next();
  res.status(401).json({ error: "Invalid or missing API key." });
}

// ── JWT middleware (replay-proof — one-time-use nonce + 60s expiry) ───────────
function requireJWT(req, res, next) {
  if (!checkInternalSecret(req, res)) return;
  if (!API_SECRET) return next(); // no auth configured — open
  const auth = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing Bearer token. Call GET /v1/auth/token first." });
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: "Token invalid or expired. Get a fresh one from GET /v1/auth/token." });
  }
  // One-time-use check
  const nonce = payload.nonce;
  if (usedNonces.has(nonce)) {
    return res.status(401).json({ error: "Token already used. Each token is single-use — request a new one." });
  }
  usedNonces.set(nonce, (payload.exp * 1000) + 5000); // keep 5s past JWT expiry for clock skew
  req.jwtPayload = payload;
  next();
}

// ── TOTP admin auth ───────────────────────────────────────────────────────────
let TOTP_INSTANCE = null;
let TOTP_SECRET_B32 = process.env.TOTP_SECRET || "";

function setupTOTP() {
  if (TOTP_SECRET_B32) {
    try {
      TOTP_INSTANCE = new OTPAuth.TOTP({
        issuer: "ElevenLabsAPI", label: "ElevenLabsAPI Admin",
        secret: OTPAuth.Secret.fromBase32(TOTP_SECRET_B32), digits: 6, period: 30,
      });
      slog("INFO", "[TOTP] Admin 2FA ready.");
    } catch (e) { slog("ERROR", "[TOTP] Invalid TOTP_SECRET: " + e.message); }
  } else {
    const secret = new OTPAuth.Secret({ size: 20 });
    TOTP_SECRET_B32 = secret.base32;
    TOTP_INSTANCE = new OTPAuth.TOTP({
      issuer: "ElevenLabsAPI", label: "ElevenLabsAPI Admin",
      secret, digits: 6, period: 30,
    });
    slog("WARN", `[TOTP] Auto-generated. Set TOTP_SECRET=${TOTP_SECRET_B32} in Render env to persist.`);
    slog("INFO", `[TOTP] URI: ${TOTP_INSTANCE.toString()}`);
    QRCode.toString(TOTP_INSTANCE.toString(), { type: "terminal", small: true }, (err, qr) => {
      if (!err) console.log(qr);
    });
  }
}
setupTOTP();

const adminSessions = new Map();
const ADMIN_TTL = 24 * 3600 * 1000;

function createAdminSession() {
  const token = crypto.randomBytes(32).toString("hex");
  adminSessions.set(token, Date.now() + ADMIN_TTL);
  return token;
}
function isAdminSession(token) {
  if (!token) return false;
  const exp = adminSessions.get(token);
  if (!exp || Date.now() > exp) { adminSessions.delete(token); return false; }
  return true;
}
function verifyTOTP(code) {
  if (!TOTP_INSTANCE) return false;
  return TOTP_INSTANCE.validate({ token: String(code).replace(/\s/g, ""), window: 1 }) !== null;
}
function adminAuth(req, res, next) {
  // Machine-to-machine: frontend's backendAdmin() sends X-API-Key + X-Internal-Secret
  if (API_SECRET && req.headers["x-api-key"] === API_SECRET &&
      INTERNAL_SECRET && req.headers["x-internal-secret"] === INTERNAL_SECRET) return next();
  if (isAdminSession(req.cookies?.admin_session)) return next();
  if (req.method !== "GET") return res.status(401).json({ ok: false, error: "Session expired — log in at /admin/login" });
  res.redirect("/admin/login?next=" + encodeURIComponent(req.path));
}

// ── Public routes ─────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  const active = accounts.filter(a => a.active !== false).length;
  res.json({
    status: "ok",
    accounts: { total: accounts.length, active },
    uptime_seconds: Math.floor(process.uptime()),
  });
});

// ── Auth token endpoints ──────────────────────────────────────────────────────
// External callers: GET /v1/auth/token — requires X-API-Key, returns 60s single-use JWT
app.get("/v1/auth/token", requireApiKey, (req, res) => {
  const nonce = crypto.randomBytes(16).toString("hex");
  const token = jwt.sign({ nonce }, JWT_SECRET, { expiresIn: JWT_TTL_SEC });
  res.json({ token, expires_in: JWT_TTL_SEC, note: "Single-use. One token = one request." });
});

// Web UI: GET /v1/webui/token — no API key required (JWT itself is single-use + 60s, replay-proof)
// The web UI is served from the same origin; external callers with a webui token can only make ONE request.
app.get("/v1/webui/token", (req, res) => {
  if (!API_SECRET) { return res.json({ token: null }); } // no auth configured
  const nonce = crypto.randomBytes(16).toString("hex");
  const token = jwt.sign({ nonce, src: "webui" }, JWT_SECRET, { expiresIn: JWT_TTL_SEC });
  res.json({ token, expires_in: JWT_TTL_SEC });
});

app.get("/v1/models", async (req, res) => {
  const type = req.query.type || "image";
  const acct = pickAccount();
  if (!acct) return res.status(503).json({ error: "No active accounts" });
  try {
    const token = await getActiveToken(acct);
    const data = await getModels(token);
    // Filter by type if requested
    const models = Array.isArray(data) ? data : (data.models || data.data || []);
    const filtered = type === "all" ? models : models.filter(m => (m.type || "image") === type);
    res.json({ data: filtered, total: filtered.length });
  } catch (e) {
    slog("ERROR", `GET /v1/models: ${e.message}`);
    res.status(500).json({ error: e.message });
  }
});

app.get("/logs", (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  res.json(serverLogs.slice(-limit));
});

// ── Generation endpoints ──────────────────────────────────────────────────────
app.post("/v1/images/generate", requireJWT, async (req, res) => {
  const { prompt, model, model_id, aspect_ratio = "1:1", generations_count = 1, ref_url, ref_asset_id: bodyRefAssetId } = req.body;
  if (!prompt) return res.status(400).json({ error: "prompt is required" });

  const actualModel = model_id || model || "gemini-2.5-flash-image";
  if (!accounts.filter(a => a.active !== false).length) return res.status(503).json({ error: "No active accounts" });

  const job = createJob("image", { prompt, model: actualModel });
  res.status(202).json({ job_id: job.id, status: "queued", retry_after: 3, poll_url: `/v1/jobs/${job.id}` });

  setImmediate(async () => {
    try {
      updateJob(job.id, { status: "processing" });
      const { images, project_id, usedAcct } = await tryWithFallback(async (acct) => {
        const token = await getActiveToken(acct);

        let ref_asset_id = bodyRefAssetId || null;
        if (!ref_asset_id && ref_url) {
          const imgRes = await fetch(ref_url, { signal: AbortSignal.timeout(30000) });
          if (!imgRes.ok) throw new Error(`Failed to fetch reference image: ${imgRes.status}`);
          const buf = Buffer.from(await imgRes.arrayBuffer());
          const mime = imgRes.headers.get("content-type") || "image/jpeg";
          const asset = await uploadAsset(token, buf, `ref.${mime.split("/")[1] || "jpg"}`, mime);
          ref_asset_id = asset.id;
        }

        slog("INFO", `[image] job=${job.id} calling generate model=${actualModel} account=${acct.email}`);
        const { project_id } = await generateImage(token, {
          prompt, model_id: actualModel, aspect_ratio, generations_count, ref_asset_id,
        });
        slog("INFO", `[image] job=${job.id} project=${project_id} model=${actualModel} account=${acct.email}`);
        const result = await waitForImageCompletion(token, project_id);

        const images = [];
        if (result.content_url) images.push({ url: result.content_url, preview_url: result.content_capped_resolution_url || result.preview_content_url });
        if (result.sessions) {
          for (const s of result.sessions)
            for (const g of (s.generations || []))
              if (g.content_url) images.push({ url: g.content_url, preview_url: g.content_capped_resolution_url });
        }
        return { images, project_id, usedAcct: acct.email };
      });

      updateJob(job.id, { status: "completed", account: usedAcct, result: { images, project_id }, retry_after: undefined });
      slog("INFO", `[image] job=${job.id} done — ${images.length} image(s)`);
    } catch (e) {
      const detail = e.data ? ` | body: ${JSON.stringify(e.data).slice(0, 300)}` : "";
      slog("ERROR", `[image] job=${job.id} failed: ${e.message}${detail}`);
      updateJob(job.id, { status: "failed", error: e.message });
    }
  });
});

app.post("/v1/videos/generate", requireJWT, async (req, res) => {
  const { prompt, model, model_id, aspect_ratio = "16:9", duration_secs, generate_audio = true, start_image_url, end_image_url, start_asset_id: bodyStartAssetId, end_asset_id: bodyEndAssetId } = req.body;
  if (!prompt) return res.status(400).json({ error: "prompt is required" });

  const actualModel = model_id || model || "flux-3-video";
  if (!accounts.filter(a => a.active !== false).length) return res.status(503).json({ error: "No active accounts" });

  const job = createJob("video", { prompt, model: actualModel });
  res.status(202).json({ job_id: job.id, status: "queued", retry_after: 10, poll_url: `/v1/jobs/${job.id}` });

  setImmediate(async () => {
    try {
      updateJob(job.id, { status: "processing" });
      const { project_id: vProjectId, video_url, usedAcct } = await tryWithFallback(async (acct) => {
        const token = await getActiveToken(acct);

        async function fetchAndUpload(url) {
          if (!url) return null;
          const r = await fetch(url, { signal: AbortSignal.timeout(30000) });
          if (!r.ok) throw new Error(`Failed to fetch asset: ${r.status}`);
          const buf = Buffer.from(await r.arrayBuffer());
          const mime = r.headers.get("content-type") || "image/jpeg";
          const asset = await uploadAsset(token, buf, `asset.${mime.split("/")[1] || "jpg"}`, mime);
          return asset.id;
        }

        const start_asset_id = bodyStartAssetId || await fetchAndUpload(start_image_url);
        const end_asset_id = bodyEndAssetId || await fetchAndUpload(end_image_url);

        const { project_id } = await generateVideo(token, {
          prompt, model_id: actualModel, aspect_ratio, duration_secs, generate_audio,
          start_asset_id, end_asset_id,
        });

        const result = await waitForImageCompletion(token, project_id);
        const video_url = result.content_url || result.video_url;
        return { project_id, video_url, usedAcct: acct.email };
      });

      updateJob(job.id, { status: "completed", account: usedAcct, result: { url: video_url, project_id: vProjectId }, retry_after: undefined });
      slog("INFO", `[video] job=${job.id} done account=${usedAcct}`);
    } catch (e) {
      const detail = e.data ? ` | body: ${JSON.stringify(e.data).slice(0, 300)}` : "";
      slog("ERROR", `[video] job=${job.id} failed: ${e.message}${detail}`);
      updateJob(job.id, { status: "failed", error: e.message });
    }
  });
});

// ── Job polling ───────────────────────────────────────────────────────────────
app.get("/v1/jobs/:id", requireJWT, (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or expired" });
  res.json(job);
});

app.get("/v1/jobs", requireJWT, (req, res) => {
  const list = [...jobs.values()].sort((a, b) => b.created_at - a.created_at).slice(0, 100);
  res.json({ jobs: list, total: list.length });
});

// ── Account info ──────────────────────────────────────────────────────────────
app.get("/v1/accounts", requireJWT, async (req, res) => {
  const result = await Promise.all(accounts.map(async (acct) => {
    try {
      const token = await getActiveToken(acct);
      const sub = await getSubscription(token);
      if (sub !== null) { acct.sub_cached = sub; acct.credits_cached = sub.credits_remaining ?? 0; }
      const s = sub ?? acct.sub_cached;
      return {
        email:             acct.email,
        active:            acct.active !== false,
        credits:           s?.credits_remaining ?? null,
        credits_limit:     s?.credits_limit ?? null,
        credits_used:      s?.credits_used ?? null,
        plan:              s?.plan ?? null,
        status:            s?.status ?? null,
        token_expires_at:  acct.token_expires_at,
      };
    } catch (e) {
      return { email: acct.email, active: false, error: e.message };
    }
  }));
  res.json(result);
});

// ── Asset upload ──────────────────────────────────────────────────────────────
app.post("/v1/upload", requireJWT, async (req, res) => {
  const { image_url, image_data, mime_type } = req.body;
  const acct = pickAccount();
  if (!acct) return res.status(503).json({ error: "No active accounts" });
  try {
    const token = await getActiveToken(acct);
    let buf, mime, filename;
    if (image_data) {
      const match = image_data.match(/^data:([^;]+);base64,(.+)$/);
      if (!match) return res.status(400).json({ error: "Invalid base64 data URL" });
      mime = match[1];
      buf = Buffer.from(match[2], "base64");
      filename = `upload.${mime.split("/")[1] || "bin"}`;
    } else if (image_url) {
      const r = await fetch(image_url, { signal: AbortSignal.timeout(30000) });
      if (!r.ok) throw new Error(`Failed to fetch: ${r.status}`);
      buf = Buffer.from(await r.arrayBuffer());
      mime = mime_type || r.headers.get("content-type") || "image/jpeg";
      filename = `upload.${mime.split("/")[1] || "jpg"}`;
    } else {
      return res.status(400).json({ error: "Provide image_url or image_data" });
    }
    const asset = await uploadAsset(token, buf, filename, mime);
    res.json({ asset_id: asset.id, asset, account: acct.email });
  } catch (e) {
    const detail = e.data ? ` | ${String(e.data).slice(0, 300)}` : "";
    slog("ERROR", `POST /v1/upload: ${e.message}${detail}`);
    res.status(e.status || 500).json({ error: e.message, detail: e.data || null });
  }
});

// ── Admin login ───────────────────────────────────────────────────────────────
app.get("/admin/login", (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Admin Login</title>
<style>body{font-family:sans-serif;background:#0a0a0c;color:#f0f0f4;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{background:#121216;border:1px solid #26262f;border-radius:14px;padding:32px 36px;width:320px}
h2{margin:0 0 24px;font-size:18px}
input{width:100%;box-sizing:border-box;background:#17171d;border:1px solid #26262f;color:#f0f0f4;border-radius:10px;padding:11px 13px;font-size:14px;margin-bottom:14px}
button{width:100%;padding:13px;border:none;border-radius:10px;background:linear-gradient(135deg,#7c6cff,#9183ff);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.err{color:#ff6b6b;font-size:13px;margin-bottom:12px}</style></head>
<body><div class="box">
<h2>Admin Login</h2>
<form method="POST" action="/admin/login">
<input type="hidden" name="next" value="${req.query.next || "/admin"}">
<input name="totp" placeholder="6-digit TOTP code" autofocus autocomplete="off" maxlength="6">
${req.query.err ? '<div class="err">Invalid code — try again</div>' : ''}
<button type="submit">Login</button>
</form></div></body></html>`);
});

app.post("/admin/login", express.urlencoded({ extended: false }), (req, res) => {
  const { totp, next } = req.body;
  if (!verifyTOTP(totp)) return res.redirect("/admin/login?err=1");
  const token = createAdminSession();
  res.cookie("admin_session", token, { httpOnly: true, maxAge: ADMIN_TTL, sameSite: "lax" });
  res.redirect(next || "/admin");
});

app.post("/admin/logout", (req, res) => {
  res.clearCookie("admin_session");
  res.redirect("/admin/login");
});

// ── Admin panel ───────────────────────────────────────────────────────────────
app.get("/admin", adminAuth, (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Admin — ElevenLabs API</title>
<style>
body{font-family:system-ui,sans-serif;background:#0a0a0c;color:#f0f0f4;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 24px}h2{font-size:15px;color:#9a9aa8;margin:24px 0 12px;text-transform:uppercase;letter-spacing:.8px}
.card{background:#121216;border:1px solid #26262f;border-radius:12px;padding:20px;margin-bottom:16px}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px 12px;font-size:13px;border-bottom:1px solid #1d1d24}
th{color:#9a9aa8;font-weight:500}td{color:#f0f0f4}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600}
.ok{background:#3dd68c22;color:#3dd68c}.err{background:#ff6b6b22;color:#ff6b6b}
input,textarea{width:100%;box-sizing:border-box;background:#17171d;border:1px solid #26262f;color:#f0f0f4;border-radius:8px;padding:10px;font-size:13px;font-family:monospace;margin-bottom:10px}
button{padding:10px 20px;border:none;border-radius:8px;background:#7c6cff;color:#fff;font-size:13px;font-weight:600;cursor:pointer;margin-right:8px}
button.danger{background:#ff6b6b22;color:#ff6b6b;border:1px solid #ff6b6b44}
a{color:#7c6cff;text-decoration:none}.logout{float:right;font-size:13px}
#status-msg{font-size:13px;margin-top:10px;color:#3dd68c}
</style></head><body>
<h1>ElevenLabs API Admin <a href="/admin/logout" class="logout">Logout</a></h1>

<div class="card">
<h2>Accounts</h2>
<div id="accounts-list"><em>Loading…</em></div>
<h2 style="margin-top:24px">Add Account</h2>
<input id="add-email" placeholder="Email">
<input id="add-pass" type="password" placeholder="Password (used once to get refresh_token, never stored)">
<button onclick="addAccount()">Add Account</button>
<div id="add-status"></div>
</div>

<div class="card">
<h2>Export ACCOUNTS_JSON</h2>
<p style="font-size:13px;color:#9a9aa8">Copy this into the Render env var ACCOUNTS_JSON to persist accounts across restarts.</p>
<textarea id="accounts-json" rows="6" readonly></textarea>
<button onclick="copyJson()">Copy</button>
<div id="copy-status"></div>
</div>

<div class="card">
<h2>Logs</h2>
<div id="logs" style="font-family:monospace;font-size:12px;color:#9a9aa8;max-height:300px;overflow-y:auto"></div>
</div>

<script>
async function api(path, opts={}) {
  const r = await fetch(path, { ...opts, headers: { 'Content-Type': 'application/json', ...opts.headers } });
  return r.json();
}

async function loadAccounts() {
  const list = await api('/v1/accounts');
  const el = document.getElementById('accounts-list');
  if (!list.length) { el.innerHTML = '<em style="color:#9a9aa8">No accounts yet</em>'; return; }
  el.innerHTML = '<table><thead><tr><th>Email</th><th>Status</th><th>Credits</th><th>Token expires</th><th></th></tr></thead><tbody>' +
    list.map(a => \`<tr>
      <td>\${a.email}</td>
      <td><span class="badge \${a.active ? 'ok':'err'}">\${a.active ? 'active':'inactive'}</span></td>
      <td>\${a.credits ?? '—'}</td>
      <td>\${a.token_expires_at ? new Date(a.token_expires_at).toLocaleTimeString() : '—'}</td>
      <td><button class="danger" onclick="removeAccount('\${a.email}')">Remove</button></td>
    </tr>\`).join('') + '</tbody></table>';
}

async function addAccount() {
  const email = document.getElementById('add-email').value.trim();
  const pass = document.getElementById('add-pass').value;
  const st = document.getElementById('add-status');
  if (!email || !pass) { st.textContent = 'Fill in both fields.'; st.style.color='#ff6b6b'; return; }
  st.textContent = 'Adding…'; st.style.color = '#9a9aa8';
  const r = await api('/admin/accounts/add', { method:'POST', body: JSON.stringify({ email, password: pass }) });
  if (r.ok) { st.textContent = '✓ Added: ' + email; st.style.color='#3dd68c'; document.getElementById('add-email').value=''; document.getElementById('add-pass').value=''; loadAccounts(); exportJson(); }
  else { st.textContent = 'Error: ' + r.error; st.style.color='#ff6b6b'; }
}

async function removeAccount(email) {
  if (!confirm('Remove ' + email + '?')) return;
  const r = await api('/admin/accounts/remove', { method:'POST', body: JSON.stringify({ email }) });
  if (r.ok) { loadAccounts(); exportJson(); }
  else alert('Error: ' + r.error);
}

async function exportJson() {
  const r = await api('/admin/accounts/export');
  document.getElementById('accounts-json').value = JSON.stringify(r.accounts, null, 2);
}

function copyJson() {
  const v = document.getElementById('accounts-json').value;
  navigator.clipboard.writeText(v).then(() => {
    document.getElementById('copy-status').textContent = '✓ Copied!';
  });
}

async function loadLogs() {
  const logs = await api('/logs?limit=50');
  const el = document.getElementById('logs');
  el.innerHTML = logs.map(l => \`<div><span style="color:#63636f">\${l.ts.slice(11,19)}</span> <span style="color:\${l.level==='ERROR'?'#ff6b6b':l.level==='WARN'?'#ffb23e':'#9a9aa8'}">\${l.level}</span> \${l.msg}</div>\`).join('');
  el.scrollTop = el.scrollHeight;
}

loadAccounts(); exportJson(); loadLogs();
setInterval(() => { loadAccounts(); loadLogs(); }, 15000);
</script>
</body></html>`);
});

// ── Admin API routes ──────────────────────────────────────────────────────────
app.post("/admin/accounts/add", adminAuth, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ ok: false, error: "email and password required" });
  if (accounts.find(a => a.email === email)) return res.json({ ok: false, error: "Account already exists" });
  try {
    // Login to get refresh_token
    const r = await fetch(FIREBASE_LOGIN_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true, clientType: "CLIENT_TYPE_ANDROID" }),
      signal: AbortSignal.timeout(15000),
    });
    const data = await r.json();
    if (!data.refreshToken) throw new Error(data.error?.message || "Login failed");
    const acct = {
      email,
      refresh_token: data.refreshToken,
      id_token: data.idToken,
      token_expires_at: Date.now() + (Number(data.expiresIn || 3600) * 1000),
      credits_cached: 0,
      active: true,
    };
    accounts.push(acct);
    slog("INFO", `[admin] Added account: ${email}`);
    persistAccounts();
    res.json({ ok: true, email });
  } catch (e) {
    slog("ERROR", `[admin] Add account ${email}: ${e.message}`);
    res.json({ ok: false, error: e.message });
  }
});

app.post("/admin/accounts/remove", adminAuth, (req, res) => {
  const { email } = req.body;
  const idx = accounts.findIndex(a => a.email === email);
  if (idx === -1) return res.json({ ok: false, error: "Not found" });
  accounts.splice(idx, 1);
  slog("INFO", `[admin] Removed account: ${email}`);
  persistAccounts();
  res.json({ ok: true });
});

app.post("/admin/accounts/toggle", adminAuth, (req, res) => {
  const { email, active } = req.body;
  const acct = accounts.find(a => a.email === email);
  if (!acct) return res.json({ ok: false, error: "Not found" });
  acct.active = !!active;
  slog("INFO", `[admin] ${active ? "Enabled" : "Disabled"} account: ${email}`);
  persistAccounts();
  res.json({ ok: true, email, active: acct.active });
});

app.get("/admin/accounts/export", adminAuth, (req, res) => {
  // Return accounts without exposing full tokens in export (keep refresh_token for persistence)
  const safe = accounts.map(a => ({
    email: a.email,
    refresh_token: a.refresh_token,
    active: a.active !== false,
  }));
  res.json({ accounts: safe });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  slog("INFO", `ElevenLabs API server running on port ${PORT}`);
  slog("INFO", `Accounts loaded: ${accounts.length}`);
  if (!API_SECRET) slog("WARN", "API_SECRET not set — all requests pass without auth");
});
