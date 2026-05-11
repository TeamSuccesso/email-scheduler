require('dotenv').config();

const express    = require('express');
const cron       = require('node-cron');
const cors       = require('cors');
const fs         = require('fs');
const path       = require('path');
const { google } = require('googleapis');
const mongoose   = require('mongoose');
const Email      = require('./models/Email');
const AuthState  = require('./models/AuthState');
// CHANGED: AES-256-GCM encryption at rest (MongoDB)
const {
  getEncryptionKey,
  encrypt, decrypt,
  encryptObject, decryptObject,
  FIELDS_TO_ENCRYPT, AUTH_FIELDS_TO_ENCRYPT,
} = require('./utils/crypto');
// END CHANGED

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: function (origin, callback) {
    // Allow Chrome extensions, and no-origin requests (Render health checks, cron pings)
    if (!origin || /^chrome-extension:\/\//.test(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS: origin not allowed'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-instance-id', 'authorization', 'x-cron-secret'],
}));
app.use(express.json({ limit: '50mb' }));

const chromeHeartbeat = new Map();

// CHANGED: Validate ENCRYPTION_KEY on startup.
// WARNING: If this key is lost, all encrypted data in MongoDB is unrecoverable.
getEncryptionKey();
// END CHANGED

// ── Connect MongoDB ───────────────────────────────────────────────────────────

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

// ── Token storage ─────────────────────────────────────────────────────────────

const TOKENS_FILE    = path.join(__dirname, 'tokens.json');
const AUTH_META_FILE = path.join(__dirname, 'auth.json');

let _tokensCache   = null;
let _authMetaCache = null;

function setTokensCache(next) {
  const normalized = (next && typeof next === 'object') ? next : {};
  if (!_tokensCache) { _tokensCache = normalized; return _tokensCache; }
  if (_tokensCache === normalized) return _tokensCache;
  for (const k of Object.keys(_tokensCache)) { if (!(k in normalized)) delete _tokensCache[k]; }
  for (const [k, v] of Object.entries(normalized)) { _tokensCache[k] = v; }
  return _tokensCache;
}

// ── FIX: loadTokens ALWAYS reads from MongoDB on Vercel (serverless).
// On serverless platforms, _tokensCache is null on every cold start.
// Passing forceReload:true ensures we always get the real persisted data.
async function loadTokens(opts = {}) {
  const forceReload = opts?.forceReload === true;
  if (_tokensCache && !forceReload) return _tokensCache;
  try {
    if (mongoose.connection.readyState === 1) {
      const doc = await AuthState.findOne({ key: 'tokens' }).lean();
      // CHANGED: Decrypt AuthState.value (tokens) when stored as AES-256-GCM string
      if (doc?.value) {
        if (typeof doc.value === 'string') {
          const decrypted = decrypt(doc.value);
          const parsed = decrypted ? JSON.parse(decrypted) : {};
          if (parsed && typeof parsed === 'object') return setTokensCache(parsed);
        } else if (typeof doc.value === 'object') {
          return setTokensCache(doc.value); // backward compatibility (legacy plaintext object)
        }
      }
      // END CHANGED
    }
  } catch (err) {
    // CHANGED: Surface crypto errors (e.g., wrong ENCRYPTION_KEY) instead of silently falling back.
    const msg = String(err?.message || err || '');
    if (msg.includes('ENCRYPTION_KEY') || msg.startsWith('Decryption failed') || msg.includes('Encrypted value')) {
      throw err;
    }
    // END CHANGED
  }
  if (!fs.existsSync(TOKENS_FILE)) return setTokensCache({});
  try { return setTokensCache(JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'))); }
  catch (_) { return setTokensCache({}); }
}

async function saveTokens(tokens) {
  setTokensCache(tokens);
  try {
    if (mongoose.connection.readyState === 1) {
      // CHANGED: Encrypt AuthState.value (tokens) before saving to MongoDB
      const encryptedValue = encrypt(JSON.stringify(_tokensCache || {}));
      await AuthState.findOneAndUpdate({ key: 'tokens' }, { value: encryptedValue }, { upsert: true });
      // END CHANGED
    }
  } catch (_) {}
  try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(_tokensCache, null, 2)); } catch (_) {}
}

function setAuthMetaCache(next) {
  const normalized = (next && typeof next === 'object') ? next : {};
  if (!_authMetaCache) { _authMetaCache = normalized; return _authMetaCache; }
  if (_authMetaCache === normalized) return _authMetaCache;
  for (const k of Object.keys(_authMetaCache)) { if (!(k in normalized)) delete _authMetaCache[k]; }
  for (const [k, v] of Object.entries(normalized)) { _authMetaCache[k] = v; }
  return _authMetaCache;
}

async function loadAuthMeta(opts = {}) {
  const forceReload = opts?.forceReload === true;
  if (_authMetaCache && !forceReload) return _authMetaCache;
  try {
    if (mongoose.connection.readyState === 1) {
      const doc = await AuthState.findOne({ key: 'meta' }).lean();
      // CHANGED: Decrypt AuthState.value (meta) when stored as AES-256-GCM string
      if (doc?.value) {
        if (typeof doc.value === 'string') {
          const decrypted = decrypt(doc.value);
          const parsed = decrypted ? JSON.parse(decrypted) : {};
          if (parsed && typeof parsed === 'object') return setAuthMetaCache(parsed);
        } else if (typeof doc.value === 'object') {
          return setAuthMetaCache(doc.value); // backward compatibility (legacy plaintext object)
        }
      }
      // END CHANGED
    }
  } catch (err) {
    // CHANGED: Surface crypto errors (e.g., wrong ENCRYPTION_KEY) instead of silently falling back.
    const msg = String(err?.message || err || '');
    if (msg.includes('ENCRYPTION_KEY') || msg.startsWith('Decryption failed') || msg.includes('Encrypted value')) {
      throw err;
    }
    // END CHANGED
  }
  if (!fs.existsSync(AUTH_META_FILE)) return setAuthMetaCache({});
  try { return setAuthMetaCache(JSON.parse(fs.readFileSync(AUTH_META_FILE, 'utf8'))); }
  catch (_) { return setAuthMetaCache({}); }
}

async function saveAuthMeta(meta) {
  setAuthMetaCache(meta);
  try {
    if (mongoose.connection.readyState === 1) {
      // CHANGED: Encrypt AuthState.value (meta) before saving to MongoDB
      const encryptedValue = encrypt(JSON.stringify(_authMetaCache || {}));
      await AuthState.findOneAndUpdate({ key: 'meta' }, { value: encryptedValue }, { upsert: true });
      // END CHANGED
    }
  } catch (_) {}
  try { fs.writeFileSync(AUTH_META_FILE, JSON.stringify(_authMetaCache, null, 2)); } catch (_) {}
}

function getInstanceId(req) {
  const id = (req.headers['x-instance-id'] || '').toString().trim();
  return id || null;
}

async function getTokensForInstance(instanceId) {
  if (!instanceId) return null;
  // ── FIX: always forceReload so Vercel cold-start doesn't return null ──────
  const allTokens = await loadTokens({ forceReload: true });
  const entry = allTokens[instanceId];
  if (entry && entry.tokens && entry.userEmail) return entry;
  return null;
}

async function getUserEmailForInstance(instanceId) {
  if (instanceId) {
    const entry = await getTokensForInstance(instanceId);
    if (entry?.userEmail) return entry.userEmail;
  }
  return getPrimaryUserEmail();
}

function listTokenEmails(tokens) {
  return Object.keys(tokens || {}).filter(k => k.includes('@'));
}

async function getPrimaryUserEmail() {
  // ── FIX: always forceReload so Vercel cold-start doesn't return null ──────
  const allTokens = await loadTokens({ forceReload: true });
  const emails = listTokenEmails(allTokens);
  if (!emails.length) return null;
  const meta = await loadAuthMeta({ forceReload: true });
  if (meta.lastConnectedEmail && allTokens[meta.lastConnectedEmail]) return meta.lastConnectedEmail;
  return emails[0];
}

// ── OAuth2 client ─────────────────────────────────────────────────────────────

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function isAccessTokenExpired(tokens, skewMs = 30_000) {
  const expiry = Number(tokens?.expiry_date);
  if (!Number.isFinite(expiry) || expiry <= 0) return false;
  return expiry <= (Date.now() + skewMs);
}

function extractGoogleApiError(err) {
  const status = err?.code || err?.response?.status || null;
  const data   = err?.response?.data;
  const apiMsg = data?.error?.message || err?.message || 'Unknown Gmail API error';
  const reason = data?.error?.errors?.[0]?.reason || data?.error?.status || null;
  return { status, apiMsg, reason, data };
}

class GmailSendError extends Error {
  constructor(message, opts = {}) {
    super(message);
    this.name         = 'GmailSendError';
    this.httpStatus   = opts.httpStatus   || 500;
    this.googleStatus = opts.googleStatus || null;
    this.googleReason = opts.googleReason || null;
    this.diagnostics  = opts.diagnostics  || null;
  }
}

async function deactivateEmail(email, reason) {
  try {
    if (!email?.id) return;
    await Email.findOneAndUpdate({ id: email.id }, { active: false, inFlightUntil: null }, { returnDocument: 'after' });
    console.warn(`🔒 Deactivated email ${email.id}${reason ? ` (${reason})` : ''}`);
  } catch (_) {}
}

function makeOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/oauth/callback'
  );
}

// ── Health check ──────────────────────────────────────────────────────────────

app.get('/', async (req, res) => {
  try {
    const total  = await Email.countDocuments();
    const active = await Email.countDocuments({ active: true });
    res.json({ status: 'running', time: new Date().toISOString(), scheduled: total, active });
  } catch (_) {
    res.json({ status: 'running', time: new Date().toISOString() });
  }
});

app.get('/oauth/url', (req, res) => {
  const instanceId = (req.query.instanceId || '').toString().trim();
  if (!instanceId) {
    return res.status(400).send('Missing instanceId. Please re-open the extension and try connecting again.');
  }

  const oauth2 = makeOAuthClient();
  const url = oauth2.generateAuthUrl({
    access_type: 'offline',
    prompt:      'consent',
    state:       instanceId,
    scope: [
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/userinfo.email',
    ],
  });
  res.redirect(url);
});

app.get('/oauth/callback', async (req, res) => {
  const { code, state: instanceId } = req.query;
  if (!code) return res.status(400).send('Missing code');

  if (!instanceId) {
    return res.status(400).send('Missing instanceId in OAuth state. Please try connecting again from the extension.');
  }

  try {
    const oauth2 = makeOAuthClient();
    const { tokens } = await oauth2.getToken(code);
    oauth2.setCredentials(tokens);

    const oauth2Api = google.oauth2({ version: 'v2', auth: oauth2 });
    const { data }  = await oauth2Api.userinfo.get();
    const email     = data.email;

    // ── FIX: forceReload so we don't overwrite other instances' tokens ────────
    const allTokens = await loadTokens({ forceReload: true });

    const existingEntry = allTokens[instanceId] || {};
    const existingTokens = existingEntry.tokens || {};
    if (existingTokens.refresh_token && !tokens.refresh_token) {
      tokens.refresh_token = existingTokens.refresh_token;
    }

    allTokens[instanceId] = { userEmail: email, tokens };
    // BUG 4 FIX: Also store under email key so lookup by userEmail works during auth/status scans
    allTokens[email]      = { userEmail: email, tokens };

    await saveTokens(allTokens);

    // ── FIX: forceReload meta too ─────────────────────────────────────────────
    const meta = await loadAuthMeta({ forceReload: true });
    meta[instanceId] = { lastConnectedEmail: email, connectedAt: new Date().toISOString() };
    await saveAuthMeta(meta);

    console.log(`✅ Tokens saved for ${email} (instance: ${instanceId})`);
    res.send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:40px;">
        <h2>✅ Connected!</h2>
        <p>Signed in as <strong>${email}</strong></p>
        <p>You can close this tab. Your recurring emails will now send even when Chrome is closed.</p>
      </body></html>
    `);
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.status(500).send('Auth failed: ' + err.message);
  }
});

app.post('/oauth/token', async (req, res) => {
  const { email, tokens } = req.body;
  if (!email || !tokens) return res.status(400).json({ error: 'Missing email or tokens' });

  const instanceId = getInstanceId(req);

  // ── FIX: forceReload so we don't lose other instances on cold start ────────
  const allTokens = await loadTokens({ forceReload: true });

  if (instanceId) {
    const existingEntry  = allTokens[instanceId] || {};
    const existingTokens = existingEntry.tokens  || {};
    const merged = {
      ...existingTokens,
      ...tokens,
      refresh_token: tokens.refresh_token || existingTokens.refresh_token || null,
    };
    if (!merged.refresh_token) {
      console.warn(`⚠️  No refresh_token for ${email} (instance: ${instanceId}) — server sending may fail after token expiry`);
    }
    allTokens[instanceId] = { userEmail: email, tokens: merged };
    await saveTokens(allTokens);

    const meta = await loadAuthMeta({ forceReload: true });
    meta[instanceId] = { lastConnectedEmail: email, connectedAt: new Date().toISOString() };
    await saveAuthMeta(meta);

    console.log(`💾 Token updated for ${email} (instance: ${instanceId}, has refresh: ${!!merged.refresh_token})`);
  } else {
    const existing = allTokens[email] || {};
    const merged = {
      ...existing,
      ...tokens,
      refresh_token: tokens.refresh_token || existing.refresh_token || null,
    };
    allTokens[email] = merged;
    await saveTokens(allTokens);
    await saveAuthMeta({ lastConnectedEmail: email, connectedAt: new Date().toISOString() });
    console.log(`💾 Token updated for ${email} (legacy flat, has refresh: ${!!merged.refresh_token})`);
  }

  res.json({ ok: true });
});

// BUG 4 FIX: waitForDB — ensure MongoDB is ready before reading tokens on cold start
async function waitForDB(ms = 3000) {
  if (mongoose.connection.readyState === 1) return true;
  return new Promise(resolve => {
    const t = Date.now();
    const i = setInterval(() => {
      if (mongoose.connection.readyState === 1) { clearInterval(i); resolve(true); }
      if (Date.now() - t > ms)                  { clearInterval(i); resolve(false); }
    }, 200);
  });
}

// FIX: Always read from MongoDB here so the real persisted auth is returned.
// WHY: On Vercel (serverless), every request may start a fresh Node process.
// _tokensCache is always null on cold start, so without forceReload the server
// always returns { connected: false } — making the extension show "Not connected"
// every time Chrome restarts, even though the user already authenticated.
// FIX: Always read from MongoDB here so the real persisted auth is returned.
app.get('/auth/status', async (req, res) => {
  try {
    // BUG 4 FIX: Wait for DB before reading — avoids cold-start false negatives
    await waitForDB(3000);

    const instanceId = getInstanceId(req);

    if (instanceId) {
      // forceReload: true — never trust the empty in-memory cache on serverless
      const allTokens = await loadTokens({ forceReload: true });
      const entry = allTokens[instanceId];
      if (entry?.userEmail && entry?.tokens) {
        return res.json({ connected: true, email: entry.userEmail });
      }
      // BUG 4 FIX: Scan all entries for matching userEmail (handles case where
      // token was stored under email key only, not instanceId)
      for (const val of Object.values(allTokens)) {
        if (val && typeof val === 'object' && val.userEmail && val.tokens) {
          // check if this entry could be ours via meta
          const meta = await loadAuthMeta({ forceReload: true });
          const instMeta = meta[instanceId];
          if (instMeta?.lastConnectedEmail && instMeta.lastConnectedEmail === val.userEmail) {
            return res.json({ connected: true, email: val.userEmail });
          }
        }
      }
      return res.json({ connected: false, email: null });
    }

    const email = await getPrimaryUserEmail();
    // BUG 4 FIX: Always return 200 (never 500)
    res.json({ connected: !!email, email: email || null });
  } catch (err) {
    // BUG 4 FIX: Always return 200 so popup doesn't flip to "unknown" on transient errors
    res.status(200).json({ connected: false, email: null, error: err.message });
  }
});

app.post('/auth/disconnect', async (req, res) => {
  try {
    // ── FIX: forceReload so we don't accidentally clear only a partial set ───
    const allTokens = await loadTokens({ forceReload: true });
    const email = (req.body?.email || '').toString().trim();
    const mode  = (req.body?.mode  || '').toString().trim();

    if (mode === 'all') {
      for (const k of Object.keys(allTokens)) delete allTokens[k];
      await saveTokens(allTokens);
      await saveAuthMeta({});
      return res.json({ ok: true });
    }

    if (mode === 'instance') {
      const instanceId = getInstanceId(req);
      if (instanceId && allTokens[instanceId]) {
        delete allTokens[instanceId];
        await saveTokens(allTokens);
        const meta = await loadAuthMeta({ forceReload: true });
        delete meta[instanceId];
        await saveAuthMeta(meta);
      }
      return res.json({ ok: true });
    }

    if (email && allTokens[email]) {
      delete allTokens[email];
      await saveTokens(allTokens);
    }

    const remaining = listTokenEmails(await loadTokens());
    if (!remaining.length) await saveAuthMeta({});
    else {
      const meta = await loadAuthMeta({ forceReload: true });
      if (meta.lastConnectedEmail === email) {
        await saveAuthMeta({ lastConnectedEmail: remaining[0], connectedAt: new Date().toISOString() });
      }
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── Schedule / update an email ────────────────────────────────────────────────

app.post('/schedule', async (req, res) => {
  try {
    const incoming   = req.body;
    const instanceId = getInstanceId(req);

    if (!incoming || !incoming.id) return res.status(400).json({ error: 'Invalid email data' });

    if (!incoming.userEmail) {
      const resolvedEmail = await getUserEmailForInstance(instanceId);
      if (resolvedEmail) incoming.userEmail = resolvedEmail;
      else return res.status(400).json({ error: 'No authenticated user — cannot schedule email' });
    }

    incoming.userEmail      = String(incoming.userEmail || '').trim();
    incoming.userEmailLower = incoming.userEmail ? incoming.userEmail.toLowerCase() : '';

    if (incoming.fromChrome && incoming.userEmail) {
      // FIX: Always store heartbeat key in lowercase to match runSchedulerTick lookup
      chromeHeartbeat.set(incoming.userEmail.toLowerCase(), Date.now());
    }

    incoming.to  = sanitizeRecipient(incoming.to);
    incoming.cc  = sanitizeRecipient(incoming.cc);
    incoming.bcc = sanitizeRecipient(incoming.bcc);

    const existing = await Email.findOne({ id: incoming.id });

    if (existing && incoming.fromChrome) {
      const serverLastSentMs = existing.lastSent     ? new Date(existing.lastSent).getTime()     : 0;
      const chromeLastSentMs = incoming.lastSent     ? new Date(incoming.lastSent).getTime()     : 0;
      const serverNextSendMs = existing.nextSendTime ? new Date(existing.nextSendTime).getTime() : 0;
      const chromeNextSendMs = incoming.nextSendTime ? new Date(incoming.nextSendTime).getTime() : 0;
      const nowMs            = Date.now();

      if (serverLastSentMs >= chromeLastSentMs) {
        delete incoming.nextSendTime;
        delete incoming.lastSent;
        delete incoming.sentCount;
      } else if (incoming.nextSendTime && chromeNextSendMs < nowMs && serverNextSendMs > nowMs) {
        delete incoming.nextSendTime;
      }
    }

    if (existing) {
      const wantsClear = incoming.clearAttachments === true;
      const updateDoc  = { ...existing.toObject(), ...incoming };

      updateDoc.sentCount = incoming.sentCount ?? existing.sentCount ?? 0;
      updateDoc.lastSent  = incoming.lastSent  ?? existing.lastSent  ?? null;

      if (wantsClear) {
        updateDoc.attachments   = [];
        updateDoc.attachmentIds = [];
      } else {
        const hasNewAttachments = Array.isArray(incoming.attachments) && incoming.attachments.length > 0;
        if (!hasNewAttachments) {
          delete updateDoc.attachments;
          delete updateDoc.attachmentIds;
        }
      }

      delete updateDoc._id;

      // CHANGED: Encrypt sensitive fields before saving to MongoDB
      const encryptedUpdateDoc = encryptEmailDoc(updateDoc);
      await Email.findOneAndUpdate({ id: incoming.id }, encryptedUpdateDoc, { returnDocument: 'after' });
      // END CHANGED
      console.log(`📝 Updated: "${incoming.subject}" | attachments: ${(updateDoc.attachments || existing.attachments || []).length}`);
    } else {
      // CHANGED: Encrypt sensitive fields before saving to MongoDB
      // NOTE: Use findOneAndUpdate+upsert to avoid the Email pre('save') hook overwriting userEmailLower.
      await Email.findOneAndUpdate({ id: incoming.id }, encryptEmailDoc(incoming), { upsert: true });
      // END CHANGED
      console.log(`📅 New: "${incoming.subject}" → ${incoming.nextSendTime} | attachments: ${(incoming.attachments || []).length}`);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Schedule error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/send-now', async (req, res) => {
  // CHANGED: Only release the MongoDB send lock if THIS request acquired it.
  // Otherwise a 409 response would clear another instance's lock and allow duplicate sends.
  let emailIdForUnlock = null;
  try {
    const incoming   = req.body?.email || req.body;
    const instanceId = getInstanceId(req);

    if (!incoming || !incoming.id) return res.status(400).json({ ok: false, error: 'Invalid email data' });
    // NOTE: Do not set emailIdForUnlock yet — we have not acquired the send lock.

    if (!incoming.userEmail) {
      const resolvedEmail = await getUserEmailForInstance(instanceId);
      if (resolvedEmail) incoming.userEmail = resolvedEmail;
      else return res.status(400).json({ ok: false, error: 'No authenticated user' });
    }

    incoming.to  = sanitizeRecipient(incoming.to);
    incoming.cc  = sanitizeRecipient(incoming.cc);
    incoming.bcc = sanitizeRecipient(incoming.bcc);

    // Read existing record from DB (needed to get attachments and current state)
    const existing = await Email.findOne({ id: incoming.id });
    const existingPlain = existing ? decryptEmailDoc(existing.toObject()) : null;
    const merged   = existingPlain ? { ...existingPlain, ...incoming } : incoming;

    if ((!Array.isArray(merged.attachments) || merged.attachments.length === 0) && Array.isArray(existingPlain?.attachments) && existingPlain.attachments.length) {
      merged.attachments = existingPlain.attachments;
    }

    // FIX: Acquire the send lock BEFORE writing updated data to DB.
    // Previously the upsert happened before tryAcquireSendLock — meaning two
    // simultaneous callers (Chrome alarm + server cron) could both write, then
    // both race for the lock. Now we lock first, then write+send atomically.
    const locked = await tryAcquireSendLock(merged.id);
    if (!locked) {
      const current = await Email.findOne({ id: merged.id });
      const currentPlain = decryptEmailDoc(current?.toObject ? current.toObject() : current);
      const currentPayload = stripEmailPayload(currentPlain);
      return res.status(409).json({
        ok: false, inProgress: true, retryAfterMs: 30_000,
        email: currentPayload,
        error: 'Email is already sending. Please try again in a moment.',
      });
    }
    emailIdForUnlock = merged.id;

    // Write merged data to DB now that we hold the lock
    const mergedToStore = { ...merged };
    delete mergedToStore.inFlightUntil;
    await Email.findOneAndUpdate({ id: merged.id }, encryptEmailDoc(mergedToStore), { upsert: true });

    // Decrypt and send
    const lockedPlain = decryptEmailDoc(merged);
    try {
      await sendEmailViaGmail(lockedPlain, instanceId);
    } catch (sendErr) {
      const msg = String(sendErr?.message || sendErr || '');
      if (msg.startsWith('DUPLICATE_PREVENTED:')) {
        // Treat as a success/no-op: another process already handled this window.
        // Return the latest DB state so Chrome can reschedule correctly.
        const current = await Email.findOne({ id: merged.id });
        const currentPlain = decryptEmailDoc(current?.toObject ? current.toObject() : current);
        const payload = stripEmailPayload(currentPlain);
        return res.json({ ok: true, skipped: true, reason: 'duplicate_prevented', email: payload, message: msg });
      }
      throw sendErr;
    }

    const now          = new Date();
    const newSentCount = (merged.sentCount || 0) + 1;
    const isOnce       = merged.recurrence?.once === true || merged.type === 'once';
    // BUGFIX: use Number.isFinite so NaN (from encrypted/invalid maxTimes) never
    // triggers a false reachedMax and incorrectly marks the email as done.
    const maxTimesNum  = parseInt(merged.maxTimes);
    const reachedMax   = merged.maxTimes !== 'indefinitely'
      && Number.isFinite(maxTimesNum)
      && newSentCount >= maxTimesNum;
    const isDone       = isOnce || reachedMax;
    const nextSendTime = isDone ? null : computeNextSendTime(merged);

    const updated = await Email.findOneAndUpdate(
      { id: merged.id },
      { sentCount: newSentCount, lastSent: now.toISOString(), active: isDone ? false : merged.active, nextSendTime, inFlightUntil: null },
      { returnDocument: 'after' }
    );

    // CHANGED: Always return plaintext to the extension (decrypt response)
    const updatedPlain = decryptEmailDoc(updated?.toObject ? updated.toObject() : updated);
    res.json({ ok: true, email: stripEmailPayload(updatedPlain) });
    // END CHANGED
  } catch (err) {
    const status = (err && typeof err === 'object' && Number.isFinite(err.httpStatus)) ? err.httpStatus : 500;
    res.status(status).json({ ok: false, error: err?.message || String(err || 'Unknown error') });
  } finally {
    try { await releaseSendLock(emailIdForUnlock); } catch (_) {}
  }
});

// ── Diagnostic test-send ──────────────────────────────────────────────────────

app.post('/test-send', async (req, res) => {
  const requestedEmail = (req.body?.userEmail || '').toString().trim() || null;
  const instanceId     = getInstanceId(req);
  const diagnostics    = { requestedEmail, resolvedUserEmail: null, token: null, tokenInfo: null, profile: null, send: null, gmailError: null };

  try {
    console.log('[test-send] start', { requestedEmail, instanceId });

    // ── FIX: forceReload so cold-start serverless doesn't return empty tokens ─
    const allTokens = await loadTokens({ forceReload: true });

    let userEmail, tokens;
    if (instanceId && allTokens[instanceId]) {
      userEmail = allTokens[instanceId].userEmail;
      tokens    = allTokens[instanceId].tokens;
    } else {
      userEmail = requestedEmail || await getPrimaryUserEmail() || Object.keys(allTokens).find(k => k.includes('@'));
      tokens    = userEmail ? allTokens[userEmail] : null;
    }

    diagnostics.resolvedUserEmail = userEmail || null;
    if (!userEmail) return res.status(400).json({ ok: false, error: 'No authenticated user found', diagnostics });
    if (!tokens)    return res.status(404).json({ ok: false, error: `No tokens for ${userEmail}`, diagnostics });

    diagnostics.token = {
      hasAccessToken:  !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiry_date:     tokens.expiry_date || null,
      isExpired:       isAccessTokenExpired(tokens),
    };

    const oauth2 = makeOAuthClient();
    oauth2.setCredentials(tokens);

    if (tokens.access_token) {
      try {
        const info = await oauth2.getTokenInfo(tokens.access_token);
        diagnostics.tokenInfo = { expires_in: info?.expires_in ?? null, scope: info?.scope ?? null };
        diagnostics.tokenInfo.hasGmailSendScope = String(info?.scope || '').includes('gmail.send');
      } catch (e) {
        diagnostics.tokenInfo = { error: String(e?.message || e) };
      }
    }

    const gmail = google.gmail({ version: 'v1', auth: oauth2 });

    try {
      const prof = await gmail.users.getProfile({ userId: 'me' });
      diagnostics.profile = { emailAddress: prof?.data?.emailAddress || null };
      diagnostics.profile.mismatch = !!(diagnostics.profile.emailAddress && diagnostics.profile.emailAddress.toLowerCase() !== String(userEmail).toLowerCase());
    } catch (e) {
      diagnostics.profile = { error: String(e?.message || e) };
    }

    const subject    = `Test send ${new Date().toISOString()}`;
    const subjectB64 = Buffer.from(subject, 'utf8').toString('base64');
    const body       = `Test email sent at ${new Date().toISOString()} from Recurring Gmail server.`;
    const bodyB64    = chunkBase64Lines(Buffer.from(body, 'utf8').toString('base64'));
    const mime = [
      `From: ${userEmail}`, `To: ${userEmail}`,
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      `Date: ${new Date().toUTCString()}`,
      'MIME-Version: 1.0', 'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64', '', bodyB64,
    ].join('\r\n');

    const raw = Buffer.from(mime, 'utf8').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

    const delays = [2000, 4000, 8000];
    let lastErr = null, responseData = null;
    for (let attempt = 0; attempt < (delays.length + 1); attempt++) {
      try {
        const resp = await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
        responseData = resp?.data || null; lastErr = null; break;
      } catch (e) {
        lastErr = e;
        const { status, apiMsg } = extractGoogleApiError(e);
        const retryable = Number.isFinite(status) && status >= 500 && status < 600;
        if (retryable && attempt < delays.length) { await sleep(delays[attempt]); continue; }
        break;
      }
    }

    if (lastErr) {
      const { status, apiMsg, reason, data } = extractGoogleApiError(lastErr);
      diagnostics.gmailError = { status: status || null, reason: reason || null, message: apiMsg, raw: data?.error || data || null };
      return res.status(Number.isFinite(status) ? status : 500).json({ ok: false, error: `Gmail send failed${status ? ` (${status})` : ''}: ${apiMsg}`, diagnostics });
    }

    diagnostics.send = { ok: true, response: responseData };
    return res.json({ ok: true, diagnostics });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err?.message || String(err || 'Unknown error'), diagnostics });
  }
});

// ── Get emails for a user ─────────────────────────────────────────────────────

app.get('/emails', async (req, res) => {
  try {
    const instanceId    = getInstanceId(req);
    const userEmailRaw  = (req.query?.userEmail || '').toString();
    let   userEmail     = userEmailRaw.trim();

    if (!userEmail && instanceId) {
      // ── FIX: forceReload for same cold-start reason ───────────────────────
      const allTokens = await loadTokens({ forceReload: true });
      const entry = allTokens[instanceId];
      if (entry?.userEmail) userEmail = entry.userEmail;
    }

    const userEmailLower = userEmail ? userEmail.toLowerCase() : '';

    // Try 1: query by userEmailLower (stored plaintext for querying)
    let emails = [];
    if (userEmail) {
      emails = await Email.find({ userEmailLower }).select('-attachments').sort({ createdAt: -1 }).limit(200);
    }

    // Try 2: query by encrypted userEmail value
    if (userEmail && !emails.length) {
      try {
        const encryptedEmail = encrypt(userEmail);
        emails = await Email.find({ userEmail: encryptedEmail }).select('-attachments').sort({ createdAt: -1 }).limit(200);
      } catch (_) {}
    }

    // Try 3: get ALL emails and filter by decrypting (fallback for migration)
    if (userEmail && !emails.length) {
      try {
        const allEmails = await Email.find({}).select('-attachments').sort({ createdAt: -1 }).limit(500);
        emails = allEmails.filter(e => {
          try {
            const decrypted = decrypt(e.userEmail || '');
            return decrypted && decrypted.toLowerCase() === userEmailLower;
          } catch (_) {
            return false;
          }
        });
        // Fix userEmailLower for any found emails that are missing it
        if (emails.length) {
          for (const e of emails) {
            if (!e.userEmailLower) {
              await Email.findOneAndUpdate(
                { id: e.id },
                { userEmailLower }
              );
            }
          }
        }
      } catch (_) {}
    }

    // Try 4: no filter — return all if no userEmail provided
    if (!userEmail) {
      emails = await Email.find({}).select('-attachments').sort({ createdAt: -1 }).limit(200);
    }

    if (userEmail && !emails.length) {
      const primary = await getPrimaryUserEmail().catch(() => null);
      if (primary && primary.toLowerCase() === userEmailLower) {
        const unassignedFilter = {
          $or: [
            { userEmail: '' }, { userEmail: null },
            { userEmailLower: '' }, { userEmailLower: null },
            { userEmailLower: { $exists: false } },
          ],
        };
        const unassignedCount = await Email.countDocuments(unassignedFilter);
        if (unassignedCount > 0) {
          // CHANGED: Store encrypted userEmail while keeping userEmailLower plaintext for queries
          await Email.updateMany(unassignedFilter, { userEmail: encrypt(primary), userEmailLower });
          // END CHANGED
          emails = await Email.find({ $or: [{ userEmailLower }, { userEmail: primary }] }).select('-attachments');
        }
      }
    }

    // CHANGED: Decrypt sensitive fields before returning to the extension (attachments already stripped by select)
    const plainEmails = (emails || []).map(e => decryptEmailDoc(e?.toObject ? e.toObject() : e));
    res.json(plainEmails);
    // END CHANGED
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Delete an email ───────────────────────────────────────────────────────────

app.delete('/schedule/:id', async (req, res) => {
  try {
    await Email.deleteOne({ id: req.params.id });
    console.log(`🗑️  Deleted: ${req.params.id}`);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Pause / resume an email ───────────────────────────────────────────────────

app.patch('/schedule/:id', async (req, res) => {
  try {
    // CHANGED: Encrypt any sensitive fields included in the PATCH update
    const updateDoc = { ...(req.body || {}) };

    if (updateDoc && updateDoc.userEmail) {
      const u = String(updateDoc.userEmail || '').trim();
      updateDoc.userEmail      = u;
      updateDoc.userEmailLower = u ? u.toLowerCase() : '';
    }

    for (const field of FIELDS_TO_ENCRYPT) {
      if (!(field in updateDoc)) continue;
      const val = updateDoc[field];
      if (val === null || val === undefined) continue;

      if (field === 'attachments') {
        if (val === '') updateDoc.attachments = '';
        else if (typeof val === 'string') updateDoc.attachments = encrypt(val);
        else updateDoc.attachments = encrypt(JSON.stringify(val));
      } else {
        updateDoc[field] = encrypt(String(val));
      }
    }

    const updated = await Email.findOneAndUpdate({ id: req.params.id }, updateDoc, { new: true });
    // END CHANGED
    if (!updated) return res.status(404).json({ error: 'Not found' });
    // CHANGED: Return plaintext to extension
    const updatedPlain = decryptEmailDoc(updated?.toObject ? updated.toObject() : updated);
    res.json({ ok: true, email: stripEmailPayload(updatedPlain) });
    // END CHANGED
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function sanitizeRecipient(val) {
  if (!val) return '';
  if (Array.isArray(val)) return val.map(v => (typeof v === 'string' ? v : v?.email || v?.address || '')).filter(Boolean).join(',');
  const str = String(val).trim();
  return str === '[object Object]' ? '' : str;
}

function stripEmailPayload(emailDoc) {
  if (!emailDoc) return emailDoc;
  const obj = typeof emailDoc.toObject === 'function' ? emailDoc.toObject() : { ...emailDoc };
  delete obj.attachments;
  return obj;
}

// CHANGED: Encrypt/decrypt Email docs for MongoDB at-rest protection (AES-256-GCM)
function encryptEmailDoc(doc) {
  const base = (doc && typeof doc === 'object') ? { ...doc } : {};
  const withoutAttachments = FIELDS_TO_ENCRYPT.filter(f => f !== 'attachments');
  const out = encryptObject(base, withoutAttachments);

  if ('attachments' in base) {
    const at = base.attachments;
    if (at === null || at === undefined || at === '') out.attachments = '';
    else if (typeof at === 'string') out.attachments = encrypt(at);
    else out.attachments = encrypt(JSON.stringify(at));
  }

  return out;
}

function decryptEmailDoc(doc) {
  const base = (doc && typeof doc === 'object') ? { ...doc } : {};
  const withoutAttachments = FIELDS_TO_ENCRYPT.filter(f => f !== 'attachments');
  const out = decryptObject(base, withoutAttachments);

  if ('attachments' in base) {
    const at = base.attachments;
    if (at === null || at === undefined || at === '') {
      out.attachments = [];
    } else if (Array.isArray(at)) {
      out.attachments = at;
    } else if (typeof at === 'string') {
      const decrypted = decrypt(at);
      if (!decrypted) out.attachments = [];
      else {
        try { out.attachments = JSON.parse(decrypted); }
        catch (_) { throw new Error(`Failed to parse decrypted attachments JSON for email id=${String(base.id || '')}`); }
      }
    } else {
      out.attachments = at;
    }
  }

  return out;
}
// END CHANGED

async function tryAcquireSendLock(emailId, lockMs = 2 * 60_000) {
  const nowIso   = new Date().toISOString();
  const untilIso = new Date(Date.now() + lockMs).toISOString();
  // BUG 1C FIX: Must include $exists:false so newly-inserted docs (no inFlightUntil field) are also matchable.
  // Without this, a doc created before the inFlightUntil field existed would never acquire the lock.
  return Email.findOneAndUpdate(
    {
      id: emailId,
      $or: [
        { inFlightUntil: null },
        { inFlightUntil: { $exists: false } },
        { inFlightUntil: { $lt: nowIso } },
      ],
    },
    { $set: { inFlightUntil: untilIso } },
    { returnDocument: 'after' }
  );
}

async function releaseSendLock(emailId) {
  if (!emailId) return;
  await Email.findOneAndUpdate({ id: emailId }, { inFlightUntil: null });
}

function isEmailDone(email) {
  const isOnce = email.recurrence?.once === true || email.type === 'once';
  // BUGFIX: maxTimes may be an AES-encrypted string when called on a raw DB doc
  // (before decryptEmailDoc). parseInt of an encrypted blob = NaN, and x >= NaN
  // is always false — so reachedMax would never trigger on encrypted docs.
  // Safe guard: treat any non-numeric, non-'indefinitely' value as 'indefinitely'.
  const maxTimesRaw = email.maxTimes;
  const maxTimesNum = parseInt(maxTimesRaw);
  const reachedMax  = maxTimesRaw !== 'indefinitely'
    && Number.isFinite(maxTimesNum)   // ← only true for real numeric strings
    && (email.sentCount || 0) >= maxTimesNum;
  return !email.active || (isOnce && (email.sentCount || 0) >= 1) || reachedMax;
}

// ── Timezone offset for IST (UTC+5:30) ────────────────────────────────────────
// Server runs on Render in UTC. All user-facing times are in IST (India Standard Time).
// We must compute nextSendTime in IST, then store as UTC ISO string.
const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000; // 5 hours 30 minutes in ms

function nowIST() {
  // Returns a Date object whose UTC fields reflect the current IST time.
  // e.g. if UTC is 09:37, this returns a Date where getUTCHours() === 15 (3 PM IST)
  return new Date(Date.now() + IST_OFFSET_MS);
}

function makeDateIST(year, month, day, h, m) {
  // Create a UTC-based Date representing the given clock time in IST.
  // e.g. IST 15:07 on 2026-04-28 → UTC 09:37 on 2026-04-28
  const utcMs = Date.UTC(year, month, day, h, m, 0, 0) - IST_OFFSET_MS;
  return new Date(utcMs);
}

function computeNextSendTime(email) {
  const r = email.recurrence || {};

  const nowUtc = new Date();
  const nowIst = nowIST(); // UTC fields of this object reflect IST clock time

  // Parse time safely — default to 08:00
  const timeParts = (email.time || '08:00').split(':');
  const h = parseInt(timeParts[0], 10) || 0;
  const m = parseInt(timeParts[1], 10) || 0;

  if (r.once) return null;

  // ── Hourly: exactly N hours from now (UTC, no timezone needed) ───────────
  if (r.hours) {
    return new Date(nowUtc.getTime() + r.hours * 3_600_000).toISOString();
  }

  // ── Daily: next occurrence at exact IST time ──────────────────────────────
  if (r.days) {
    const candidate = makeDateIST(
      nowIst.getUTCFullYear(), nowIst.getUTCMonth(), nowIst.getUTCDate(), h, m
    );
    if (candidate.getTime() <= nowUtc.getTime()) {
      return new Date(candidate.getTime() + 24 * 60 * 60 * 1000 * r.days).toISOString();
    }
    return candidate.toISOString();
  }

  // ── Weekly: next occurrence of target weekday at exact IST time ───────────
  if (r.weeks) {
    const targetDay = typeof r.dayOfWeek === 'number' ? r.dayOfWeek : 1;
    const istDayOfWeek = nowIst.getUTCDay(); // day of week in IST

    const candidate = makeDateIST(
      nowIst.getUTCFullYear(), nowIst.getUTCMonth(), nowIst.getUTCDate(), h, m
    );

    let daysUntil = (targetDay - istDayOfWeek + 7) % 7;
    // Always schedule for NEXT occurrence (not today even if same weekday)
    if (daysUntil === 0) daysUntil = 7;

    return new Date(candidate.getTime() + daysUntil * 24 * 60 * 60 * 1000).toISOString();
  }

  // ── Monthly: same day-of-month next month at exact IST time ──────────────
  if (r.months) {
    const targetDOM = Number.isFinite(r.dayOfMonth) ? r.dayOfMonth : nowIst.getUTCDate();
    const nextMonthIst = new Date(Date.UTC(
      nowIst.getUTCFullYear(),
      nowIst.getUTCMonth() + r.months,
      1
    ));
    const daysInNextMonth = new Date(Date.UTC(
      nextMonthIst.getUTCFullYear(),
      nextMonthIst.getUTCMonth() + 1,
      0
    )).getUTCDate();
    const clampedDay = Math.min(Math.max(1, targetDOM), daysInNextMonth);
    return makeDateIST(
      nextMonthIst.getUTCFullYear(), nextMonthIst.getUTCMonth(), clampedDay, h, m
    ).toISOString();
  }

  // ── Fallback: daily ───────────────────────────────────────────────────────
  const candidate = makeDateIST(
    nowIst.getUTCFullYear(), nowIst.getUTCMonth(), nowIst.getUTCDate(), h, m
  );
  if (candidate.getTime() <= nowUtc.getTime()) {
    return new Date(candidate.getTime() + 24 * 60 * 60 * 1000).toISOString();
  }
  return candidate.toISOString();
}

function chunkBase64Lines(b64, lineLen = 76) {
  const s = String(b64 || '').replace(/\r?\n/g, '');
  if (!s) return '';
  let out = '';
  for (let i = 0; i < s.length; i += lineLen) out += s.slice(i, i + lineLen) + '\r\n';
  return out.replace(/\r\n$/, '');
}

async function sendEmailViaGmail(email, instanceId = null) {
  const toStr = sanitizeRecipient(email.to);
  if (!toStr || toStr === '[object Object]') throw new Error('Recipient address required');

  // ── FIX: forceReload so we get real tokens on serverless cold start ────────
  const allTokens = await loadTokens({ forceReload: true });

  let userEmail, tokens;

  if (instanceId && allTokens[instanceId]) {
    userEmail = allTokens[instanceId].userEmail;
    tokens    = allTokens[instanceId].tokens;
  } else {
    userEmail = email.userEmail || await getPrimaryUserEmail() || Object.keys(allTokens).find(k => k.includes('@'));
    tokens    = userEmail ? allTokens[userEmail] : null;
  }

  if (!userEmail) throw new Error('No authenticated user found');
  if (!tokens)    throw new Error(`No tokens for ${userEmail}`);

  const isExpired = isAccessTokenExpired(tokens);
  if (isExpired && !tokens.refresh_token) {
    const msg = 'Token expired and no refresh_token available. Please reconnect via /oauth/url';
    await deactivateEmail(email, 'token_expired_no_refresh');
    throw new GmailSendError(msg, { httpStatus: 401, diagnostics: { userEmail, expiry_date: tokens.expiry_date || null } });
  }

  if (!tokens.refresh_token) {
    console.warn(`⚠️  No refresh_token for ${userEmail} — will fail if access_token is expired`);
  }

  const oauth2 = makeOAuthClient();
  oauth2.setCredentials(tokens);

  oauth2.on('tokens', (newTokens) => {
    if (newTokens.refresh_token) tokens.refresh_token = newTokens.refresh_token;
    if (newTokens.access_token)  tokens.access_token  = newTokens.access_token;
    if (newTokens.expiry_date)   tokens.expiry_date   = newTokens.expiry_date;
    if (instanceId && allTokens[instanceId]) {
      allTokens[instanceId].tokens = tokens;
    } else {
      allTokens[userEmail] = tokens;
    }
    void saveTokens(allTokens);
    console.log(`🔄 Token refreshed for ${userEmail}`);
  });

  const gmail = google.gmail({ version: 'v1', auth: oauth2 });

  const boundary   = `boundary_${Date.now()}`;
  const toHeader   = toStr;
  const ccHeader   = sanitizeRecipient(email.cc);
  const bccHeader  = sanitizeRecipient(email.bcc);
  const fromHeader = sanitizeRecipient(email.from) || userEmail;

  const subjectB64 = Buffer.from(email.subject || '(no subject)', 'utf8').toString('base64');
  const bodyType   = email.bodyType === 'html' ? 'html' : 'text';
  const bodyContentType = bodyType === 'html' ? 'text/html' : 'text/plain';
  let bodyContent  = String(email.body || '');

  if (!bodyContent || bodyContent.trim() === '') {
    deactivateEmail(email, 'empty_body_detected');
    throw new Error('Email body is empty. Please delete this schedule and create a new one.');
  }

  const bodyB64   = chunkBase64Lines(Buffer.from(bodyContent, 'utf8').toString('base64'));
  const attachments = Array.isArray(email.attachments) ? email.attachments.filter(a => a && (a.dataBase64 || a.data)) : [];

  let mime;

  if (attachments.length === 0) {
    mime = [
      `From: ${fromHeader}`, `To: ${toHeader}`,
      // CHANGED: Only include Cc/Bcc when genuinely non-empty after sanitization
      (ccHeader && ccHeader.trim())  ? `Cc: ${ccHeader}`   : null,
      (bccHeader && bccHeader.trim()) ? `Bcc: ${bccHeader}` : null,
      // END CHANGED
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      `Date: ${new Date().toUTCString()}`,
      'MIME-Version: 1.0',
      `Content-Type: ${bodyContentType}; charset=UTF-8`,
      'Content-Transfer-Encoding: base64', '', bodyB64,
    ].filter(v => v !== null && v !== undefined).join('\r\n');
  } else {
    const parts = [`--${boundary}`, `Content-Type: ${bodyContentType}; charset=UTF-8`, 'Content-Transfer-Encoding: base64', '', bodyB64, ''];

    for (const att of attachments) {
      const attName = (att.name || 'attachment').replace(/[\r\n"]/g, '');
      const attType = att.type || 'application/octet-stream';
      let b64 = (att.dataBase64 || att.data || '').replace(/\r?\n/g, '');
      if (b64.includes('base64,')) b64 = b64.split('base64,').pop() || '';
      if (!b64) continue;
      parts.push('', `--${boundary}`, `Content-Type: ${attType}; name="${attName}"`, `Content-Disposition: attachment; filename="${attName}"`, 'Content-Transfer-Encoding: base64', '', chunkBase64Lines(b64), '');
    }
    parts.push(`--${boundary}--`);

    mime = [
      `From: ${fromHeader}`, `To: ${toHeader}`,
      // CHANGED: Only include Cc/Bcc when genuinely non-empty after sanitization
      (ccHeader && ccHeader.trim())  ? `Cc: ${ccHeader}`   : null,
      (bccHeader && bccHeader.trim()) ? `Bcc: ${bccHeader}` : null,
      // END CHANGED
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      `Date: ${new Date().toUTCString()}`,
      'MIME-Version: 1.0',
      `Content-Type: multipart/mixed; boundary="${boundary}"`, '', '',
      ...parts,
    ].filter(v => v !== null && v !== undefined).join('\r\n');
  }

  const raw = Buffer.from(mime, 'utf8').toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

  // LAST RESORT: Re-read DB immediately before calling Gmail API.
  // If another process already sent this for the CURRENT scheduled window, abort.
  // Use recurrence-aware window: for hourly emails, allow up to (hours - 2min) gap.
  // For all others, use 5 minutes as the duplicate window.
  if (email.id) {
    const freshCheck = await Email.findOne({ id: email.id }).lean();
    if (freshCheck?.lastSent && freshCheck?.nextSendTime) {
      const lastSentMs   = new Date(freshCheck.lastSent).getTime();
      const nextSendMs   = new Date(freshCheck.nextSendTime).getTime();
      // If lastSent is >= nextSendTime, this window was already handled
      if (lastSentMs >= nextSendMs) {
        // This can also happen if the process crashed after Gmail send but before
        // nextSendTime was advanced in MongoDB (stuck schedule). Best-effort: bump
        // nextSendTime forward so the email doesn't appear "stuck" (commonly seen
        // with hourly schedules).
        try {
          const decrypted = decryptEmailDoc(freshCheck);
          if (decrypted && decrypted.active && !isEmailDone(decrypted)) {
            const bumped = computeNextSendTime(decrypted);
            if (bumped) {
              await Email.findOneAndUpdate({ id: email.id }, { nextSendTime: bumped }, { returnDocument: 'after' });
              console.log('[send] Advanced stale nextSendTime after duplicate-prevented:', { id: email.id, from: new Date(nextSendMs).toISOString(), to: bumped });
            }
          }
        } catch (_) {}
        throw new Error(
          'DUPLICATE_PREVENTED: lastSent(' + new Date(lastSentMs).toISOString() + ') >= nextSendTime(' + new Date(nextSendMs).toISOString() + ') for id=' + String(email.id)
        );
      }
    } else if (freshCheck?.lastSent) {
      // Fallback: no nextSendTime — use recurrence interval as the window
      const recurrenceMs = email.recurrence?.hours
        ? email.recurrence.hours * 3_600_000
        : 5 * 60_000;
      const windowMs = Math.max(recurrenceMs - 2 * 60_000, 5 * 60_000);
      const msSince = Date.now() - new Date(freshCheck.lastSent).getTime();
      if (msSince < windowMs) {
        throw new Error(
          'DUPLICATE_PREVENTED: already sent ' + Math.round(msSince / 1000) + 's ago for id=' + String(email.id)
        );
      }
    }
  }

  try {
    const delays = [2000, 4000, 8000];
    for (let attempt = 0; attempt < (delays.length + 1); attempt++) {
      try {
        await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
        break;
      } catch (err) {
        const { status, apiMsg } = extractGoogleApiError(err);
        const retryable = Number.isFinite(status) && status >= 500 && status < 600;
        if (retryable && attempt < delays.length) { await sleep(delays[attempt]); continue; }
        throw err;
      }
    }
  } catch (err) {
    const { status, apiMsg, reason, data } = extractGoogleApiError(err);
    let extra = '';
    const diagnostics = {
      userEmail, instanceId,
      google: { status: status || null, reason: reason || null },
      token:  { hasAccessToken: !!tokens.access_token, hasRefreshToken: !!tokens.refresh_token, expiry_date: tokens.expiry_date || null, isExpired: isAccessTokenExpired(tokens) },
    };
    const isFailedPrecondition = status === 400 && (String(apiMsg).toLowerCase().includes('precondition') || reason === 'failedPrecondition');
    if (isFailedPrecondition) {
      try {
        if (tokens.access_token) {
          const info = await oauth2.getTokenInfo(tokens.access_token);
          diagnostics.tokenInfo = { expires_in: info?.expires_in ?? null, scope: info?.scope ?? null };
          diagnostics.hasGmailSendScope = String(info?.scope || '').includes('gmail.send');
        }
      } catch (e) { diagnostics.tokenInfoError = String(e?.message || e); }
      try {
        const prof = await gmail.users.getProfile({ userId: 'me' });
        diagnostics.profileEmail = prof?.data?.emailAddress || null;
        if (diagnostics.profileEmail && diagnostics.profileEmail.toLowerCase() !== String(userEmail).toLowerCase()) diagnostics.profileMismatch = true;
      } catch (e) { diagnostics.profileError = String(e?.message || e); }
      console.error('❌ Gmail failedPrecondition (400). Diagnostics:', diagnostics);
    } else {
      console.error('❌ Gmail send failed:', { status, reason, apiMsg });
    }
    if (String(apiMsg).toLowerCase().includes('precondition')) {
      extra = ' (If this is a Google Workspace account, ask your admin to enable Gmail API and allow third‑party access for this user, then reconnect.)';
    }
    throw new GmailSendError(`Gmail send failed${status ? ` (${status})` : ''}: ${apiMsg}${extra}`, {
      httpStatus: Number.isFinite(status) ? status : 500,
      googleStatus: status || null, googleReason: reason || null,
      diagnostics: { ...diagnostics, rawGoogleError: data?.error || data || null },
    });
  }
  console.log(`✅ Sent: "${email.subject}" → ${toHeader} | attachments: ${attachments.length}`);
}

// ── Shared scheduler logic (used by both cron and /cron-tick) ─────────────────

async function runSchedulerTick() {
  const now    = new Date();
  const emails = await Email.find({ active: true });

  for (const email of emails) {
    if (email.inFlightUntil && new Date(email.inFlightUntil) > new Date()) {
      console.log('[cron] Skipping locked:', email.id);
      continue;
    }
    if (isEmailDone(email))  continue;
    if (!email.nextSendTime) continue;

    const sendAt = new Date(email.nextSendTime);
    if (sendAt > now) continue;

    if (email.lastSent) {
      const diffMs = sendAt.getTime() - new Date(email.lastSent).getTime();
      // BUGFIX: Compare lastSent against the SCHEDULED send time, not now.
      // Previously: (now - lastSent) < 5min → skipped sends if cron ran shortly
      // after a successful send, even when the next scheduled time was already due.
      // Now: only skip if lastSent is AFTER the scheduled send time (already sent
      // for this window). A negative or small diffMs means it was sent after
      // nextSendTime — i.e. already handled. Positive diffMs means not yet sent.
      if (diffMs < 0) {
        console.log(`[cron] Duplicate prevented (lastSent=${new Date(email.lastSent).toISOString()} is after scheduled=${sendAt.toISOString()}):`, email.id);
        // If nextSendTime is stale (still behind lastSent), bump it forward so the
        // schedule doesn't get stuck in a permanent "duplicate prevented" loop.
        try {
          const decrypted = decryptEmailDoc(email.toObject ? email.toObject() : email);
          const bumped = (decrypted && decrypted.active && !isEmailDone(decrypted)) ? computeNextSendTime(decrypted) : null;
          if (bumped) await Email.findOneAndUpdate({ id: email.id }, { nextSendTime: bumped });
        } catch (_) {}
        continue;
      }
    }

    console.log('[cron] Firing email id=' + email.id + ' scheduled=' + sendAt.toISOString());

    // ROOT CAUSE FIX: email.userEmail is AES-ENCRYPTED in MongoDB — using it for
    // chromeHeartbeat.get() always returns undefined (encrypted blob never matches).
    // userEmailLower is stored PLAINTEXT for query purposes — use it instead.
    // Also fixed: /schedule was storing heartbeat with original-case email;
    // now always lowercased before storing (see /schedule and /heartbeat handlers).
    const ownerEmailLower = (email.userEmailLower || '').toLowerCase().trim();
    const lastHeartbeat   = ownerEmailLower ? chromeHeartbeat.get(ownerEmailLower) : null;
    const twoMinutesAgo   = Date.now() - (2 * 60 * 1000);
    const chromeIsAlive   = !!(lastHeartbeat && lastHeartbeat > twoMinutesAgo);

    // CHANGE: If Chrome is alive, prefer Chrome to send (prevents duplicates).
    // The server only sends when Chrome is offline, or when the schedule is overdue
    // by a grace period (Chrome might be stuck/asleep even while "alive").
    const CHROME_GRACE_MS = 3 * 60 * 1000;
    if (chromeIsAlive && (Date.now() - sendAt.getTime()) < CHROME_GRACE_MS) {
      console.log('[cron] Chrome is alive; skipping server send for', email.id);
      continue;
    }

    const locked = await tryAcquireSendLock(email.id);
    if (!locked) continue;

    const freshEmail = await Email.findOne({ id: email.id });

    if (freshEmail && freshEmail.lastSent) {
      const diffMs = sendAt.getTime() - new Date(freshEmail.lastSent).getTime();
      // BUGFIX: Same fix as above — compare lastSent against scheduled time, not now.
      if (diffMs < 0) {
        console.log('[cron] Aborting: lastSent is after scheduled time (fresh read):', email.id);
        try {
          const decrypted = decryptEmailDoc(freshEmail.toObject ? freshEmail.toObject() : freshEmail);
          const bumped = (decrypted && decrypted.active && !isEmailDone(decrypted)) ? computeNextSendTime(decrypted) : null;
          if (bumped) await Email.findOneAndUpdate({ id: email.id }, { nextSendTime: bumped });
        } catch (_) {}
        await releaseSendLock(email.id);
        continue;
      }
    }

    if (freshEmail && !freshEmail.active) {
      await releaseSendLock(email.id);
      continue;
    }

    const emailToSend = (freshEmail && freshEmail.toObject) ? freshEmail.toObject() : (locked.toObject ? locked.toObject() : locked);

    try {
      // ── FIX: forceReload tokens inside cron tick ───────────────────────────
      // On Vercel each cron-tick is a fresh HTTP request with an empty cache.
      // Without forceReload the allTokens object is {} and the send fails.
      const allTokens  = await loadTokens({ forceReload: true });

      // CHANGED: Decrypt only at send-time (in memory)
      const decryptedEmailToSend = decryptEmailDoc(emailToSend);
      // END CHANGED

      const emailOwner = decryptedEmailToSend.userEmail ? decryptedEmailToSend.userEmail.toLowerCase() : null;
      let   cronInstanceId = null;

      if (emailOwner) {
        for (const [key, val] of Object.entries(allTokens)) {
          if (val && typeof val === 'object' && val.userEmail && val.tokens) {
            if (val.userEmail.toLowerCase() === emailOwner) {
              cronInstanceId = key;
              break;
            }
          }
        }
      }

      // CHANGED: Decrypt only at send-time (in memory)
      await sendEmailViaGmail(decryptedEmailToSend, cronInstanceId);
      // END CHANGED

      const newSentCount = (emailToSend.sentCount || 0) + 1;
      const isOnce       = emailToSend.recurrence?.once === true || emailToSend.type === 'once';
      // BUGFIX: use Number.isFinite so NaN (from encrypted/invalid maxTimes) never
      // triggers a false reachedMax and incorrectly stops the email.
      const maxTimesNum  = parseInt(emailToSend.maxTimes);
      const reachedMax   = emailToSend.maxTimes !== 'indefinitely'
        && Number.isFinite(maxTimesNum)
        && newSentCount >= maxTimesNum;
      const isDone       = isOnce || reachedMax;
      const nextSendTime = isDone ? null : computeNextSendTime(emailToSend);

      await Email.findOneAndUpdate(
        { id: emailToSend.id },
        {
          sentCount: newSentCount,
          lastSent:  now.toISOString(),
          active:    isDone ? false : emailToSend.active,
          nextSendTime,
          inFlightUntil: null,
        },
        { returnDocument: 'after' }
      );

    } catch (err) {
      console.error(`❌ Failed to send "${email.subject}":`, err.message);
    } finally {
      try { await releaseSendLock(email.id); } catch (_) {}
    }
  }
  // END CHANGED
}

// ── /cron-tick endpoint — called by Vercel Cron every minute ─────────────────
// WHY THIS EXISTS: Vercel is a serverless platform. The node-cron job below
// only runs while a request is being handled — the process dies after each
// response. So cron.schedule() never fires on its own between requests.
//
// FIX: Add a plain HTTP endpoint that Vercel Cron calls on a schedule.
// This makes the scheduler work reliably on Vercel without any extra services.
// Just add vercel.json (included alongside this file) and deploy — done.
//
// If you ever migrate to Railway/Render/a VPS (persistent process), the
// cron.schedule below will handle it and you can ignore this endpoint.
app.post('/cron-tick', async (req, res) => {
  // Simple shared secret so random internet traffic can't spam this endpoint.
  // Set CRON_SECRET=any-random-string in your Vercel environment variables.
  const secret = process.env.CRON_SECRET || '';
  if (secret) {
    const authHeader = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (authHeader !== secret) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  try {
    await runSchedulerTick();
    res.json({ ok: true, time: new Date().toISOString() });
  } catch (err) {
    console.error('cron-tick error:', err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── Main scheduler — runs every second (works on Railway/Render/VPS) ─────────
// On Vercel this never fires between requests, so /cron-tick + vercel.json
// handles scheduling instead. Both can coexist safely.
async function runEmailCron() {
  try {
    await runSchedulerTick();
  } catch (err) {
    console.error('Cron error:', err.message);
  }
}

// Run frequently to minimize send-time drift. Supports seconds-field syntax in node-cron.
// Example: "*/10 * * * * *" (every 10 seconds). Default is every 10 seconds.
const CRON_EXPR = (process.env.CRON_EXPR || '*/10 * * * * *').toString().trim();
cron.schedule(CRON_EXPR, runEmailCron);

// ── Start ─────────────────────────────────────────────────────────────────────

app.post('/run-cron', async (req, res) => {
  const secret = (req.headers['x-cron-secret'] || '').toString().trim();
  if (!secret || secret !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    await runEmailCron();
    res.json({ ok: true, time: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Recurring Emails server running on port ${PORT}`);
  if (!process.env.CRON_SECRET) console.warn('⚠️  CRON_SECRET not set!');
  if (!process.env.GOOGLE_CLIENT_ID) console.warn('⚠️  GOOGLE_CLIENT_ID not set!');
  if (!process.env.MONGO_URI)        console.warn('⚠️  MONGO_URI not set!');
});

// Chrome heartbeat
app.post('/heartbeat', (req, res) => {
  // CHANGED: Always store heartbeat key in lowercase (matches runSchedulerTick lookup)
  const userEmail = (req.body?.userEmail || '')
    .toString().trim().toLowerCase();
  if (userEmail) chromeHeartbeat.set(userEmail, Date.now());
  // END CHANGED
  res.json({ ok: true });
});

app.get('/ping', async (req, res) => {
  try {
    await runSchedulerTick();
    res.json({ ok: true, time: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Minimal diagnostics endpoint to help verify scheduler/DB/heartbeat behavior.
// If CRON_SECRET is set, require `Authorization: Bearer <CRON_SECRET>`.
app.get('/status', async (req, res) => {
  const secret = process.env.CRON_SECRET || '';
  if (secret) {
    const authHeader = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (authHeader !== secret) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }

  try {
    const now = new Date();
    const activeCount = await Email.countDocuments({ active: true });
    const due = await Email.find({ active: true, nextSendTime: { $ne: null } })
      .sort({ nextSendTime: 1 })
      .limit(50)
      .lean();

    const dueNow = [];
    const nextUp = [];
    for (const e of due) {
      const nextMs = e?.nextSendTime ? new Date(e.nextSendTime).getTime() : NaN;
      const item = { id: e?.id || null, subject: e?.subject || '', nextSendTime: e?.nextSendTime || null, lastSent: e?.lastSent || null, inFlightUntil: e?.inFlightUntil || null };
      if (Number.isFinite(nextMs) && nextMs <= now.getTime()) dueNow.push(item);
      else nextUp.push(item);
      if (dueNow.length >= 10 && nextUp.length >= 10) break;
    }

    res.json({
      ok: true,
      time: now.toISOString(),
      mongo: { readyState: mongoose?.connection?.readyState ?? null },
      counts: { active: activeCount, heartbeatKeys: chromeHeartbeat.size },
      dueNow,
      nextUp: nextUp.slice(0, 10),
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});
