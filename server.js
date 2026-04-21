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

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Track whether the Chrome extension is currently online (prevents duplicate sends).
// When Chrome is online, the server acts as backup only.
const chromeHeartbeat = new Map(); // userEmail -> lastSeenMs
const HEARTBEAT_TTL_MS = 2 * 60_000;

// ── Connect MongoDB ───────────────────────────────────────────────────────────

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

// ── Token storage (file-based) ────────────────────────────────────────────────

const TOKENS_FILE = path.join(__dirname, 'tokens.json');
const AUTH_META_FILE = path.join(__dirname, 'auth.json');

let _tokensCache = null;
let _authMetaCache = null;

function setTokensCache(next) {
  const normalized = (next && typeof next === 'object') ? next : {};
  if (!_tokensCache) {
    _tokensCache = normalized;
    return _tokensCache;
  }
  if (_tokensCache === normalized) return _tokensCache;

  // Mutate in-place so any existing references keep seeing updates.
  for (const k of Object.keys(_tokensCache)) {
    if (!(k in normalized)) delete _tokensCache[k];
  }
  for (const [k, v] of Object.entries(normalized)) {
    _tokensCache[k] = v;
  }
  return _tokensCache;
}

async function loadTokens(opts = {}) {
  const forceReload = opts?.forceReload === true;
  if (_tokensCache && !forceReload) return _tokensCache;
  try {
    if (mongoose.connection.readyState === 1) {
      const doc = await AuthState.findOne({ key: 'tokens' }).lean();
      if (doc?.value && typeof doc.value === 'object') {
        return setTokensCache(doc.value);
      }
    }
  } catch (_) {}
  // Fallback: file-based
  if (!fs.existsSync(TOKENS_FILE)) return setTokensCache({});
  try { return setTokensCache(JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'))); }
  catch (_) { return setTokensCache({}); }
}

async function saveTokens(tokens) {
  setTokensCache(tokens);
  try {
    if (mongoose.connection.readyState === 1) {
      await AuthState.findOneAndUpdate(
        { key: 'tokens' },
        { value: _tokensCache },
        { upsert: true }
      );
    }
  } catch (_) {}
  // Best-effort mirror to file for local dev
  try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(_tokensCache, null, 2)); } catch (_) {}
}

function setAuthMetaCache(next) {
  const normalized = (next && typeof next === 'object') ? next : {};
  if (!_authMetaCache) {
    _authMetaCache = normalized;
    return _authMetaCache;
  }
  if (_authMetaCache === normalized) return _authMetaCache;
  for (const k of Object.keys(_authMetaCache)) {
    if (!(k in normalized)) delete _authMetaCache[k];
  }
  for (const [k, v] of Object.entries(normalized)) {
    _authMetaCache[k] = v;
  }
  return _authMetaCache;
}

async function loadAuthMeta(opts = {}) {
  const forceReload = opts?.forceReload === true;
  if (_authMetaCache && !forceReload) return _authMetaCache;
  try {
    if (mongoose.connection.readyState === 1) {
      const doc = await AuthState.findOne({ key: 'meta' }).lean();
      if (doc?.value && typeof doc.value === 'object') {
        return setAuthMetaCache(doc.value);
      }
    }
  } catch (_) {}
  if (!fs.existsSync(AUTH_META_FILE)) return setAuthMetaCache({});
  try { return setAuthMetaCache(JSON.parse(fs.readFileSync(AUTH_META_FILE, 'utf8'))); }
  catch (_) { return setAuthMetaCache({}); }
}

async function saveAuthMeta(meta) {
  setAuthMetaCache(meta);
  try {
    if (mongoose.connection.readyState === 1) {
      await AuthState.findOneAndUpdate(
        { key: 'meta' },
        { value: _authMetaCache },
        { upsert: true }
      );
    }
  } catch (_) {}
  try { fs.writeFileSync(AUTH_META_FILE, JSON.stringify(_authMetaCache, null, 2)); } catch (_) {}
}

function listTokenEmails(tokens) {
  return Object.keys(tokens || {}).filter(k => k.includes('@'));
}

async function getPrimaryUserEmail() {
  const allTokens = await loadTokens();
  const emails = listTokenEmails(allTokens);
  if (!emails.length) return null;

  const meta = await loadAuthMeta();
  if (meta.lastConnectedEmail && allTokens[meta.lastConnectedEmail]) return meta.lastConnectedEmail;
  return emails[0];
}

// ── OAuth2 client ─────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isAccessTokenExpired(tokens, skewMs = 30_000) {
  const expiry = Number(tokens?.expiry_date);
  if (!Number.isFinite(expiry) || expiry <= 0) return false;
  return expiry <= (Date.now() + skewMs);
}

function extractGoogleApiError(err) {
  const status = err?.code || err?.response?.status || null;
  const data = err?.response?.data;
  const apiMsg = data?.error?.message || err?.message || 'Unknown Gmail API error';
  const reason =
    data?.error?.errors?.[0]?.reason ||
    data?.error?.status ||
    null;
  return { status, apiMsg, reason, data };
}

class GmailSendError extends Error {
  constructor(message, opts = {}) {
    super(message);
    this.name = 'GmailSendError';
    this.httpStatus = opts.httpStatus || 500;
    this.googleStatus = opts.googleStatus || null;
    this.googleReason = opts.googleReason || null;
    this.diagnostics = opts.diagnostics || null;
  }
}

async function deactivateEmail(email, reason) {
  try {
    if (!email?.id) return;
    await Email.findOneAndUpdate(
      { id: email.id },
      { active: false, inFlightUntil: null },
      { returnDocument: 'after' }
    );
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

// ── OAuth: get auth URL ───────────────────────────────────────────────────────

app.get('/oauth/url', (req, res) => {
  const oauth2 = makeOAuthClient();
  const url = oauth2.generateAuthUrl({
    access_type: 'offline',
    prompt:      'consent',
    scope: [
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/userinfo.email',
    ],
  });
  // res.json({ url });
  res.redirect(url);
});

// ── OAuth: callback ───────────────────────────────────────────────────────────

app.get('/oauth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');
  try {
    const oauth2 = makeOAuthClient();
    const { tokens } = await oauth2.getToken(code);
    oauth2.setCredentials(tokens);

    const oauth2Api = google.oauth2({ version: 'v2', auth: oauth2 });
    const { data }  = await oauth2Api.userinfo.get();
    const email     = data.email;

    const allTokens  = await loadTokens();
    if (allTokens[email]?.refresh_token && !tokens.refresh_token) {
      tokens.refresh_token = allTokens[email].refresh_token;
    }
    allTokens[email] = tokens;
    await saveTokens(allTokens);
    await saveAuthMeta({ lastConnectedEmail: email, connectedAt: new Date().toISOString() });

    console.log(`✅ Tokens saved for ${email}`);
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

// ── Save token from extension ─────────────────────────────────────────────────

app.post('/oauth/token', async (req, res) => {
  const { email, tokens } = req.body;
  if (!email || !tokens) return res.status(400).json({ error: 'Missing email or tokens' });

  const allTokens = await loadTokens();
  const existing  = allTokens[email] || {};

  const merged = {
    ...existing,
    ...tokens,
    refresh_token: tokens.refresh_token || existing.refresh_token || null,
  };

  if (!merged.refresh_token) {
    console.warn(`⚠️  No refresh_token for ${email} — server sending may fail after token expiry`);
  }

  allTokens[email] = merged;
  await saveTokens(allTokens);
  await saveAuthMeta({ lastConnectedEmail: email, connectedAt: new Date().toISOString() });
  console.log(`💾 Token updated for ${email} (has refresh: ${!!merged.refresh_token})`);
  res.json({ ok: true });
});

// ── Auth status (used by Chrome extension UI) ────────────────────────────────

app.get('/auth/status', (req, res) => {
  getPrimaryUserEmail()
    .then(email => res.json({ connected: !!email, email: email || null }))
    .catch(err => res.status(500).json({ connected: false, email: null, error: err.message }));
});

// Optional: Disconnect (delete stored tokens)
app.post('/auth/disconnect', async (req, res) => {
  try {
    const allTokens = await loadTokens();
    const email = (req.body?.email || '').toString().trim();
    const mode = (req.body?.mode || '').toString().trim(); // "all" or ""

    if (mode === 'all') {
      for (const k of Object.keys(allTokens)) delete allTokens[k];
      await saveTokens(allTokens);
      await saveAuthMeta({});
      return res.json({ ok: true });
    }

    if (email && allTokens[email]) {
      delete allTokens[email];
      await saveTokens(allTokens);
    }

    const remaining = listTokenEmails(await loadTokens());
    if (!remaining.length) await saveAuthMeta({});
    else {
      const meta = await loadAuthMeta();
      if (meta.lastConnectedEmail === email) await saveAuthMeta({ lastConnectedEmail: remaining[0], connectedAt: new Date().toISOString() });
    }

    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── Schedule / update an email ────────────────────────────────────────────────

// ── Schedule / update an email ────────────────────────────────────────────────

app.post('/schedule', async (req, res) => {
  try {
    const incoming = req.body;
    if (!incoming || !incoming.id) return res.status(400).json({ error: 'Invalid email data' });

    if (!incoming.userEmail) {
      const primary = await getPrimaryUserEmail();
      if (primary) incoming.userEmail = primary;
      else return res.status(400).json({ error: 'No authenticated user — cannot schedule email' });
    }

    // If this schedule request came from the Chrome extension, treat Chrome as online immediately
    // so the cron job doesn't race and double-send before the first heartbeat tick.
    incoming.userEmail = String(incoming.userEmail || '').trim();
    incoming.userEmailLower = incoming.userEmail ? incoming.userEmail.toLowerCase() : '';

    if (incoming.fromChrome && incoming.userEmail) {
      chromeHeartbeat.set(incoming.userEmail, Date.now());
    }

    // ✅ FIX: Sanitize recipient fields — guard against [object Object] stored in old records
    incoming.userEmail = String(incoming.userEmail || '').trim();
    incoming.userEmailLower = incoming.userEmail ? incoming.userEmail.toLowerCase() : '';

    incoming.to  = sanitizeRecipient(incoming.to);
    incoming.cc  = sanitizeRecipient(incoming.cc);
    incoming.bcc = sanitizeRecipient(incoming.bcc);

    const existing = await Email.findOne({ id: incoming.id });

    if (existing) {
        const wantsClear = incoming.clearAttachments === true;
        
        // ✅ FIX: Start with existing data to be safe
        const updateDoc = { ...existing.toObject(), ...incoming };

        // ✅ FIX: Explicitly handle sentCount/lastSent so they don't revert
        updateDoc.sentCount = incoming.sentCount ?? existing.sentCount ?? 0;
        updateDoc.lastSent = incoming.lastSent ?? existing.lastSent ?? null;

        // ✅ FIX: Attachment Preservation Logic
        if (wantsClear) {
          // User explicitly clicked "Clear Attachments"
          updateDoc.attachments = [];
          updateDoc.attachmentIds = [];
        } else {
          // If incoming data has attachments, use them.
          // If incoming data has NO attachments (empty/undefined), keep OLD ones (don't delete them!).
          const hasNewAttachments = Array.isArray(incoming.attachments) && incoming.attachments.length > 0;
          if (!hasNewAttachments) {
            // Preserve existing attachments from DB record
            updateDoc.attachments = existing.attachments || [];
            updateDoc.attachmentIds = existing.attachmentIds || [];
            // Ensure we don't revert to empty if incoming payload had empty arrays
            delete updateDoc.attachments; 
            delete updateDoc.attachmentIds;
          }
        }

        // Remove _id to prevent MongoDB errors on update
        delete updateDoc._id;

        await Email.findOneAndUpdate(
          { id: incoming.id },
          updateDoc,
          { returnDocument: 'after' }
        );
        console.log(`📝 Updated: "${incoming.subject}" | attachments: ${(updateDoc.attachments || existing.attachments || []).length}`);
    } else {
        // ✅ FIX: MISSING ELSE BLOCK - This handles NEW emails
        await Email.create(incoming);
        console.log(`📅 New: "${incoming.subject}" → ${incoming.nextSendTime} | attachments: ${(incoming.attachments || []).length}`);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Schedule error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Send now (used by Chrome extension when Chrome is open) ──────────────────

app.post('/send-now', async (req, res) => {
  let emailIdForUnlock = null;
  try {
    const incoming = req.body?.email || req.body;
    if (!incoming || !incoming.id) return res.status(400).json({ ok: false, error: 'Invalid email data' });
    emailIdForUnlock = incoming.id;

    if (!incoming.userEmail) {
      const primary = await getPrimaryUserEmail();
      if (primary) incoming.userEmail = primary;
      else return res.status(400).json({ ok: false, error: 'No authenticated user' });
    }

    incoming.to  = sanitizeRecipient(incoming.to);
    incoming.cc  = sanitizeRecipient(incoming.cc);
    incoming.bcc = sanitizeRecipient(incoming.bcc);

    const existing = await Email.findOne({ id: incoming.id });
    const merged = existing ? { ...existing.toObject(), ...incoming } : incoming;

    // If attachments were not included in this request, keep stored attachments.
    if ((!Array.isArray(merged.attachments) || merged.attachments.length === 0) && existing?.attachments?.length) {
      merged.attachments = existing.attachments;
    }

    // Persist latest payload before acquiring lock (do not overwrite lock fields here)
    const mergedToStore = { ...merged };
    delete mergedToStore.inFlightUntil;
    await Email.findOneAndUpdate({ id: merged.id }, mergedToStore, { upsert: true });

    const locked = await tryAcquireSendLock(merged.id);
    if (!locked) {
      const current = await Email.findOne({ id: merged.id });
      return res.status(409).json({
        ok: false,
        inProgress: true,
        retryAfterMs: 30_000,
        email: stripEmailPayload(current),
        error: 'Email is already sending. Please try again in a moment.',
      });
    }

    await sendEmailViaGmail(locked.toObject ? locked.toObject() : locked);

    const now = new Date();
    const newSentCount = (merged.sentCount || 0) + 1;
    const isOnce       = merged.recurrence?.once === true || merged.type === 'once';
    const reachedMax   = merged.maxTimes !== 'indefinitely' && newSentCount >= parseInt(merged.maxTimes);
    const isDone       = isOnce || reachedMax;

    const nextSendTime = isDone ? null : computeNextSendTime(merged);

    const updated = await Email.findOneAndUpdate(
      { id: merged.id },
      {
        sentCount: newSentCount,
        lastSent: now.toISOString(),
        active: isDone ? false : merged.active,
        nextSendTime,
        inFlightUntil: null,
      },
      { returnDocument: 'after' }
    );

    res.json({ ok: true, email: stripEmailPayload(updated) });
  } catch (err) {
    const status = (err && typeof err === 'object' && Number.isFinite(err.httpStatus))
      ? err.httpStatus
      : 500;
    res.status(status).json({ ok: false, error: err?.message || String(err || 'Unknown error') });
  } finally {
    try { await releaseSendLock(emailIdForUnlock); } catch (_) {}
  }
});

// ── Get emails for a user ─────────────────────────────────────────────────────

// Diagnostic endpoint for debugging Gmail API auth/sending
// POST /test-send { userEmail: "..." }
app.post('/test-send', async (req, res) => {
  const requestedEmail = (req.body?.userEmail || '').toString().trim() || null;
  const diagnostics = {
    requestedEmail,
    resolvedUserEmail: null,
    token: null,
    tokenInfo: null,
    profile: null,
    send: null,
    gmailError: null,
  };

  try {
    console.log('[test-send] start', { requestedEmail });

    const allTokens = await loadTokens();
    const userEmail = requestedEmail || await getPrimaryUserEmail() || Object.keys(allTokens)[0];
    diagnostics.resolvedUserEmail = userEmail || null;
    if (!userEmail) return res.status(400).json({ ok: false, error: 'No authenticated user found', diagnostics });

    const tokens = allTokens[userEmail];
    if (!tokens) return res.status(404).json({ ok: false, error: `No tokens for ${userEmail}`, diagnostics });

    diagnostics.token = {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiry_date: tokens.expiry_date || null,
      isExpired: isAccessTokenExpired(tokens),
    };
    console.log('[test-send] token loaded', diagnostics.token);

    const oauth2 = makeOAuthClient();
    oauth2.setCredentials(tokens);
    console.log('[test-send] credentials set');

    if (tokens.access_token) {
      try {
        const info = await oauth2.getTokenInfo(tokens.access_token);
        diagnostics.tokenInfo = {
          expires_in: info?.expires_in ?? null,
          scope: info?.scope ?? null,
        };
        diagnostics.tokenInfo.hasGmailSendScope = String(info?.scope || '').includes('gmail.send');
        console.log('[test-send] tokenInfo', diagnostics.tokenInfo);
      } catch (e) {
        diagnostics.tokenInfo = { error: String(e?.message || e) };
        console.warn('[test-send] tokenInfo failed', diagnostics.tokenInfo);
      }
    }

    const gmail = google.gmail({ version: 'v1', auth: oauth2 });

    try {
      const prof = await gmail.users.getProfile({ userId: 'me' });
      diagnostics.profile = { emailAddress: prof?.data?.emailAddress || null };
      diagnostics.profile.mismatch = !!(
        diagnostics.profile.emailAddress &&
        diagnostics.profile.emailAddress.toLowerCase() !== String(userEmail).toLowerCase()
      );
      console.log('[test-send] profile', diagnostics.profile);
    } catch (e) {
      diagnostics.profile = { error: String(e?.message || e) };
      console.warn('[test-send] profile failed', diagnostics.profile);
    }

    const subject = `Test send ${new Date().toISOString()}`;
    const subjectB64 = Buffer.from(subject, 'utf8').toString('base64');
    const body = `Test email sent at ${new Date().toISOString()} from Recurring Gmail server.`;
    const bodyB64 = chunkBase64Lines(Buffer.from(body, 'utf8').toString('base64'));
    const mime = [
      `From: ${userEmail}`,
      `To: ${userEmail}`,
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      `Date: ${new Date().toUTCString()}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      bodyB64,
    ].join('\r\n');

    const raw = Buffer.from(mime, 'utf8')
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    console.log('[test-send] sending…');

    const delays = [2000, 4000, 8000];
    let lastErr = null;
    let responseData = null;

    for (let attempt = 0; attempt < (delays.length + 1); attempt++) {
      try {
        const resp = await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
        responseData = resp?.data || null;
        lastErr = null;
        break;
      } catch (e) {
        lastErr = e;
        const { status, apiMsg } = extractGoogleApiError(e);
        const retryable = Number.isFinite(status) && status >= 500 && status < 600;
        if (retryable && attempt < delays.length) {
          const waitMs = delays[attempt];
          console.warn(`[test-send] Gmail 5xx (${status}). Retry ${attempt + 1}/${delays.length} in ${waitMs}ms: ${apiMsg}`);
          await sleep(waitMs);
          continue;
        }
        break;
      }
    }

    if (lastErr) {
      const { status, apiMsg, reason, data } = extractGoogleApiError(lastErr);
      diagnostics.gmailError = {
        status: status || null,
        reason: reason || null,
        message: apiMsg,
        raw: data?.error || data || null,
      };
      console.error('[test-send] failed', diagnostics.gmailError);
      return res.status(Number.isFinite(status) ? status : 500).json({
        ok: false,
        error: `Gmail send failed${status ? ` (${status})` : ''}: ${apiMsg}`,
        diagnostics,
      });
    }

    diagnostics.send = { ok: true, response: responseData };
    console.log('[test-send] success', responseData);
    return res.json({ ok: true, diagnostics });
  } catch (err) {
    console.error('[test-send] unexpected error', err);
    return res.status(500).json({ ok: false, error: err?.message || String(err || 'Unknown error'), diagnostics });
  }
});

app.get('/emails', async (req, res) => {
  try {
    const userEmailRaw = (req.query?.userEmail || '').toString();
    const userEmail = userEmailRaw.trim();
    const userEmailLower = userEmail ? userEmail.toLowerCase() : '';
    const filter = userEmail ? { $or: [{ userEmailLower }, { userEmail }] } : {};
    // ✅ FIX: Select all fields EXCEPT 'attachments'. This makes the UI fast and responsive.
    let emails = await Email.find(filter).select('-attachments');

    if (userEmail && !emails.length) {
      // Back-compat: case-insensitive match on userEmail field.
      emails = await Email.find({ userEmail }).collation({ locale: 'en', strength: 2 }).select('-attachments');
    }

    if (userEmail && !emails.length) {
      // Migration safety net: if the requester is the primary authenticated account,
      // adopt any legacy rows with missing userEmail so they show up in the extension UI.
      const primary = await getPrimaryUserEmail().catch(() => null);
      if (primary && primary.toLowerCase() === userEmailLower) {
        const unassignedFilter = {
          $or: [
            { userEmail: '' },
            { userEmail: null },
            { userEmailLower: '' },
            { userEmailLower: null },
            { userEmailLower: { $exists: false } },
          ],
        };
        const unassignedCount = await Email.countDocuments(unassignedFilter);
        if (unassignedCount > 0) {
          await Email.updateMany(unassignedFilter, { userEmail: primary, userEmailLower });
          emails = await Email.find({ $or: [{ userEmailLower }, { userEmail: primary }] }).select('-attachments');
        }
      }
    }

    res.json(emails);
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
    if (req.body && req.body.userEmail) {
      const u = String(req.body.userEmail || '').trim();
      req.body.userEmail = u;
      req.body.userEmailLower = u ? u.toLowerCase() : '';
    }
    const updated = await Email.findOneAndUpdate(
      { id: req.params.id },
      req.body,
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true, email: stripEmailPayload(updated) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────

// ✅ FIX: Sanitize recipient — converts arrays/objects to plain string, strips [object Object]
function sanitizeRecipient(val) {
  if (!val) return '';
  if (Array.isArray(val)) return val.map(v => (typeof v === 'string' ? v : v?.email || v?.address || '')).filter(Boolean).join(',');
  const str = String(val).trim();
  return str === '[object Object]' ? '' : str;
}

function stripEmailPayload(emailDoc) {
  if (!emailDoc) return emailDoc;
  const obj = typeof emailDoc.toObject === 'function' ? emailDoc.toObject() : { ...emailDoc };
  delete obj.attachments; // can be very large (base64)
  return obj;
}

async function tryAcquireSendLock(emailId, lockMs = 2 * 60_000) {
  const nowIso   = new Date().toISOString();
  const untilIso = new Date(Date.now() + lockMs).toISOString();
  const doc = await Email.findOneAndUpdate(
    {
      id: emailId,
      $or: [
        { inFlightUntil: null },
        { inFlightUntil: { $lt: nowIso } },
      ],
    },
    { inFlightUntil: untilIso },
    { returnDocument: 'after' }
  );
  return doc;
}

async function releaseSendLock(emailId) {
  if (!emailId) return;
  await Email.findOneAndUpdate({ id: emailId }, { inFlightUntil: null });
}

function isEmailDone(email) {
  const isOnce     = email.recurrence?.once === true || email.type === 'once';
  const reachedMax = email.maxTimes !== 'indefinitely' &&
                     (email.sentCount || 0) >= parseInt(email.maxTimes);
  return !email.active || (isOnce && (email.sentCount || 0) >= 1) || reachedMax;
}

function computeNextSendTime(email) {
  const r   = email.recurrence || {};
  const now = new Date();
  const [h, m] = (email.time || '08:00').split(':').map(Number);

  if (r.once) return null;

  if (r.hours) {
    return new Date(now.getTime() + r.hours * 3_600_000).toISOString();
  }

  if (r.weeks) {
    const targetDay = typeof r.dayOfWeek === 'number' ? r.dayOfWeek : 1;
    const next = new Date(now);
    next.setHours(h, m, 0, 0);
    let daysUntil = (targetDay - now.getDay() + 7) % 7;
    if (daysUntil === 0 && next <= now) daysUntil = 7;
    next.setDate(next.getDate() + daysUntil);
    return next.toISOString();
  }

  if (r.days) {
    const next = new Date(now);
    next.setDate(next.getDate() + r.days);
    next.setHours(h, m, 0, 0);
    return next.toISOString();
  }

  if (r.months) {
    const fallbackFromNext = email.nextSendTime ? new Date(email.nextSendTime).getDate() : now.getDate();
    const targetDay = Number.isFinite(r.dayOfMonth) ? r.dayOfMonth : fallbackFromNext;
    const next = new Date(now);
    next.setHours(h, m, 0, 0);
    next.setDate(1);
    next.setMonth(next.getMonth() + r.months);
    const dim = new Date(next.getFullYear(), next.getMonth() + 1, 0).getDate();
    next.setDate(Math.min(Math.max(1, targetDay), dim));
    return next.toISOString();
  }

  const next = new Date(now);
  next.setDate(next.getDate() + 1);
  next.setHours(h, m, 0, 0);
  return next.toISOString();
}

// ── Send email via Gmail API ──────────────────────────────────────────────────

function chunkBase64Lines(b64, lineLen = 76) {
  const s = String(b64 || '').replace(/\r?\n/g, '');
  if (!s) return '';
  let out = '';
  for (let i = 0; i < s.length; i += lineLen) {
    out += s.slice(i, i + lineLen) + '\r\n';
  }
  return out.replace(/\r\n$/, '');
}

async function sendEmailViaGmail(email) {
  // ✅ FIX: Sanitize recipient at send time to catch any corrupted DB records
  const toStr = sanitizeRecipient(email.to);
  if (!toStr || toStr === '[object Object]') {
    throw new Error('Recipient address required');
  }

  const allTokens = await loadTokens();
  const userEmail = email.userEmail || await getPrimaryUserEmail() || Object.keys(allTokens)[0];
  if (!userEmail) throw new Error('No authenticated user found');

  const tokens = allTokens[userEmail];
  if (!tokens) throw new Error(`No tokens for ${userEmail}`);

  const isExpired = isAccessTokenExpired(tokens);
  if (isExpired && !tokens.refresh_token) {
    const msg = 'Token expired and no refresh_token available. Please reconnect via /oauth/url';
    console.error(msg, {
      userEmail,
      expiry_date: tokens.expiry_date || null,
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: false,
    });
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
    if (newTokens.access_token) tokens.access_token = newTokens.access_token;
    if (newTokens.expiry_date) tokens.expiry_date  = newTokens.expiry_date;
    allTokens[userEmail] = tokens;
    void saveTokens(allTokens);
    console.log(`🔄 Token refreshed for ${userEmail}`);
  });

  const gmail = google.gmail({ version: 'v1', auth: oauth2 });

  const boundary  = `boundary_${Date.now()}`;
  const toHeader  = toStr;
  const ccHeader  = sanitizeRecipient(email.cc);
  const bccHeader = sanitizeRecipient(email.bcc);
  const fromHeader = sanitizeRecipient(email.from) || userEmail;

 // ── FIX: Define Subject and Body ────────────────────────────────────────
const subjectB64 = Buffer.from(email.subject || '(no subject)', 'utf8').toString('base64');

const bodyType = email.bodyType === 'html' ? 'html' : 'text';
const bodyContentType = bodyType === 'html' ? 'text/html' : 'text/plain';
let bodyContent = String(email.body || '');

// Force fallback if body is empty to solve "no content" issue
// ✅ FIX: BLOCK EMPTY EMAILS
if (!bodyContent || bodyContent.trim() === '') {
    console.error('❌ ABORTING SEND: Email body is empty. Deleting this bad schedule.');
    // Deactivate this specific email so it stops firing
    deactivateEmail(email, 'empty_body_detected');
    // Throw error to stop the process
    throw new Error('Email body is empty. Please delete this schedule and create a new one.');
}

const bodyB64 = chunkBase64Lines(Buffer.from(bodyContent, 'utf8').toString('base64'));

const attachments = Array.isArray(email.attachments)
  ? email.attachments.filter(a => a && (a.dataBase64 || a.data))
  : [];

  let mime;

  if (attachments.length === 0) {
    mime = [
      `From: ${fromHeader}`,
      `To: ${toHeader}`,
      ccHeader  ? `Cc: ${ccHeader}`   : null,
      bccHeader ? `Bcc: ${bccHeader}` : null,
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      `Date: ${new Date().toUTCString()}`,
      'MIME-Version: 1.0',
      `Content-Type: ${bodyContentType}; charset=UTF-8`,
      'Content-Transfer-Encoding: base64',
      '',
      bodyB64,
    ].filter(v => v !== null && v !== undefined).join('\r\n');
  } else {
    const parts = [
      `--${boundary}`,
      `Content-Type: ${bodyContentType}; charset=UTF-8`,
      'Content-Transfer-Encoding: base64',
      '',
      bodyB64,
      '',
    ];

    for (const att of attachments) {
      const attName = (att.name || 'attachment').replace(/[\r\n"]/g, '');
      const attType = att.type || 'application/octet-stream';
      let b64 = (att.dataBase64 || att.data || '').replace(/\r?\n/g, '');
      if (b64.includes('base64,')) b64 = b64.split('base64,').pop() || '';
      if (!b64) continue;

      parts.push('');
      parts.push(`--${boundary}`);
      parts.push(`Content-Type: ${attType}; name="${attName}"`);
      parts.push(`Content-Disposition: attachment; filename="${attName}"`);
      parts.push('Content-Transfer-Encoding: base64');
      parts.push('');
      parts.push(chunkBase64Lines(b64));
      parts.push('');
    }
    parts.push(`--${boundary}--`);

    mime = [
      `From: ${fromHeader}`,
      `To: ${toHeader}`,
      ccHeader  ? `Cc: ${ccHeader}`   : null,
      bccHeader ? `Bcc: ${bccHeader}` : null,
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      `Date: ${new Date().toUTCString()}`,
      'MIME-Version: 1.0',
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      '',
      ...parts,
    ].filter(v => v !== null && v !== undefined).join('\r\n');
  }

  const raw = Buffer.from(mime, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  try {
    const delays = [2000, 4000, 8000];
    for (let attempt = 0; attempt < (delays.length + 1); attempt++) {
      try {
        await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
        break;
      } catch (err) {
        const { status, apiMsg } = extractGoogleApiError(err);
        const retryable = Number.isFinite(status) && status >= 500 && status < 600;
        if (retryable && attempt < delays.length) {
          const waitMs = delays[attempt];
          console.warn(`Gmail 5xx (${status}). Retry ${attempt + 1}/${delays.length} in ${waitMs}ms: ${apiMsg}`);
          await sleep(waitMs);
          continue;
        }
        throw err;
      }
    }
  } catch (err) {
    const { status, apiMsg, reason, data } = extractGoogleApiError(err);
    let extra = '';

    const diagnostics = {
      userEmail,
      google: { status: status || null, reason: reason || null },
      token: {
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiry_date: tokens.expiry_date || null,
        isExpired: isAccessTokenExpired(tokens),
      },
    };

    const isFailedPrecondition =
      status === 400 && (String(apiMsg).toLowerCase().includes('precondition') || reason === 'failedPrecondition');

    if (isFailedPrecondition) {
      try {
        if (tokens.access_token) {
          const info = await oauth2.getTokenInfo(tokens.access_token);
          diagnostics.tokenInfo = {
            expires_in: info?.expires_in ?? null,
            scope: info?.scope ?? null,
          };
          diagnostics.hasGmailSendScope = String(info?.scope || '').includes('gmail.send');
        }
      } catch (e) {
        diagnostics.tokenInfoError = String(e?.message || e);
      }

      try {
        const prof = await gmail.users.getProfile({ userId: 'me' });
        diagnostics.profileEmail = prof?.data?.emailAddress || null;
        if (diagnostics.profileEmail && diagnostics.profileEmail.toLowerCase() !== String(userEmail).toLowerCase()) {
          diagnostics.profileMismatch = true;
        }
      } catch (e) {
        diagnostics.profileError = String(e?.message || e);
      }

      console.error('❌ Gmail failedPrecondition (400). Diagnostics:', diagnostics);
    } else {
      console.error('❌ Gmail send failed:', { status, reason, apiMsg });
    }
    if (String(apiMsg).toLowerCase().includes('precondition')) {
      extra = ' (If this is a Google Workspace account, ask your admin to enable Gmail API and allow third‑party access for this user, then reconnect.)';
    }
    throw new GmailSendError(`Gmail send failed${status ? ` (${status})` : ''}: ${apiMsg}${extra}`, {
      httpStatus: Number.isFinite(status) ? status : 500,
      googleStatus: status || null,
      googleReason: reason || null,
      diagnostics: { ...diagnostics, rawGoogleError: data?.error || data || null },
    });
  }
  console.log(`✅ Sent: "${email.subject}" → ${toHeader} | attachments: ${attachments.length}`);
}

// ── Main scheduler — runs every minute ───────────────────────────────────────

cron.schedule('* * * * *', async () => {
  try {
    const now    = new Date();
    const emails = await Email.find({ active: true });

    for (const email of emails) {
      if (isEmailDone(email)) continue;
      if (!email.nextSendTime)  continue;

      const sendAt = new Date(email.nextSendTime);
      if (sendAt > now) continue;

      if (email.lastSent) {
        const diffMinutes = (now - new Date(email.lastSent)) / 1000 / 60;
        if (diffMinutes < 5) {
          console.log(`⏭️  Skipping "${email.subject}" — sent ${diffMinutes.toFixed(1)} min ago by Chrome`);
          const isOnce = email.recurrence?.once === true || email.type === 'once';
          if (!isOnce) {
            await Email.findOneAndUpdate(
              { id: email.id },
              { nextSendTime: computeNextSendTime(email) }
            );
          }
          continue;
        }
      }

      console.log(`⏰ Firing: "${email.subject}" (scheduled ${sendAt.toISOString()})`);

      try {
        const locked = await tryAcquireSendLock(email.id);
        if (!locked) continue; // another sender (Chrome or cron) is handling it
        await sendEmailViaGmail(locked.toObject ? locked.toObject() : locked);

        const newSentCount = (email.sentCount || 0) + 1;
        const isOnce       = email.recurrence?.once === true || email.type === 'once';
        const reachedMax   = email.maxTimes !== 'indefinitely' &&
                             newSentCount >= parseInt(email.maxTimes);
        const isDone       = isOnce || reachedMax;

              await Email.findOneAndUpdate(
        { id: email.id },
        {
          sentCount:    newSentCount,
          lastSent:     now.toISOString(),
          active:       isDone ? false : email.active,
          nextSendTime: isDone ? null  : computeNextSendTime(email),
          inFlightUntil: null,
        },
        { returnDocument: 'after' }
      );

      } catch (err) {
        console.error(`❌ Failed to send "${email.subject}":`, err.message);

        // ✅ FIX: Only permanently deactivate on auth errors.
        // For network/temporary errors, retry in 5 minutes instead of killing the schedule.
        const msg = String(err?.message || '');
        const isAuthError = msg.includes('401') ||
                            msg.includes('No tokens') ||
                            msg.includes('No refresh') ||
                            msg.includes('refresh_token') ||
                            msg.includes('Token expired') ||
                            msg.includes('No authenticated');

        if (isAuthError) {
          console.log(`🔒 Auth error — deactivating "${email.subject}"`);
          await Email.findOneAndUpdate({ id: email.id }, { active: false, inFlightUntil: null });
        } else {
          const retryAt = new Date(Date.now() + 5 * 60_000).toISOString();
          console.log(`🔁 Temporary error — will retry "${email.subject}" at ${retryAt}`);
          await Email.findOneAndUpdate({ id: email.id }, { nextSendTime: retryAt, inFlightUntil: null });
        }
      } finally {
        try { await releaseSendLock(email.id); } catch (_) {}
      }
    }
  } catch (err) {
    console.error('Cron error:', err.message);
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`🚀 Recurring Emails server running on port ${PORT}`);
  if (!process.env.GOOGLE_CLIENT_ID) console.warn('⚠️  GOOGLE_CLIENT_ID not set!');
  if (!process.env.MONGO_URI)        console.warn('⚠️  MONGO_URI not set!');
});

// Chrome heartbeat (prevents server from sending duplicates while Chrome is open)
app.post('/heartbeat', (req, res) => {
  const userEmail = (req.body?.userEmail || '').toString().trim();
  if (userEmail) chromeHeartbeat.set(userEmail, Date.now());
  res.json({ ok: true });
});
