require('dotenv').config();

const express    = require('express');
const cron       = require('node-cron');
const cors       = require('cors');
const fs         = require('fs');
const path       = require('path');
const { google } = require('googleapis');
const mongoose   = require('mongoose');
const Email      = require('./models/Email');

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

function loadTokens() {
  if (!fs.existsSync(TOKENS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8')); }
  catch (_) { return {}; }
}

function saveTokens(tokens) {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
}

// ── OAuth2 client ─────────────────────────────────────────────────────────────

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
  res.json({ url });
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

    const allTokens  = loadTokens();
    if (allTokens[email]?.refresh_token && !tokens.refresh_token) {
      tokens.refresh_token = allTokens[email].refresh_token;
    }
    allTokens[email] = tokens;
    saveTokens(allTokens);

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

app.post('/oauth/token', (req, res) => {
  const { email, tokens } = req.body;
  if (!email || !tokens) return res.status(400).json({ error: 'Missing email or tokens' });

  const allTokens = loadTokens();
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
  saveTokens(allTokens);
  console.log(`💾 Token updated for ${email} (has refresh: ${!!merged.refresh_token})`);
  res.json({ ok: true });
});

// ── Schedule / update an email ────────────────────────────────────────────────

app.post('/schedule', async (req, res) => {
  try {
    const incoming = req.body;
    if (!incoming || !incoming.id) return res.status(400).json({ error: 'Invalid email data' });

    if (!incoming.userEmail) {
      const allTokens = loadTokens();
      const users = Object.keys(allTokens);
      if (users.length > 0) {
        incoming.userEmail = users[0];
      } else {
        return res.status(400).json({ error: 'No authenticated user — cannot schedule email' });
      }
    }

    // If this schedule request came from the Chrome extension, treat Chrome as online immediately
    // so the cron job doesn't race and double-send before the first heartbeat tick.
    if (incoming.fromChrome && incoming.userEmail) {
      chromeHeartbeat.set(incoming.userEmail, Date.now());
    }

    // ✅ FIX: Sanitize recipient fields — guard against [object Object] stored in old records
    incoming.to  = sanitizeRecipient(incoming.to);
    incoming.cc  = sanitizeRecipient(incoming.cc);
    incoming.bcc = sanitizeRecipient(incoming.bcc);

    const existing = await Email.findOne({ id: incoming.id });

    if (existing) {
            await Email.findOneAndUpdate(
        { id: incoming.id },
        { ...incoming,
          sentCount: incoming.sentCount ?? existing.sentCount ?? 0,
          lastSent: incoming.lastSent ?? existing.lastSent ?? null,
        },
        { returnDocument: 'after' }
      );
      console.log(`📝 Updated: "${incoming.subject}" | attachments: ${(incoming.attachments || []).length}`);
    } else {
      await Email.create(incoming);
      console.log(`📅 New: "${incoming.subject}" → ${incoming.nextSendTime} | attachments: ${(incoming.attachments || []).length}`);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Schedule error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Get emails for a user ─────────────────────────────────────────────────────

app.get('/emails', async (req, res) => {
  try {
    const { userEmail } = req.query;
    const filter = userEmail ? { userEmail } : {};
    const emails = await Email.find(filter);
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
    const updated = await Email.findOneAndUpdate(
      { id: req.params.id },
      req.body,
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true, email: updated });
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
    const next = new Date(now);
    next.setMonth(next.getMonth() + r.months);
    next.setHours(h, m, 0, 0);
    return next.toISOString();
  }

  const next = new Date(now);
  next.setDate(next.getDate() + 1);
  next.setHours(h, m, 0, 0);
  return next.toISOString();
}

// ── Send email via Gmail API ──────────────────────────────────────────────────

async function sendEmailViaGmail(email) {
  // ✅ FIX: Sanitize recipient at send time to catch any corrupted DB records
  const toStr = sanitizeRecipient(email.to);
  if (!toStr || toStr === '[object Object]') {
    throw new Error('Recipient address required');
  }

  const allTokens = loadTokens();
  const userEmail = email.userEmail || Object.keys(allTokens)[0];
  if (!userEmail) throw new Error('No authenticated user found');

  const tokens = allTokens[userEmail];
  if (!tokens) throw new Error(`No tokens for ${userEmail}`);

  if (!tokens.refresh_token) {
    console.warn(`⚠️  No refresh_token for ${userEmail} — will fail if access_token is expired`);
  }

  const oauth2 = makeOAuthClient();
  oauth2.setCredentials(tokens);

  oauth2.on('tokens', (newTokens) => {
    if (newTokens.refresh_token) tokens.refresh_token = newTokens.refresh_token;
    tokens.access_token = newTokens.access_token;
    tokens.expiry_date  = newTokens.expiry_date;
    allTokens[userEmail] = tokens;
    saveTokens(allTokens);
    console.log(`🔄 Token refreshed for ${userEmail}`);
  });

  const gmail = google.gmail({ version: 'v1', auth: oauth2 });

  const boundary  = `boundary_${Date.now()}`;
  const toHeader  = toStr;
  const ccHeader  = sanitizeRecipient(email.cc);
  const bccHeader = sanitizeRecipient(email.bcc);

  const subjectB64 = Buffer.from(email.subject || '(no subject)', 'utf8').toString('base64');
  const bodyHtml   = email.body || '';
  const bodyB64    = Buffer.from(bodyHtml, 'utf8').toString('base64');

  const attachments = Array.isArray(email.attachments)
    ? email.attachments.filter(a => a && a.dataBase64)
    : [];

  let mime;

  if (attachments.length === 0) {
    mime = [
      `To: ${toHeader}`,
      ccHeader  ? `Cc: ${ccHeader}`   : null,
      bccHeader ? `Bcc: ${bccHeader}` : null,
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      bodyB64,
    ].filter(Boolean).join('\r\n');
  } else {
    const parts = [
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      bodyB64,
    ];

    for (const att of attachments) {
      const attName = (att.name || 'attachment').replace(/[\r\n"]/g, '');
      const attType = att.type || 'application/octet-stream';
      let b64 = (att.dataBase64 || '').replace(/\r?\n/g, '');
      if (b64.includes('base64,')) b64 = b64.split('base64,').pop() || '';
      if (!b64) continue;

      parts.push(`--${boundary}`);
      parts.push(`Content-Type: ${attType}; name="${attName}"`);
      parts.push(`Content-Disposition: attachment; filename="${attName}"`);
      parts.push('Content-Transfer-Encoding: base64');
      parts.push('');
      parts.push(b64);
    }
    parts.push(`--${boundary}--`);

    mime = [
      `To: ${toHeader}`,
      ccHeader  ? `Cc: ${ccHeader}`   : null,
      bccHeader ? `Bcc: ${bccHeader}` : null,
      `Subject: =?UTF-8?B?${subjectB64}?=`,
      'MIME-Version: 1.0',
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      ...parts,
    ].filter(Boolean).join('\r\n');
  }

  const raw = Buffer.from(mime, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
  console.log(`✅ Sent: "${email.subject}" → ${toHeader} | attachments: ${attachments.length}`);
}

// ── Main scheduler — runs every minute ───────────────────────────────────────

cron.schedule('* * * * *', async () => {
  try {
    const now    = new Date();
    const emails = await Email.find({ active: true });

    for (const email of emails) {
      const hb = chromeHeartbeat.get(email.userEmail);
      if (hb && (Date.now() - hb) < HEARTBEAT_TTL_MS) {
        continue;
      }
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
        await sendEmailViaGmail(email);

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
        },
        { returnDocument: 'after' }
      );

      } catch (err) {
        console.error(`❌ Failed to send "${email.subject}":`, err.message);

        // ✅ FIX: Only permanently deactivate on auth errors.
        // For network/temporary errors, retry in 5 minutes instead of killing the schedule.
        const isAuthError = err.message.includes('401') ||
                            err.message.includes('No tokens') ||
                            err.message.includes('No refresh') ||
                            err.message.includes('No authenticated');

        if (isAuthError) {
          console.log(`🔒 Auth error — deactivating "${email.subject}"`);
          await Email.findOneAndUpdate({ id: email.id }, { active: false });
        } else {
          const retryAt = new Date(Date.now() + 5 * 60_000).toISOString();
          console.log(`🔁 Temporary error — will retry "${email.subject}" at ${retryAt}`);
          await Email.findOneAndUpdate({ id: email.id }, { nextSendTime: retryAt });
        }
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
