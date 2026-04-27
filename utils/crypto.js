const crypto = require('crypto');

const FIELDS_TO_ENCRYPT = [
  'to', 'cc', 'bcc', 'subject', 'body',
  'attachments', 'userEmail',
];

const AUTH_FIELDS_TO_ENCRYPT = ['value'];

let _keyCache = null;

function getEncryptionKey() {
  if (_keyCache) return _keyCache;

  const keyHex = (process.env.ENCRYPTION_KEY || '').toString().trim();
  if (!keyHex) {
    throw new Error(
      'ENCRYPTION_KEY is missing. Set ENCRYPTION_KEY to a 64-character hex string (32 random bytes). ' +
      'If this key is lost, all encrypted data in MongoDB is unrecoverable.'
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    throw new Error('ENCRYPTION_KEY is invalid. Expected a 64-character hex string.');
  }

  _keyCache = Buffer.from(keyHex, 'hex');
  if (_keyCache.length !== 32) {
    throw new Error('ENCRYPTION_KEY is invalid. Expected 32 bytes after hex decoding.');
  }
  return _keyCache;
}

function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === '') return '';
  if (typeof plaintext !== 'string') {
    throw new Error('encrypt() expects a string. JSON.stringify objects/arrays before encrypting.');
  }
  // Idempotency: if already encrypted, keep as-is.
  if (plaintext.startsWith('enc:')) return plaintext;

  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `enc:${iv.toString('hex')}:${authTag.toString('hex')}:${ciphertext.toString('hex')}`;
}

function decrypt(ciphertext) {
  if (ciphertext === null || ciphertext === undefined || ciphertext === '') return '';
  // Backward compatibility: legacy plaintext or non-string values.
  if (typeof ciphertext !== 'string') return ciphertext;
  if (!ciphertext.startsWith('enc:')) return ciphertext;

  const parts = ciphertext.split(':');
  if (parts.length !== 4) throw new Error('Encrypted value has invalid format (expected enc:<iv>:<tag>:<ciphertext>).');

  const ivHex = parts[1] || '';
  const tagHex = parts[2] || '';
  const dataHex = parts[3] || '';

  if (!/^[0-9a-fA-F]{24}$/.test(ivHex)) throw new Error('Encrypted value has invalid IV (expected 12-byte hex).');
  if (!/^[0-9a-fA-F]{32}$/.test(tagHex)) throw new Error('Encrypted value has invalid authTag (expected 16-byte hex).');
  if (!/^[0-9a-fA-F]+$/.test(dataHex)) throw new Error('Encrypted value has invalid ciphertext (expected hex).');

  const key = getEncryptionKey();
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(tagHex, 'hex');
  const data = Buffer.from(dataHex, 'hex');

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    return plaintext;
  } catch (err) {
    throw new Error(`Decryption failed: ${err?.message || String(err)}`);
  }
}

function encryptObject(obj, fields) {
  const out = { ...(obj && typeof obj === 'object' ? obj : {}) };
  for (const field of (fields || [])) {
    if (!(field in out)) continue;
    const val = out[field];
    if (val === null || val === undefined) continue;
    out[field] = encrypt(typeof val === 'string' ? val : String(val));
  }
  return out;
}

function decryptObject(obj, fields) {
  const out = { ...(obj && typeof obj === 'object' ? obj : {}) };
  for (const field of (fields || [])) {
    if (!(field in out)) continue;
    const val = out[field];
    if (val === null || val === undefined) continue;
    out[field] = decrypt(val);
  }
  return out;
}

module.exports = {
  getEncryptionKey,
  encrypt,
  decrypt,
  encryptObject,
  decryptObject,
  FIELDS_TO_ENCRYPT,
  AUTH_FIELDS_TO_ENCRYPT,
};

