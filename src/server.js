const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const { initFirebase } = require('./firebase');

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '12kb', strict: true }));

const generalLimiter = rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: 'draft-7', legacyHeaders: false });
const verifyLimiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
app.use(generalLimiter);

const db = initFirebase();
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || '';
const DEFAULT_DEVICE_LIMIT = Math.max(1, Math.min(20, Number(process.env.LICENSE_DEVICE_LIMIT_DEFAULT || 3)));

const keySchema = z.object({
  key: z.string().trim().min(8).max(128).regex(/^[A-Za-z0-9_-]+$/),
  expiresAt: z.number().int().positive().nullable().optional(),
  deviceLimit: z.number().int().min(1).max(20).optional(),
  note: z.string().trim().max(120).optional()
});
const verifySchema = z.object({
  key: z.string().trim().min(8).max(128).regex(/^[A-Za-z0-9_-]+$/),
  deviceId: z.string().trim().min(8).max(200).regex(/^[A-Za-z0-9._:-]+$/)
});

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function requireAdmin(req, res, next) {
  const supplied = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!ADMIN_API_KEY || !safeEqual(supplied, ADMIN_API_KEY)) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  next();
}
function normalizeKey(key) { return key.trim().toUpperCase(); }
function hashDevice(deviceId) {
  // Avoid storing raw device identifiers in the database.
  return crypto.createHash('sha256').update(deviceId).digest('hex');
}
function nowMs() { return Date.now(); }

app.get('/health', (_req, res) => res.json({ ok: true, service: 'aadit-mods-license-api' }));

app.post('/v1/licenses/verify', verifyLimiter, async (req, res) => {
  const parsed = verifySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'invalid_request' });

  const key = normalizeKey(parsed.data.key);
  const deviceHash = hashDevice(parsed.data.deviceId);
  try {
    const ref = db.ref(`licenses/${key}`);
    const snap = await ref.get();
    if (!snap.exists()) return res.status(403).json({ ok: false, error: 'invalid_or_inactive_key' });
    const license = snap.val();

    if (license.status !== 'active') return res.status(403).json({ ok: false, error: 'invalid_or_inactive_key' });
    if (license.expiresAt !== null && license.expiresAt !== undefined && Number(license.expiresAt) <= nowMs()) {
      return res.status(403).json({ ok: false, error: 'expired_key' });
    }

    const devicesRef = ref.child('devices');
    let deviceResult = { allowed: false };
    await devicesRef.transaction((current) => {
      const devices = current && typeof current === 'object' ? current : {};
      if (devices[deviceHash]) {
        deviceResult = { allowed: true, existing: true };
        return devices;
      }
      const count = Object.keys(devices).length;
      const limit = Math.max(1, Math.min(20, Number(license.deviceLimit || DEFAULT_DEVICE_LIMIT)));
      if (count >= limit) {
        deviceResult = { allowed: false, limit };
        return; // abort transaction
      }
      devices[deviceHash] = { firstSeenAt: nowMs(), lastSeenAt: nowMs() };
      deviceResult = { allowed: true, existing: false };
      return devices;
    });

    if (!deviceResult.allowed) {
      return res.status(403).json({ ok: false, error: 'device_limit_reached', deviceLimit: deviceResult.limit });
    }
    // Update lastSeenAt for known device. Best-effort, not required for authorization.
    await devicesRef.child(deviceHash).update({ lastSeenAt: nowMs() }).catch(() => {});
    return res.json({
      ok: true,
      status: 'active',
      expiresAt: license.expiresAt ?? null,
      deviceLimit: Math.max(1, Math.min(20, Number(license.deviceLimit || DEFAULT_DEVICE_LIMIT)))
    });
  } catch (err) {
    console.error('verify failed:', err.message);
    return res.status(503).json({ ok: false, error: 'verification_unavailable' });
  }
});

app.post('/v1/admin/licenses', requireAdmin, async (req, res) => {
  const parsed = keySchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ ok: false, error: 'invalid_request', details: parsed.error.issues.map(i => ({ path: i.path, message: i.message })) });
  const key = normalizeKey(parsed.data.key);
  const expiresAt = parsed.data.expiresAt === undefined ? null : parsed.data.expiresAt;
  if (expiresAt !== null && expiresAt <= nowMs()) return res.status(400).json({ ok: false, error: 'expiry_must_be_future' });
  const payload = {
    status: 'active',
    createdAt: nowMs(),
    expiresAt,
    deviceLimit: parsed.data.deviceLimit || DEFAULT_DEVICE_LIMIT,
    note: parsed.data.note || '',
    devices: {}
  };
  try {
    const ref = db.ref(`licenses/${key}`);
    const result = await ref.transaction(current => current === null ? payload : undefined);
    if (!result.committed) return res.status(409).json({ ok: false, error: 'key_already_exists' });
    res.status(201).json({ ok: true, key, status: payload.status, expiresAt, deviceLimit: payload.deviceLimit });
  } catch (err) {
    console.error('create license failed:', err.message);
    res.status(503).json({ ok: false, error: 'database_unavailable' });
  }
});

app.patch('/v1/admin/licenses/:key/status', requireAdmin, async (req, res) => {
  const key = normalizeKey(String(req.params.key || ''));
  const parsed = z.object({ status: z.enum(['active', 'disabled']) }).safeParse(req.body);
  if (!/^[A-Z0-9_-]{8,128}$/.test(key) || !parsed.success) return res.status(400).json({ ok: false, error: 'invalid_request' });
  try {
    const ref = db.ref(`licenses/${key}`);
    const snap = await ref.get();
    if (!snap.exists()) return res.status(404).json({ ok: false, error: 'license_not_found' });
    await ref.update({ status: parsed.data.status, updatedAt: nowMs() });
    return res.json({ ok: true, key, status: parsed.data.status });
  } catch (err) {
    console.error('update status failed:', err.message);
    return res.status(503).json({ ok: false, error: 'database_unavailable' });
  }
});

app.patch('/v1/admin/licenses/:key/expiry', requireAdmin, async (req, res) => {
  const key = normalizeKey(String(req.params.key || ''));
  const parsed = z.object({ expiresAt: z.number().int().positive().nullable() }).safeParse(req.body);
  if (!/^[A-Z0-9_-]{8,128}$/.test(key) || !parsed.success) return res.status(400).json({ ok: false, error: 'invalid_request' });
  if (parsed.data.expiresAt !== null && parsed.data.expiresAt <= nowMs()) return res.status(400).json({ ok: false, error: 'expiry_must_be_future' });
  try {
    const ref = db.ref(`licenses/${key}`);
    const snap = await ref.get();
    if (!snap.exists()) return res.status(404).json({ ok: false, error: 'license_not_found' });
    await ref.update({ expiresAt: parsed.data.expiresAt, updatedAt: nowMs() });
    return res.json({ ok: true, key, expiresAt: parsed.data.expiresAt });
  } catch (err) {
    console.error('update expiry failed:', err.message);
    return res.status(503).json({ ok: false, error: 'database_unavailable' });
  }
});

app.delete('/v1/admin/licenses/:key/devices/:deviceHash', requireAdmin, async (req, res) => {
  const key = normalizeKey(String(req.params.key || ''));
  const deviceHash = String(req.params.deviceHash || '');
  if (!/^[A-Z0-9_-]{8,128}$/.test(key) || !/^[a-f0-9]{64}$/.test(deviceHash)) return res.status(400).json({ ok: false, error: 'invalid_request' });
  try {
    const deviceRef = db.ref(`licenses/${key}/devices/${deviceHash}`);
    const snap = await deviceRef.get();
    if (!snap.exists()) return res.status(404).json({ ok: false, error: 'device_not_found' });
    await deviceRef.remove();
    return res.json({ ok: true, removed: true });
  } catch (err) {
    console.error('remove device failed:', err.message);
    return res.status(503).json({ ok: false, error: 'database_unavailable' });
  }
});

app.use((err, _req, res, _next) => {
  console.error('request error:', err.message);
  res.status(400).json({ ok: false, error: 'bad_request' });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => console.log(`AADIT MODS License API listening on ${port}`));
