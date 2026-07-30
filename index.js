// ============================================================================
// Invigil — access-code + register verification backend
//
// This is the small server referenced throughout the README. It exists so
// two pieces of sensitive data never reach a student's browser:
//   1. The university access code (POST /verify-code)
//   2. The class register — names + student numbers (POST /verify-student)
//
// Both endpoints are deliberately "yes/no" — the response never echoes back
// which part of the input was wrong, so a student's browser (or a script
// probing the endpoint) can't use error messages to enumerate valid codes,
// names, or student numbers.
//
// Requires two things beyond the access-code setup already described in the
// README: a Firebase service-account key (so this server can read the
// register straight out of Firestore using the Admin SDK, bypassing
// firestore.rules — that's fine here because the key is never exposed to a
// browser, only to this server) and the FIREBASE_SERVICE_ACCOUNT_BASE64 env
// var described below.
// ============================================================================

const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
app.use(express.json({ limit: '10kb' })); // requests here are tiny; reject anything else outright

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const UNIVERSITY_CODE = process.env.UNIVERSITY_CODE || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Firebase Admin init
//
// FIREBASE_SERVICE_ACCOUNT_BASE64 = the full service-account JSON (Project
// settings → Service accounts → Generate new private key), base64-encoded
// onto ONE line — that avoids Render's env-var box mangling the JSON's
// newlines/quotes. See README "5b" for the exact command to produce this.
// ---------------------------------------------------------------------------
let db = null;
if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
  try {
    const json = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
    const serviceAccount = JSON.parse(json);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    db = admin.firestore();
  } catch (err) {
    console.error('Could not initialize Firebase Admin — check FIREBASE_SERVICE_ACCOUNT_BASE64:', err.message);
  }
} else {
  console.warn('FIREBASE_SERVICE_ACCOUNT_BASE64 not set — /verify-student will refuse all requests until it is.');
}

// ---------------------------------------------------------------------------
// CORS — only your deployed Hosting origins may call this server at all.
// ---------------------------------------------------------------------------
app.use(cors({
  origin(origin, callback) {
    // Allow tools with no Origin header (curl, health checks) but not browsers
    // from unlisted origins.
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed'));
  }
}));

// ---------------------------------------------------------------------------
// Minimal in-memory rate limiter, per IP, per route. Resets if the free-tier
// instance restarts or sleeps — that's an accepted tradeoff (see README):
// this is a deterrent against casual guessing, not a hardened defense
// against a patient, distributed attacker.
// ---------------------------------------------------------------------------
const hits = new Map(); // key -> [timestamps]
function rateLimited(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  arr.push(now);
  hits.set(key, arr);
  return arr.length > max;
}
// Periodic cleanup so `hits` doesn't grow forever on a long-lived instance.
setInterval(() => {
  const now = Date.now();
  for (const [key, arr] of hits) {
    const kept = arr.filter(t => now - t < 15 * 60 * 1000);
    if (kept.length) hits.set(key, kept); else hits.delete(key);
  }
}, 5 * 60 * 1000).unref();

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

// ---------------------------------------------------------------------------
// Health check — also what an uptime pinger (e.g. UptimeRobot) should hit
// every ~10 minutes to keep the free instance from sleeping.
// ---------------------------------------------------------------------------
app.get('/', (req, res) => res.json({ ok: true, service: 'invigil-backend' }));

// ---------------------------------------------------------------------------
// POST /verify-code   { code: string }  ->  { ok: boolean }
// ---------------------------------------------------------------------------
app.post('/verify-code', (req, res) => {
  const ip = clientIp(req);
  if (rateLimited(`code:${ip}`, 20, 60 * 1000)) {
    return res.status(429).json({ ok: false, error: 'Too many attempts — wait a minute and try again.' });
  }
  if (!UNIVERSITY_CODE) {
    return res.status(500).json({ ok: false, error: 'Server not configured (UNIVERSITY_CODE missing).' });
  }
  const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  if (!code || code.length > 100) return res.json({ ok: false });

  // Constant-time-ish comparison — not critical here (the code is long and
  // rate-limited), but cheap to do properly.
  const ok = code.length === UNIVERSITY_CODE.length && timingSafeEqual(code, UNIVERSITY_CODE);
  res.json({ ok });
});

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// POST /verify-student   { testId, name, studentId }  ->  { ok: boolean }
//
// Looks up tests/{testId}/private/register in Firestore (via Admin SDK, so
// firestore.rules — which keep this doc lecturer-only — don't apply here)
// and checks whether the given name + student number match an entry.
//
// Fails CLOSED: if the register can't be read for any reason (missing,
// misconfigured server, Firestore error), the student is denied rather than
// let through — a real mismatch and a broken deploy should look the same
// to a student (contact your lecturer), and a lecturer diagnosing it can
// check the Render logs.
// ---------------------------------------------------------------------------
const registerCache = new Map(); // testId -> { entries, expiresAt }
const REGISTER_CACHE_MS = 60 * 1000;

async function getRegisterEntries(testId) {
  const cached = registerCache.get(testId);
  if (cached && cached.expiresAt > Date.now()) return cached.entries;

  const snap = await db.collection('tests').doc(testId)
    .collection('private').doc('register').get();
  const entries = snap.exists && Array.isArray(snap.data().entries) ? snap.data().entries : [];
  registerCache.set(testId, { entries, expiresAt: Date.now() + REGISTER_CACHE_MS });
  return entries;
}

function normName(s) {
  return (s || '').toString().trim().toLowerCase().replace(/\s+/g, ' ');
}
function normId(s) {
  return (s || '').toString().trim().toUpperCase().replace(/\s+/g, '');
}

app.post('/verify-student', async (req, res) => {
  const ip = clientIp(req);
  // Slightly tighter limit than /verify-code — this endpoint doubles as a
  // student-number oracle if hammered, so keep guesses expensive.
  if (rateLimited(`student:${ip}`, 15, 60 * 1000)) {
    return res.status(429).json({ ok: false, error: 'Too many attempts — wait a minute and try again.' });
  }
  if (!db) {
    return res.status(500).json({ ok: false, error: 'Server not configured (FIREBASE_SERVICE_ACCOUNT_BASE64 missing).' });
  }

  const testId = typeof req.body?.testId === 'string' ? req.body.testId.trim() : '';
  const name = typeof req.body?.name === 'string' ? req.body.name : '';
  const studentId = typeof req.body?.studentId === 'string' ? req.body.studentId : '';
  if (!testId || testId.length > 100 || !name || name.length > 200 || !studentId || studentId.length > 100) {
    return res.json({ ok: false });
  }

  try {
    const entries = await getRegisterEntries(testId);
    const wantName = normName(name);
    const wantId = normId(studentId);
    const match = entries.some(e => normId(e.studentId) === wantId && normName(e.name) === wantName);
    res.json({ ok: match });
  } catch (err) {
    console.error('verify-student error:', err.message);
    res.status(500).json({ ok: false, error: 'Could not check the register right now — try again shortly.' });
  }
});

app.listen(PORT, () => console.log(`Invigil backend listening on :${PORT}`));
