// ============================================================================
// Invigil — backend: access-code + register verification, and LTI 1.3
//
// This is the small server referenced throughout the README. It exists so
// sensitive data never reaches a student's browser, and so Moodle-facing
// protocol work that needs a private signing key has somewhere to live:
//   1. The university access code (POST /verify-code)
//   2. The class register — names + student numbers (POST /verify-student)
//   3. LTI 1.3 Advantage — SSO launch, Deep Linking, and AGS grade passback
//      (mounted at /lti/*, implemented in ./lti.js)
//
// The verify-* endpoints are deliberately "yes/no" — the response never
// echoes back which part of the input was wrong, so a student's browser (or
// a script probing the endpoint) can't use error messages to enumerate valid
// codes, names, or student numbers.
//
// Requires a Firebase service-account key (so this server can read the
// register straight out of Firestore using the Admin SDK, bypassing
// firestore.rules — that's fine here because the key is never exposed to a
// browser, only to this server) via FIREBASE_SERVICE_ACCOUNT_BASE64, plus —
// for the LTI routes — LTI_PRIVATE_KEY_BASE64, LTI_KID, PUBLIC_APP_URL, and
// PUBLIC_BACKEND_URL. See README "LTI / Moodle setup" for all of these.
// ============================================================================

const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const { createLtiRouter, pushGradeToLti } = require('./lti');

const app = express();
app.use(express.json({ limit: '10kb' })); // requests here are tiny; reject anything else outright
// LTI launches and Deep Linking responses arrive as browser form_posts
// (application/x-www-form-urlencoded), not JSON.
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const UNIVERSITY_CODE = process.env.UNIVERSITY_CODE || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const PORT = process.env.PORT || 3000;
// This service's own public URL (Render gives you this after first deploy,
// e.g. https://invigil-backend.onrender.com) — needed to build the LTI
// redirect_uri and the JWKS URL Moodle admins are given during registration.
const PUBLIC_BACKEND_URL = (process.env.PUBLIC_BACKEND_URL || '').replace(/\/$/, '');
// Your Firebase Hosting URL, e.g. https://invigil-prime.web.app — where LTI
// launches redirect the browser back into the app.
const PUBLIC_APP_URL = (process.env.PUBLIC_APP_URL || '').replace(/\/$/, '');

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
// CORS — only your deployed Hosting origins may call routes this middleware
// is applied to. Deliberately NOT applied globally: the LTI protocol routes
// (/lti/login, /lti/launch, /lti/jwks.json) are reached by real cross-origin
// browser navigations and form_posts FROM Moodle, which the CORS middleware
// would otherwise reject outright before the route ever runs. Their security
// comes from JWT/state verification inside lti.js, not from an Origin check.
// ---------------------------------------------------------------------------
const restrictedCors = cors({
  origin(origin, callback) {
    // Allow tools with no Origin header (curl, health checks) but not browsers
    // from unlisted origins.
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed'));
  }
});

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
app.post('/verify-code', restrictedCors, (req, res) => {
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

app.post('/verify-student', restrictedCors, async (req, res) => {
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

// ---------------------------------------------------------------------------
// LTI 1.3 Advantage — SSO launch, Deep Linking, and (below) AGS grade
// passback. See lti.js for the full protocol implementation and the
// Firestore schema it owns. /lti/login, /lti/launch, and /lti/jwks.json are
// deliberately outside restrictedCors — see the CORS comment above.
// ---------------------------------------------------------------------------
if (db && PUBLIC_APP_URL && PUBLIC_BACKEND_URL) {
  const ltiRouter = createLtiRouter(db, admin, { publicAppUrl: PUBLIC_APP_URL, publicBackendUrl: PUBLIC_BACKEND_URL });
  // /session and /deep-link/complete are called via fetch from our own
  // frontend, so — unlike login/launch/jwks — they do go through the
  // Origin allow-list.
  app.use('/lti/session', restrictedCors);
  app.use('/lti/deep-link/complete', restrictedCors);
  app.use('/lti', ltiRouter);
} else {
  console.warn('LTI routes disabled — PUBLIC_APP_URL, PUBLIC_BACKEND_URL, or Firebase Admin isn\'t configured yet.');
  app.use('/lti', (req, res) => res.status(503).json({ ok: false, error: 'LTI isn\'t configured on this server yet.' }));
}

// ---------------------------------------------------------------------------
// POST /lti/push-grade   { testId, submissionId, scoreGiven, scoreMaximum }
// (Authorization: Bearer <lecturer Firebase ID token>) -> { ok, error? }
//
// Pushes one submission's final mark into the Moodle gradebook column that
// was auto-provisioned when the lecturer linked this test via Deep Linking.
// The score itself is computed client-side (the app already has the marking
// key and grading logic loaded for the Results view) and passed in here —
// this route's job is just the authenticated, server-signed handoff to
// Moodle, not re-deriving the grade.
// ---------------------------------------------------------------------------
app.post('/lti/push-grade', restrictedCors, async (req, res) => {
  if (!db) return res.status(500).json({ ok: false, error: 'Server not configured.' });

  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!idToken) return res.status(401).json({ ok: false, error: 'Not signed in.' });

  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(idToken);
  } catch (err) {
    return res.status(401).json({ ok: false, error: 'Session expired — sign in again.' });
  }

  const { testId, submissionId, scoreGiven, scoreMaximum } = req.body || {};
  if (!testId || !submissionId || typeof scoreGiven !== 'number' || typeof scoreMaximum !== 'number') {
    return res.status(400).json({ ok: false, error: 'Missing or malformed fields.' });
  }

  const testSnap = await db.collection('tests').doc(testId).get();
  if (!testSnap.exists) return res.status(404).json({ ok: false, error: 'Test not found.' });
  const courseSnap = await db.collection('courses').doc(testSnap.data().courseId).get();
  if (!courseSnap.exists || courseSnap.data().createdBy !== decoded.uid) {
    return res.status(403).json({ ok: false, error: 'You don\'t own this test.' });
  }

  const result = await pushGradeToLti(db, { testId, submissionId, scoreGiven, scoreMaximum });
  res.status(result.ok ? 200 : 502).json(result);
});

app.listen(PORT, () => console.log(`Invigil backend listening on :${PORT}`));
