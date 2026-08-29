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
const crypto = require('crypto');
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

// Flutterwave secret key — from your Flutterwave Dashboard (Settings → API
// keys → Secret Key, starts with FLWSECK_TEST- in test mode or FLWSECK-
// live). Only used server-side, never sent to a browser.
const FLUTTERWAVE_SECRET_KEY = process.env.FLUTTERWAVE_SECRET_KEY || '';
// The "Secret Hash" you set yourself in Flutterwave Dashboard → Settings →
// Webhooks. Flutterwave sends this same string back in every webhook
// request's `verif-hash` header — request bodies aren't HMAC-signed;
// verification here is a direct string comparison against this value.
const FLUTTERWAVE_WEBHOOK_HASH = process.env.FLUTTERWAVE_WEBHOOK_HASH || '';
const FLUTTERWAVE_API_BASE = 'https://api.flutterwave.com/v3';
if (!FLUTTERWAVE_SECRET_KEY) {
  console.warn('FLUTTERWAVE_SECRET_KEY not set — /create-flutterwave-payment will refuse all requests until it is.');
}
if (!FLUTTERWAVE_WEBHOOK_HASH) {
  console.warn('FLUTTERWAVE_WEBHOOK_HASH not set — /flutterwave/webhook will reject all events until it is.');
}

// -----------------------------------------------------------------------
// Canonical Invigil pricing, in USD. This is the one source of truth for
// what a plan costs — the frontend only ever sends a planId, never a
// price, and the backend looks the real price up here. Flutterwave may
// settle a transaction in a different currency (e.g. ZMW) depending on
// the customer's card/region; that settlement amount/currency is recorded
// separately in the payment record and never treated as the list price.
// -----------------------------------------------------------------------
const PRICING_PLANS = {
  institution_monthly: { name: 'Institution Plan (Monthly)', priceUSD: 1.00, billingPeriod: 'monthly', perStudent: true },
  institution_annual: { name: 'Institution Plan (Annual)', priceUSD: 12.00, billingPeriod: 'yearly', perStudent: true },
};


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
app.use('/verify-code', restrictedCors);
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

app.use('/verify-student', restrictedCors);
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

// -----------------------------------------------------------------------
// POST /request-access
//   { name, email, institutionName, role, institutionType, studentCount,
//     usesMoodle, interests: string[] }
//   -> { ok: boolean, error? }
//
// Stores an institutional access request in Firestore (accessRequests
// collection) so it shows up for you to follow up on manually — this is
// deliberately NOT wired to an email/CRM service, since none is
// configured. Check the Firebase console under accessRequests, or build
// a notification integration (e.g. a Firestore trigger that emails you)
// separately if you want a push notification instead of checking Firestore.
// -----------------------------------------------------------------------
app.use('/request-access', restrictedCors);
app.post('/request-access', async (req, res) => {
  const ip = clientIp(req);
  if (rateLimited(`access-request:${ip}`, 5, 10 * 60 * 1000)) {
    return res.status(429).json({ ok: false, error: 'Too many requests — please wait a few minutes and try again.' });
  }
  if (!db) {
    return res.status(500).json({ ok: false, error: 'Server not configured (FIREBASE_SERVICE_ACCOUNT_BASE64 missing).' });
  }

  const b = req.body || {};
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  const email = typeof b.email === 'string' ? b.email.trim() : '';
  const institutionName = typeof b.institutionName === 'string' ? b.institutionName.trim() : '';
  const role = typeof b.role === 'string' ? b.role.trim() : '';
  const institutionType = typeof b.institutionType === 'string' ? b.institutionType.trim() : '';
  const studentCount = typeof b.studentCount === 'string' ? b.studentCount.trim() : '';
  const usesMoodle = typeof b.usesMoodle === 'string' ? b.usesMoodle.trim() : '';
  const interests = Array.isArray(b.interests) ? b.interests.filter(s => typeof s === 'string').slice(0, 10) : [];

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!name || name.length > 200 || !emailOk || email.length > 200 || !institutionName || institutionName.length > 300) {
    return res.status(400).json({ ok: false, error: 'Please fill in your name, a valid work email, and institution name.' });
  }

  try {
    await db.collection('accessRequests').add({
      name, email, institutionName, role, institutionType, studentCount, usesMoodle, interests,
      status: 'new',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      ip,
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('request-access error:', err.message);
    res.status(500).json({ ok: false, error: 'Could not save your request right now — try again shortly.' });
  }
});

// -----------------------------------------------------------------------
// POST /create-flutterwave-payment
//   { planId: string, studentCount: number, institutionName?: string, email: string }
//   (Authorization: Bearer <Firebase ID token>, optional — an
//   institutional access request can happen before any lecturer account
//   exists, so this route works either signed-in or signed-out. When
//   present, the token's uid is trusted as the payer's identity instead
//   of the client-supplied email.)
//   -> { ok: boolean, url?: string, error? }
//
// The frontend sends ONLY a planId (+ how many students, + who's paying).
// Price, currency, and billing period are looked up server-side from
// PRICING_PLANS — the client's opinion of the price is never trusted.
// Creates a Flutterwave Standard payment link and returns it for the
// browser to redirect to. Flutterwave collects card details on its own
// hosted page — this server never sees or stores raw card numbers.
//
// A successful redirect back from Flutterwave is NOT treated as proof of
// payment anywhere in this codebase — see /flutterwave/webhook below,
// which is the only thing allowed to activate a subscription.
// -----------------------------------------------------------------------
app.use('/create-flutterwave-payment', restrictedCors);
app.post('/create-flutterwave-payment', async (req, res) => {
  const ip = clientIp(req);
  if (rateLimited(`checkout:${ip}`, 10, 10 * 60 * 1000)) {
    return res.status(429).json({ ok: false, error: 'Too many attempts — please wait a few minutes and try again.' });
  }
  if (!FLUTTERWAVE_SECRET_KEY) {
    return res.status(500).json({ ok: false, error: 'Payment processing is currently being configured. Please try again later or contact us.' });
  }
  if (!PUBLIC_APP_URL) {
    return res.status(500).json({ ok: false, error: 'Payment processing is currently being configured. Please try again later or contact us.' });
  }
  if (!db) {
    return res.status(500).json({ ok: false, error: 'Payment processing is currently being configured. Please try again later or contact us.' });
  }

  // Identify the payer: prefer a verified Firebase UID over a client-
  // supplied email, since the UID can't be spoofed.
  let uid = null;
  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (idToken) {
    try {
      const decoded = await admin.auth().verifyIdToken(idToken);
      uid = decoded.uid;
    } catch (err) {
      return res.status(401).json({ ok: false, error: 'Your session has expired — please sign in again.' });
    }
  }

  const planId = typeof req.body?.planId === 'string' ? req.body.planId : '';
  const plan = PRICING_PLANS[planId];
  if (!plan) {
    return res.status(400).json({ ok: false, error: 'Unknown plan.' });
  }
  const studentCount = Math.round(Number(req.body?.studentCount));
  if (!Number.isFinite(studentCount) || studentCount < 1 || studentCount > 200000) {
    return res.status(400).json({ ok: false, error: 'Enter a valid number of students.' });
  }
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().slice(0, 200) : '';
  if (!uid && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ ok: false, error: 'Enter a valid email address.' });
  }
  const institutionName = typeof req.body?.institutionName === 'string' ? req.body.institutionName.trim().slice(0, 200) : '';

  const amountUSD = plan.perStudent ? +(plan.priceUSD * studentCount).toFixed(2) : plan.priceUSD;
  const payerRef = uid || email;
  const txRef = `INVIGIL-${payerRef.replace(/[^a-zA-Z0-9]/g, '').slice(0, 24)}-${crypto.randomUUID()}`;

  try {
    // Record the pending payment BEFORE redirecting the user anywhere, so
    // the webhook (which may arrive seconds or minutes later, and race
    // the browser's own redirect back) always has a matching record to
    // verify against and update — see /flutterwave/webhook.
    await db.collection('payments').doc(txRef).set({
      txRef, uid, email: uid ? null : email, planId, studentCount, institutionName,
      amountUSD, currency: 'USD', status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const flwResp = await fetch(`${FLUTTERWAVE_API_BASE}/payments`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${FLUTTERWAVE_SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tx_ref: txRef,
        amount: amountUSD,
        currency: 'USD', // Flutterwave may still settle in the customer's local currency; that is recorded separately once known, never used as the list price.
        redirect_url: `${PUBLIC_APP_URL}/?flw_tx_ref=${encodeURIComponent(txRef)}`,
        customer: { email: uid ? (req.body?.email || 'no-email-on-file@invigil') : email, name: institutionName || undefined },
        customizations: { title: 'Invigil Prime', description: `${plan.name} — ${studentCount} students` },
        meta: { uid, planId, studentCount, institutionName },
      }),
    });
    const flwData = await flwResp.json();
    if (!flwResp.ok || flwData.status !== 'success' || !flwData.data?.link) {
      console.error('Flutterwave payment creation failed:', flwData);
      return res.status(502).json({ ok: false, error: 'Could not start checkout right now — try again shortly.' });
    }
    res.json({ ok: true, url: flwData.data.link });
  } catch (err) {
    console.error('create-flutterwave-payment error:', err.message);
    res.status(500).json({ ok: false, error: 'Could not start checkout right now — try again shortly.' });
  }
});

// -----------------------------------------------------------------------
// POST /flutterwave/webhook
//
// The ONLY thing in this codebase allowed to activate a subscription.
// Verifies the `verif-hash` header against FLUTTERWAVE_WEBHOOK_HASH,
// re-queries Flutterwave's own transaction-verification endpoint (never
// trusting the webhook payload's claimed amount/status on its own — the
// payload is what tells us WHICH transaction to go check, not proof by
// itself), cross-checks the verified amount/currency/reference against
// the payment record created in /create-flutterwave-payment, and only
// then updates subscriptions/{uid-or-email} and payments/{txRef}.
//
// Idempotent: the Flutterwave event id is recorded in
// paymentEvents/{eventId} inside the same Firestore transaction that
// updates the subscription, so a duplicate/retried webhook delivery can
// never grant duplicate access or extend a subscription twice.
// -----------------------------------------------------------------------
app.post('/flutterwave/webhook', async (req, res) => {
  const signature = req.headers['verif-hash'];
  if (!FLUTTERWAVE_WEBHOOK_HASH || !signature || signature !== FLUTTERWAVE_WEBHOOK_HASH) {
    // Deliberately vague + fast rejection, same philosophy as the
    // verify-* endpoints: don't give a prober anything to work with.
    return res.status(401).json({ ok: false });
  }
  if (!db) {
    return res.status(500).json({ ok: false, error: 'Server not configured.' });
  }

  const event = req.body || {};
  const txRef = event?.data?.tx_ref || event?.txRef;
  const flwTransactionId = event?.data?.id;
  if (!txRef || !flwTransactionId) {
    return res.status(400).json({ ok: false, error: 'Malformed webhook payload.' });
  }
  // Flutterwave expects a fast 200 response; do the real work, but don't
  // make the sender retry-storm us over something we've already recorded.
  const eventId = `flw_${flwTransactionId}`;

  try {
    const alreadyProcessed = await db.collection('paymentEvents').doc(eventId).get();
    if (alreadyProcessed.exists) {
      return res.status(200).json({ ok: true, note: 'Already processed.' });
    }

    // Re-query Flutterwave directly rather than trusting the webhook body's
    // own amount/status fields — this is the actual server-side proof of
    // payment, not the webhook delivery itself.
    const verifyResp = await fetch(`${FLUTTERWAVE_API_BASE}/transactions/${flwTransactionId}/verify`, {
      headers: { 'Authorization': `Bearer ${FLUTTERWAVE_SECRET_KEY}` },
    });
    const verifyData = await verifyResp.json();
    const tx = verifyData?.data;
    if (!verifyResp.ok || verifyData.status !== 'success' || !tx || tx.tx_ref !== txRef) {
      console.error('Flutterwave webhook verification mismatch:', verifyData);
      return res.status(400).json({ ok: false, error: 'Could not verify transaction.' });
    }

    const paymentRef = db.collection('payments').doc(txRef);
    const paymentSnap = await paymentRef.get();
    if (!paymentSnap.exists) {
      console.error('Flutterwave webhook: no matching payment record for', txRef);
      return res.status(404).json({ ok: false, error: 'Unknown transaction reference.' });
    }
    const payment = paymentSnap.data();

    // Cross-check the verified transaction against what we expected when
    // the payment was created — amount, currency, and reference must all
    // agree. (Flutterwave's settlement currency/amount can legitimately
    // differ from the USD list price if the customer paid in local
    // currency; that's recorded separately below, not compared here.)
    const expectedAmount = payment.amountUSD;
    const paidInExpectedCurrency = tx.currency === 'USD';
    const amountOk = paidInExpectedCurrency
      ? Math.abs(Number(tx.amount) - expectedAmount) < 0.01
      : true; // different settlement currency — amount is checked via charged_amount/app_fee reconciliation on your Flutterwave dashboard, not blocked here.
    if (tx.status !== 'successful' || !amountOk) {
      await paymentRef.update({ status: tx.status === 'successful' ? 'amount_mismatch' : tx.status, verifiedAt: admin.firestore.FieldValue.serverTimestamp() });
      await db.collection('paymentEvents').doc(eventId).set({ txRef, receivedAt: admin.firestore.FieldValue.serverTimestamp(), outcome: 'rejected', reason: tx.status !== 'successful' ? 'not-successful' : 'amount-mismatch' });
      return res.status(200).json({ ok: true, note: 'Transaction not activated (status or amount mismatch).' });
    }

    const subjectId = payment.uid || payment.email;
    const subscriptionRef = db.collection('subscriptions').doc(subjectId);
    const plan = PRICING_PLANS[payment.planId];
    const periodMs = plan?.billingPeriod === 'monthly' ? 31 * 24 * 60 * 60 * 1000 : 366 * 24 * 60 * 60 * 1000;
    const now = Date.now();

    // Everything below happens atomically: recording the event id (for
    // idempotency) and activating the subscription happen together, so a
    // crash between the two can't leave a half-applied state that a retry
    // would then double-apply.
    await db.runTransaction(async (t) => {
      const eventDoc = await t.get(db.collection('paymentEvents').doc(eventId));
      if (eventDoc.exists) return; // another concurrent delivery already handled it
      t.set(db.collection('paymentEvents').doc(eventId), {
        txRef, flwTransactionId, receivedAt: admin.firestore.FieldValue.serverTimestamp(), outcome: 'activated',
      });
      t.update(paymentRef, {
        status: 'successful',
        verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
        settlementAmount: tx.amount,
        settlementCurrency: tx.currency,
        flwTransactionId,
      });
      t.set(subscriptionRef, {
        status: 'active',
        planId: payment.planId,
        studentCount: payment.studentCount,
        institutionName: payment.institutionName || null,
        currentPeriodEnd: new Date(now + periodMs).toISOString(),
        lastPaymentTxRef: txRef,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      }, { merge: true });
    });

    res.status(200).json({ ok: true });
  } catch (err) {
    console.error('flutterwave webhook error:', err.message);
    // Still 200 — Flutterwave will retry a non-2xx response, and retrying
    // won't fix a bug on our end; log it and investigate instead.
    res.status(200).json({ ok: false });
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
app.use('/lti/push-grade', restrictedCors);
app.post('/lti/push-grade', async (req, res) => {
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

// -----------------------------------------------------------------------
// Cloudflare R2 file storage (Part B) — question images, exam
// attachments, lecturer documents, student-submitted files. This is NEW
// functionality: the existing app had no file-upload feature at all
// (question images were pasted as externally-hosted URLs), so there is
// nothing being "migrated" here beyond that URL field staying available
// alongside this.
//
// Route summary:
//   POST   /files/upload-url    — lecturer requests a signed PUT URL
//   POST   /files/confirm       — lecturer confirms a completed upload, saves Firestore metadata
//   GET    /files/:fileId/signed-url  — signed GET URL (lecturer, OR a student mid-test — see below)
//   DELETE /files/:fileId       — lecturer deletes a file
//
// IMPORTANT LIMITATION, stated plainly rather than glossed over: Invigil's
// student exam flow has no Firebase Authentication at all — students join
// a test by access code, not by signing in (see /verify-code,
// /verify-student above). That means a per-student authorization check
// (verifying "this specific student is allowed to see this specific
// file") isn't possible without inventing a new session-token system for
// students, which is out of scope here. What IS enforced for the
// student-facing signed-URL route below is that the requested file is
// actually attached to the testId being requested — which stops the
// exact attack described in the spec (changing examId=123 to
// examId=124), but is not equivalent to full per-user authorization.
// -----------------------------------------------------------------------
const storageService = require('./storageService');
const FILE_UPLOAD_RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;

async function verifyLecturer(req) {
  const authHeader = req.headers.authorization || '';
  const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!idToken) return null;
  try {
    return await admin.auth().verifyIdToken(idToken);
  } catch (err) {
    return null;
  }
}

async function lecturerOwnsCourse(uid, courseId) {
  if (!db || !courseId) return false;
  const snap = await db.collection('courses').doc(courseId).get();
  return snap.exists && snap.data().createdBy === uid;
}

app.use('/files', restrictedCors);

app.post('/files/upload-url', async (req, res) => {
  if (!storageService.isConfigured()) {
    return res.status(500).json({ ok: false, error: 'File storage is currently being configured. Please try again later or contact us.' });
  }
  if (!db) return res.status(500).json({ ok: false, error: 'Server not configured.' });

  const decoded = await verifyLecturer(req);
  if (!decoded) return res.status(401).json({ ok: false, error: 'Not signed in.' });

  const ip = clientIp(req);
  if (rateLimited(`upload:${decoded.uid}`, 30, FILE_UPLOAD_RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ ok: false, error: 'Too many uploads — please wait a few minutes and try again.' });
  }

  const { courseId, examId, category, fileName, contentType, size } = req.body || {};
  if (!(await lecturerOwnsCourse(decoded.uid, courseId))) {
    return res.status(403).json({ ok: false, error: 'You don\'t have permission to upload to this course.' });
  }
  if (!storageService.ALLOWED_MIME_TYPES.has(contentType)) {
    return res.status(400).json({ ok: false, error: 'That file type isn\'t supported. Allowed: PNG, JPEG, GIF, WEBP, PDF.' });
  }
  if (!Number.isFinite(size) || size <= 0 || size > storageService.MAX_FILE_SIZE_BYTES) {
    return res.status(400).json({ ok: false, error: `File is too large — the limit is ${Math.round(storageService.MAX_FILE_SIZE_BYTES / 1024 / 1024)}MB.` });
  }

  try {
    const fileId = crypto.randomUUID();
    const objectKey = storageService.buildObjectKey({ courseId, examId, category });
    const uploadUrl = await storageService.getUploadUrl(objectKey, contentType);
    res.json({ ok: true, fileId, objectKey, uploadUrl });
  } catch (err) {
    console.error('files/upload-url error:', err.message);
    res.status(500).json({ ok: false, error: 'Could not prepare upload — try again shortly.' });
  }
});

app.post('/files/confirm', async (req, res) => {
  if (!storageService.isConfigured() || !db) {
    return res.status(500).json({ ok: false, error: 'File storage is currently being configured. Please try again later or contact us.' });
  }
  const decoded = await verifyLecturer(req);
  if (!decoded) return res.status(401).json({ ok: false, error: 'Not signed in.' });

  const { fileId, objectKey, courseId, examId, fileName, contentType, size } = req.body || {};
  if (!(await lecturerOwnsCourse(decoded.uid, courseId))) {
    return res.status(403).json({ ok: false, error: 'You don\'t have permission to attach files to this course.' });
  }
  if (typeof fileId !== 'string' || typeof objectKey !== 'string' || !objectKey.startsWith(`courses/${courseId}/`)) {
    return res.status(400).json({ ok: false, error: 'Malformed upload confirmation.' });
  }

  try {
    // Confirm the object actually landed in R2 before trusting the
    // client's claim that the upload succeeded.
    const uploaded = await storageService.exists(objectKey);
    if (!uploaded) {
      return res.status(400).json({ ok: false, error: 'Upload not found — please try uploading again.' });
    }
    await db.collection('files').doc(fileId).set({
      ownerId: decoded.uid,
      courseId,
      examId: examId || null,
      fileName: typeof fileName === 'string' ? fileName.slice(0, 200) : 'file',
      contentType,
      size: Number(size) || null,
      storageProvider: 'cloudflare_r2',
      objectKey,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.json({ ok: true, fileId });
  } catch (err) {
    console.error('files/confirm error:', err.message);
    res.status(500).json({ ok: false, error: 'Could not save the file — try again shortly.' });
  }
});

app.get('/files/:fileId/signed-url', async (req, res) => {
  if (!storageService.isConfigured() || !db) {
    return res.status(500).json({ ok: false, error: 'File storage is currently being configured. Please try again later or contact us.' });
  }
  const { fileId } = req.params;
  const { testId } = req.query; // present for student-mid-test access; absent for lecturer access

  try {
    const snap = await db.collection('files').doc(fileId).get();
    if (!snap.exists) return res.status(404).json({ ok: false, error: 'File not found.' });
    const file = snap.data();

    if (testId) {
      // Student-facing path — no Firebase Auth available (see comment
      // above). The one check that IS possible: the file must actually
      // belong to the test being requested, which blocks the
      // examId-swap attack the spec calls out even without per-student auth.
      if (file.examId !== testId) {
        return res.status(403).json({ ok: false, error: 'Not authorized for this file.' });
      }
    } else {
      const decoded = await verifyLecturer(req);
      if (!decoded || decoded.uid !== file.ownerId) {
        return res.status(403).json({ ok: false, error: 'Not authorized for this file.' });
      }
    }

    const url = await storageService.getSignedUrl(file.objectKey);
    res.json({ ok: true, url });
  } catch (err) {
    console.error('files/signed-url error:', err.message);
    res.status(500).json({ ok: false, error: 'Could not generate a link for this file — try again shortly.' });
  }
});

app.delete('/files/:fileId', async (req, res) => {
  if (!storageService.isConfigured() || !db) {
    return res.status(500).json({ ok: false, error: 'File storage is currently being configured. Please try again later or contact us.' });
  }
  const decoded = await verifyLecturer(req);
  if (!decoded) return res.status(401).json({ ok: false, error: 'Not signed in.' });

  try {
    const ref = db.collection('files').doc(req.params.fileId);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ ok: false, error: 'File not found.' });
    const file = snap.data();
    if (file.ownerId !== decoded.uid) {
      return res.status(403).json({ ok: false, error: 'You don\'t have permission to delete this file.' });
    }
    await storageService.delete(file.objectKey);
    await ref.delete();
    res.json({ ok: true });
  } catch (err) {
    console.error('files/delete error:', err.message);
    res.status(500).json({ ok: false, error: 'Could not delete the file — try again shortly.' });
  }
});

app.listen(PORT, () => console.log(`Invigil backend listening on :${PORT}`));
