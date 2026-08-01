// ============================================================================
// Invigil — LTI 1.3 Advantage module (SSO launch + Deep Linking + AGS)
//
// This is a hand-rolled implementation (using `jose` for JWT/JWKS) rather
// than a framework like ltijs, deliberately: ltijs wants its own session
// store (normally MongoDB), which would mean running a second database
// alongside Firestore. Everything here reuses Firestore via the Admin SDK
// that index.js already initializes, so there's exactly one datastore.
//
// ---------------------------------------------------------------------------
// THE THREE LTI MESSAGES THIS HANDLES
// ---------------------------------------------------------------------------
// 1. Resource Link launch — a student or lecturer clicks an "Invigil"
//    activity a lecturer already added to a Moodle course. Ends with the
//    browser landing on the app at ?ltiLaunch=<code>.
// 2. Deep Linking launch — a lecturer is in Moodle doing
//    "Add an activity → External tool → Invigil" for the first time. Ends
//    with the browser landing on the app at ?ltiDeepLink=<code>, where the
//    lecturer picks one of their existing tests to link.
// 3. AGS (Assignment & Grade Services) — server-to-server. After a test is
//    graded, pushGradeToLti() POSTs the score into the Moodle gradebook
//    column Moodle auto-created for that activity.
//
// ---------------------------------------------------------------------------
// FIRESTORE COLLECTIONS THIS OWNS (all Admin-SDK-only — see firestore.rules,
// which denies ALL client access to these three; only ltiPlatforms is
// client-writable, by the lecturer who registers it)
// ---------------------------------------------------------------------------
// ltiPlatforms/{platformId}   Registered Moodle sites.
//   { issuer, clientId, authLoginUrl, authTokenUrl, jwksUrl,
//     deploymentIds: [string], label, createdBy, createdAt }
//
// ltiNonces/{state}           One-time OIDC login state, ~10 min TTL.
//   { nonce, platformId, createdAt }
//
// ltiLaunches/{code}          One-time exchange code the frontend trades
//                             for a session after a verified launch.
//   resource kind: { kind:'resource', role, testId, name, sub, email,
//                     platformId, deploymentId, lineitemUrl, createdAt }
//   deepLink kind: { kind:'deepLink', platformId, deploymentId, sub, name,
//                     email, deepLinkReturnUrl, deepLinkData, createdAt }
//
// ltiResourceLinks/{resourceLinkId}   AGS lineitem cache, one per Moodle
//                             activity instance, written lazily on first
//                             real launch of that activity.
//   { lineitemUrl, testId, platformId, createdAt }
// ============================================================================

const express = require('express');
const crypto = require('crypto');
const {
  importPKCS8, exportJWK, calculateJwkThumbprint,
  SignJWT, jwtVerify, createRemoteJWKSet, decodeProtectedHeader,
} = require('jose');

const LTI_CLAIM = {
  messageType: 'https://purl.imsglobal.org/spec/lti/claim/message_type',
  deploymentId: 'https://purl.imsglobal.org/spec/lti/claim/deployment_id',
  roles: 'https://purl.imsglobal.org/spec/lti/claim/roles',
  resourceLink: 'https://purl.imsglobal.org/spec/lti/claim/resource_link',
  custom: 'https://purl.imsglobal.org/spec/lti/claim/custom',
  targetLinkUri: 'https://purl.imsglobal.org/spec/lti/claim/target_link_uri',
  ags: 'https://purl.imsglobal.org/spec/lti-ags/claim/endpoint',
  dlSettings: 'https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings',
  dlMessageType: 'LtiDeepLinkingResponse',
  dlContentItems: 'https://purl.imsglobal.org/spec/lti-dl/claim/content_items',
  dlData: 'https://purl.imsglobal.org/spec/lti-dl/claim/data',
};

const INSTRUCTOR_ROLE_HINTS = ['Instructor', 'Administrator', 'ContentDeveloper'];

// Exchange codes and OIDC state are short-lived by design — a code that
// leaks in a browser history or a referrer header should already be dead.
const LAUNCH_TTL_MS = 3 * 60 * 1000;          // resource-link launches
const DEEPLINK_TTL_MS = 20 * 60 * 1000;       // longer: lecturer needs time to pick a test
const NONCE_TTL_MS = 10 * 60 * 1000;

// In-memory cache of platforms' remote JWKS fetchers — createRemoteJWKSet
// already caches keys internally, this just avoids rebuilding the fetcher
// object (and its own cache) on every single launch.
const remoteJwksCache = new Map(); // jwksUrl -> ReturnType<createRemoteJWKSet>

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

// ---------------------------------------------------------------------------
// Invigil's own signing key — used to sign Deep Linking responses and AGS
// client-assertion JWTs, and published (public half only) at /lti/jwks.json
// for Moodle admins to paste into the tool registration screen.
//
// LTI_PRIVATE_KEY_BASE64: base64 of a PKCS8 PEM RSA private key. Generate
// once with:
//   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out lti-private.pem
//   base64 -w0 lti-private.pem
// LTI_KID: any stable short string identifying this key, e.g. "invigil-1".
// Never commit either value — set them as Render environment variables,
// same as FIREBASE_SERVICE_ACCOUNT_BASE64.
// ---------------------------------------------------------------------------
let signingKeyPromise = null;
function getSigningKey() {
  if (signingKeyPromise) return signingKeyPromise;
  const b64 = process.env.LTI_PRIVATE_KEY_BASE64;
  const kid = process.env.LTI_KID;
  if (!b64 || !kid) {
    signingKeyPromise = Promise.reject(new Error(
      'LTI_PRIVATE_KEY_BASE64 / LTI_KID not set — see server/README section "LTI setup".'
    ));
    return signingKeyPromise;
  }
  const pem = Buffer.from(b64, 'base64').toString('utf8');
  signingKeyPromise = importPKCS8(pem, 'RS256').then(async (privateKey) => {
    // CRITICAL: exportJWK() on a private KeyObject exports every field —
    // including d, p, q, dp, dq, qi, the actual private key material.
    // /lti/jwks.json is a PUBLIC endpoint by design (Moodle fetches it to
    // verify our signatures), so publishing that JWK directly would leak
    // the private key to anyone who requests the URL. Derive the public
    // key from the private key first, and export ONLY that.
    const publicKeyObject = crypto.createPublicKey(privateKey);
    const publicJwk = await exportJWK(publicKeyObject);
    publicJwk.kid = kid;
    publicJwk.alg = 'RS256';
    publicJwk.use = 'sig';
    return { privateKey, kid, publicJwk };
  });
  return signingKeyPromise;
}

function getRemoteJwks(jwksUrl) {
  let fetcher = remoteJwksCache.get(jwksUrl);
  if (!fetcher) {
    fetcher = createRemoteJWKSet(new URL(jwksUrl));
    remoteJwksCache.set(jwksUrl, fetcher);
  }
  return fetcher;
}

function htmlError(res, status, title, detail) {
  res.status(status).type('html').send(`<!doctype html><html><head><meta charset="utf-8">
<title>Invigil — ${title}</title>
<style>body{font-family:system-ui,sans-serif;max-width:520px;margin:80px auto;padding:0 20px;color:#1a1a1a}
h1{font-size:19px}p{font-size:14.5px;line-height:1.6;color:#444}</style></head>
<body><h1>${title}</h1><p>${detail}</p></body></html>`);
}

// Roles claim is a list of full URNs, e.g.
// "http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor" — we just
// check whether any of them ends in a name we treat as instructor-level.
function isInstructorRoles(roles) {
  if (!Array.isArray(roles)) return false;
  return roles.some(r => INSTRUCTOR_ROLE_HINTS.some(hint => r.endsWith('#' + hint) || r.endsWith('/' + hint)));
}

// ---------------------------------------------------------------------------
// createLtiRouter(db, opts) — db is the firebase-admin Firestore instance
// already initialized in index.js. opts: { publicAppUrl, publicBackendUrl }
// ---------------------------------------------------------------------------
function createLtiRouter(db, admin, opts) {
  const { publicAppUrl, publicBackendUrl } = opts;
  const router = express.Router();

  // -------------------------------------------------------------------
  // GET /lti/jwks.json — Invigil's own public keyset. Give this URL to
  // Moodle admins as the tool's "Public keyset URL" during registration.
  // -------------------------------------------------------------------
  router.get('/jwks.json', async (req, res) => {
    try {
      const { publicJwk } = await getSigningKey();
      res.json({ keys: [publicJwk] });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // -------------------------------------------------------------------
  // GET|POST /lti/login — OIDC third-party initiated login. Moodle sends
  // the browser here first, before the actual launch.
  // -------------------------------------------------------------------
  async function handleLogin(req, res) {
    const params = { ...req.query, ...req.body };
    const { iss, login_hint, client_id, lti_deployment_id, lti_message_hint, target_link_uri } = params;
    if (!iss || !login_hint || !client_id) {
      return htmlError(res, 400, 'Missing login parameters',
        'This link is missing required OIDC parameters. Ask your Invigil admin to check the tool registration in Moodle.');
    }

    let platformSnap;
    try {
      platformSnap = await db.collection('ltiPlatforms')
        .where('issuer', '==', iss).where('clientId', '==', client_id).limit(1).get();
    } catch (err) {
      return htmlError(res, 500, 'Could not look up this Moodle site', 'Try again shortly.');
    }
    if (platformSnap.empty) {
      return htmlError(res, 403, 'Moodle site not registered',
        'This Moodle site isn\'t registered with Invigil yet. Ask your Invigil admin to register it under Moodle setup → Register your Moodle site.');
    }
    const platformDoc = platformSnap.docs[0];
    const platform = platformDoc.data();

    const state = randomToken();
    const nonce = randomToken();
    await db.collection('ltiNonces').doc(state).set({
      nonce, platformId: platformDoc.id, deploymentId: lti_deployment_id || null,
      createdAt: Date.now(),
    });

    const authUrl = new URL(platform.authLoginUrl);
    authUrl.searchParams.set('scope', 'openid');
    authUrl.searchParams.set('response_type', 'id_token');
    authUrl.searchParams.set('client_id', client_id);
    authUrl.searchParams.set('redirect_uri', `${publicBackendUrl}/lti/launch`);
    authUrl.searchParams.set('login_hint', login_hint);
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('response_mode', 'form_post');
    authUrl.searchParams.set('nonce', nonce);
    authUrl.searchParams.set('prompt', 'none');
    if (lti_message_hint) authUrl.searchParams.set('lti_message_hint', lti_message_hint);
    if (target_link_uri) authUrl.searchParams.set('target_link_uri', target_link_uri);

    res.redirect(302, authUrl.toString());
  }
  router.get('/login', handleLogin);
  router.post('/login', handleLogin);

  // -------------------------------------------------------------------
  // POST /lti/launch — the actual LTI message, delivered as a form_post
  // containing a signed id_token. Verifies it, then branches on message
  // type and redirects the browser into the app with a one-time code.
  // -------------------------------------------------------------------
  router.post('/launch', async (req, res) => {
    const { id_token, state } = req.body;
    if (!id_token || !state) {
      return htmlError(res, 400, 'Malformed launch', 'Missing id_token or state.');
    }

    const nonceRef = db.collection('ltiNonces').doc(state);
    const nonceSnap = await nonceRef.get();
    if (!nonceSnap.exists) {
      return htmlError(res, 400, 'Launch expired or already used',
        'This login link has expired or was already used. Go back to Moodle and click the activity again.');
    }
    const nonceData = nonceSnap.data();
    await nonceRef.delete(); // one-time use, regardless of what happens below

    if (Date.now() - nonceData.createdAt > NONCE_TTL_MS) {
      return htmlError(res, 400, 'Launch expired', 'This login link expired. Go back to Moodle and try again.');
    }

    const platformRef = db.collection('ltiPlatforms').doc(nonceData.platformId);
    const platformSnap = await platformRef.get();
    if (!platformSnap.exists) {
      return htmlError(res, 400, 'Moodle site no longer registered', 'Ask your Invigil admin to re-register this site.');
    }
    const platform = platformSnap.data();

    let payload;
    try {
      decodeProtectedHeader(id_token); // throws early on garbage input
      const remoteJwks = getRemoteJwks(platform.jwksUrl);
      const result = await jwtVerify(id_token, remoteJwks, {
        issuer: platform.issuer,
        audience: platform.clientId,
      });
      payload = result.payload;
    } catch (err) {
      return htmlError(res, 401, 'Could not verify launch',
        'Invigil could not verify this launch\'s signature. This usually means the Moodle site\'s registration details are out of date.');
    }

    if (payload.nonce !== nonceData.nonce) {
      return htmlError(res, 401, 'Nonce mismatch', 'This launch could not be verified (nonce mismatch). Please try again.');
    }

    const deploymentId = payload[LTI_CLAIM.deploymentId];
    if (!deploymentId) {
      return htmlError(res, 400, 'Missing deployment', 'This launch is missing its deployment ID.');
    }
    if (!Array.isArray(platform.deploymentIds) || !platform.deploymentIds.includes(deploymentId)) {
      // First launch from a newly-added deployment under an already
      // registered tool — record it rather than reject it, since Moodle
      // issues deployment IDs on its own schedule and a lecturer shouldn't
      // need an admin round-trip just to add a second course context.
      await platformRef.update({
        deploymentIds: [...(platform.deploymentIds || []), deploymentId],
      });
    }

    const sub = payload.sub;
    const name = payload.name || [payload.given_name, payload.family_name].filter(Boolean).join(' ') || 'Moodle user';
    const email = payload.email || null;
    const roles = payload[LTI_CLAIM.roles];
    const messageType = payload[LTI_CLAIM.messageType];

    if (messageType === 'LtiDeepLinkingRequest') {
      if (!isInstructorRoles(roles)) {
        return htmlError(res, 403, 'Instructors only',
          'Only instructors can configure an Invigil activity in Moodle.');
      }
      const dlSettings = payload[LTI_CLAIM.dlSettings];
      if (!dlSettings || !dlSettings.deep_linking_return_url) {
        return htmlError(res, 400, 'Missing Deep Linking settings', 'This launch is missing required Deep Linking parameters.');
      }
      const code = randomToken();
      await db.collection('ltiLaunches').doc(code).set({
        kind: 'deepLink',
        platformId: platformRef.id,
        deploymentId,
        sub, name, email,
        deepLinkReturnUrl: dlSettings.deep_linking_return_url,
        deepLinkData: dlSettings.data || null,
        createdAt: Date.now(),
      });
      return res.redirect(302, `${publicAppUrl}/?ltiDeepLink=${code}`);
    }

    if (messageType === 'LtiResourceLinkRequest') {
      const custom = payload[LTI_CLAIM.custom] || {};
      const resourceLink = payload[LTI_CLAIM.resourceLink] || {};
      // testId travels as a custom parameter set at Deep Linking time
      // (see buildContentItem below) — the standards-compliant equivalent
      // of the old manual "?testId=" instructions.
      const testId = custom.testId || null;
      const ags = payload[LTI_CLAIM.ags];
      const lineitemUrl = ags && ags.lineitem ? ags.lineitem : null;

      if (lineitemUrl && resourceLink.id) {
        await db.collection('ltiResourceLinks').doc(resourceLink.id).set({
          lineitemUrl, testId, platformId: platformRef.id, updatedAt: Date.now(),
        }, { merge: true });
      }

      if (!testId) {
        return htmlError(res, 404, 'Not linked to a test',
          'This Moodle activity isn\'t linked to an Invigil test yet. Ask your lecturer to remove and re-add it using "Add an activity → External tool → Invigil" so it can be linked through the test picker.');
      }

      const role = isInstructorRoles(roles) ? 'instructor' : 'student';
      const code = randomToken();
      await db.collection('ltiLaunches').doc(code).set({
        kind: 'resource', role, testId, name, sub, email, custom,
        platformId: platformRef.id, deploymentId, lineitemUrl,
        createdAt: Date.now(),
      });
      return res.redirect(302, `${publicAppUrl}/?ltiLaunch=${code}`);
    }

    return htmlError(res, 400, 'Unsupported launch type', `Message type "${messageType || 'unknown'}" isn't supported.`);
  });

  // -------------------------------------------------------------------
  // GET /lti/session?code=... — the frontend exchanges a one-time code
  // (from either redirect above) for either a Firebase sign-in (instructor
  // launches, both kinds) or student join details (student resource-link
  // launches). Codes are deleted on read except deepLink codes, which stay
  // alive until /lti/deep-link/complete consumes them — the lecturer needs
  // time to pick a test.
  // -------------------------------------------------------------------
  router.get('/session', async (req, res) => {
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    if (!code) return res.status(400).json({ ok: false, error: 'Missing code.' });

    const ref = db.collection('ltiLaunches').doc(code);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ ok: false, error: 'This link has expired. Go back to Moodle and try again.' });
    const launch = snap.data();

    const ttl = launch.kind === 'deepLink' ? DEEPLINK_TTL_MS : LAUNCH_TTL_MS;
    if (Date.now() - launch.createdAt > ttl) {
      await ref.delete();
      return res.status(410).json({ ok: false, error: 'This link has expired. Go back to Moodle and try again.' });
    }

    if (launch.kind === 'resource') {
      await ref.delete(); // one-time use

      if (launch.role === 'instructor') {
        const uid = `lti:${launch.platformId}:${launch.sub}`;
        try {
          await db.collection('lecturers').doc(uid).set({
            email: launch.email || null, name: launch.name, provisionedVia: 'lti',
          }, { merge: true });
          const customToken = await admin.auth().createCustomToken(uid, { ltiPlatformId: launch.platformId });
          return res.json({ ok: true, role: 'instructor', customToken, testId: launch.testId });
        } catch (err) {
          return res.status(500).json({ ok: false, error: 'Could not sign in via Moodle right now.' });
        }
      }

      // Student. Moodle's own claims don't include a real student/matric
      // number by default — Invigil's register check exists to catch
      // someone typing in a name/ID that isn't theirs, but a Moodle
      // launch already proves identity via the institution's own login,
      // which is a stronger guarantee than the register check. So LTI
      // joins skip the register check entirely (viaLti below tells the
      // frontend to bypass it) rather than fail on an identifier mismatch
      // that isn't really a mismatch. If a Moodle admin configures a
      // custom parameter named studentid (e.g. studentid=$Person.sourcedId)
      // on the activity, that's used as the student number shown in
      // Results instead of Moodle's opaque internal ID.
      const custom = launch.custom || {};
      return res.json({
        ok: true, role: 'student', testId: launch.testId,
        name: launch.name, studentId: custom.studentid || launch.sub,
        viaLti: true,
        ltiSub: launch.sub, ltiPlatformId: launch.platformId, ltiLineitemUrl: launch.lineitemUrl || null,
      });
    }

    if (launch.kind === 'deepLink') {
      const uid = `lti:${launch.platformId}:${launch.sub}`;
      try {
        await db.collection('lecturers').doc(uid).set({
          email: launch.email || null, name: launch.name, provisionedVia: 'lti',
        }, { merge: true });
        const customToken = await admin.auth().createCustomToken(uid, { ltiPlatformId: launch.platformId });
        return res.json({ ok: true, deepLink: true, customToken, code });
      } catch (err) {
        return res.status(500).json({ ok: false, error: 'Could not sign in via Moodle right now.' });
      }
    }

    return res.status(400).json({ ok: false, error: 'Unknown launch kind.' });
  });

  // -------------------------------------------------------------------
  // POST /lti/deep-link/complete  { code, testId }  (Authorization: Bearer
  // <lecturer Firebase ID token>) — builds a signed LTI Deep Linking
  // Response containing the chosen test as a resource-link content item
  // (with a `lineItem` hint so Moodle auto-provisions a gradebook column),
  // and hands back the JWT + the platform's return URL for the frontend
  // to form_post there (a real page navigation back into Moodle).
  // -------------------------------------------------------------------
  router.post('/deep-link/complete', async (req, res) => {
    const authHeader = req.headers.authorization || '';
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!idToken) return res.status(401).json({ ok: false, error: 'Not signed in.' });

    let decoded;
    try {
      decoded = await admin.auth().verifyIdToken(idToken);
    } catch (err) {
      return res.status(401).json({ ok: false, error: 'Session expired — sign in again.' });
    }

    const { code, testId } = req.body || {};
    if (!code || !testId) return res.status(400).json({ ok: false, error: 'Missing code or testId.' });

    const ref = db.collection('ltiLaunches').doc(code);
    const snap = await ref.get();
    if (!snap.exists || snap.data().kind !== 'deepLink') {
      return res.status(404).json({ ok: false, error: 'This link has expired. Go back to Moodle and try again.' });
    }
    const launch = snap.data();

    const testSnap = await db.collection('tests').doc(testId).get();
    if (!testSnap.exists) return res.status(404).json({ ok: false, error: 'Test not found.' });
    const test = testSnap.data();

    const courseSnap = await db.collection('courses').doc(test.courseId).get();
    if (!courseSnap.exists || courseSnap.data().createdBy !== decoded.uid) {
      return res.status(403).json({ ok: false, error: 'You don\'t own this test.' });
    }

    let signingKey;
    try {
      signingKey = await getSigningKey();
    } catch (err) {
      return res.status(500).json({ ok: false, error: 'Invigil\'s LTI signing key isn\'t configured yet — ask your admin to set LTI_PRIVATE_KEY_BASE64.' });
    }

    const dlPlatformSnap = await db.collection('ltiPlatforms').doc(launch.platformId).get();
    if (!dlPlatformSnap.exists) return res.status(400).json({ ok: false, error: 'Moodle site no longer registered.' });
    const dlPlatform = dlPlatformSnap.data();

    const contentItem = {
      type: 'ltiResourceLink',
      title: test.title,
      custom: { testId },
      lineItem: { scoreMaximum: 100, label: test.title },
    };

    const jwt = await new SignJWT({
      [LTI_CLAIM.deploymentId]: launch.deploymentId,
      'https://purl.imsglobal.org/spec/lti-dl/claim/message_type': LTI_CLAIM.dlMessageType,
      [LTI_CLAIM.dlContentItems]: [contentItem],
      ...(launch.deepLinkData ? { [LTI_CLAIM.dlData]: launch.deepLinkData } : {}),
    })
      .setProtectedHeader({ alg: 'RS256', kid: signingKey.kid, typ: 'JWT' })
      .setIssuer(dlPlatform.clientId)     // iss = the tool's client_id at THIS platform (LTI spec convention for tool->platform messages)
      .setAudience(dlPlatform.issuer)     // aud = the platform's own issuer URL
      .setIssuedAt()
      .setExpirationTime('5m')
      .setJti(randomToken(12))
      .sign(signingKey.privateKey);

    await ref.delete();
    res.json({ ok: true, returnUrl: launch.deepLinkReturnUrl, jwt });
  });

  return router;
}

// ---------------------------------------------------------------------------
// pushGradeToLti(db, { testId, submissionId, scoreGiven, scoreMaximum })
// Called from a lecturer-authenticated route in index.js after grading.
// Does the OAuth2 client_credentials dance (JWT client-assertion) against
// the platform's token endpoint, then POSTs the score to the AGS scores
// endpoint. Returns { ok, error? }.
// ---------------------------------------------------------------------------
async function pushGradeToLti(db, { testId, submissionId, scoreGiven, scoreMaximum }) {
  const subSnap = await db.collection('tests').doc(testId).collection('submissions').doc(submissionId).get();
  if (!subSnap.exists) return { ok: false, error: 'Submission not found.' };
  const sub = subSnap.data();
  if (!sub.ltiLineitemUrl || !sub.ltiPlatformId || !sub.ltiSub) {
    return { ok: false, error: 'This submission has no linked Moodle gradebook entry.' };
  }

  const platformSnap = await db.collection('ltiPlatforms').doc(sub.ltiPlatformId).get();
  if (!platformSnap.exists) return { ok: false, error: 'Moodle site no longer registered.' };
  const platform = platformSnap.data();

  let signingKey;
  try {
    signingKey = await getSigningKey();
  } catch (err) {
    return { ok: false, error: 'LTI signing key not configured.' };
  }

  // Step 1: client_credentials grant using a JWT client assertion signed
  // with Invigil's own key (RFC 7523) — proves we are the tool without a
  // shared secret ever existing.
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: signingKey.kid, typ: 'JWT' })
    .setIssuer(platform.clientId)
    .setSubject(platform.clientId)
    .setAudience(platform.authTokenUrl)
    .setIssuedAt()
    .setExpirationTime('5m')
    .setJti(randomToken(12))
    .sign(signingKey.privateKey);

  let accessToken;
  try {
    const tokenResp = await fetch(platform.authTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: assertion,
        scope: 'https://purl.imsglobal.org/spec/lti-ags/scope/score',
      }),
    });
    if (!tokenResp.ok) return { ok: false, error: `Moodle rejected the token request (${tokenResp.status}).` };
    const tokenJson = await tokenResp.json();
    accessToken = tokenJson.access_token;
  } catch (err) {
    return { ok: false, error: 'Could not reach Moodle\'s token endpoint.' };
  }

  // Step 2: POST the score to the lineitem's /scores endpoint.
  try {
    const scoresUrl = sub.ltiLineitemUrl.replace(/\/?$/, '') + '/scores';
    const scoreResp = await fetch(scoresUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/vnd.ims.lis.v1.score+json',
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        userId: sub.ltiSub,
        scoreGiven,
        scoreMaximum,
        activityProgress: 'Completed',
        gradingProgress: 'FullyGraded',
        timestamp: new Date().toISOString(),
      }),
    });
    if (!scoreResp.ok) return { ok: false, error: `Moodle rejected the score (${scoreResp.status}).` };
  } catch (err) {
    return { ok: false, error: 'Could not reach Moodle\'s grade endpoint.' };
  }

  return { ok: true };
}

module.exports = { createLtiRouter, pushGradeToLti };
