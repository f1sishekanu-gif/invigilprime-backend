// ============================================================================
// Invigil — Cloudflare R2 storage service
//
// R2 is S3-compatible, so this uses the official AWS SDK v3 S3 client
// pointed at R2's endpoint rather than any custom storage logic. Every
// route in index.js that touches files goes through this module — nothing
// else in the codebase talks to R2 directly — so the storage provider can
// be swapped later (per the "storageService" abstraction requested) without
// touching route logic.
//
// Credentials (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY,
// R2_BUCKET_NAME) live ONLY in this server's environment variables — see
// README/final report for the exact list. They are never sent to, or
// reachable from, the frontend.
// ============================================================================

const { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const crypto = require('crypto');

const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID || '';
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || '';
// Optional — only needed if you've mapped the bucket to a public custom
// domain for objects you deliberately want to be public. Protected files
// (the default) are only ever reached through a signed URL, never this.
const R2_PUBLIC_BASE_URL = (process.env.R2_PUBLIC_BASE_URL || '').replace(/\/$/, '');

const configured = !!(R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_BUCKET_NAME);
if (!configured) {
  console.warn('Cloudflare R2 is not fully configured (R2_ACCOUNT_ID/R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY/R2_BUCKET_NAME) — file upload/download routes will refuse all requests until it is.');
}

const client = configured ? new S3Client({
  region: 'auto',
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_ACCESS_KEY },
}) : null;

// Allowed file categories — deliberately conservative. Extend only with a
// real product need; never add executable types (.exe, .sh, .bat, .js,
// .html, etc.) since these are lecturer/student-uploaded files served
// back to other users.
const ALLOWED_MIME_TYPES = new Set([
  'image/png', 'image/jpeg', 'image/gif', 'image/webp',
  'application/pdf',
]);
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB — generous for question images/PDFs, small enough to bound abuse.

function isConfigured() { return configured; }

// Generates a collision-proof, unpredictable object key. Never derived
// from the user-supplied filename — that stays in Firestore metadata
// (files/{fileId}.fileName) for display purposes only, never as part of
// the actual storage path.
function buildObjectKey({ courseId, examId, category }) {
  const uuid = crypto.randomUUID();
  const parts = ['courses', courseId || 'unscoped'];
  if (examId) parts.push('exams', examId);
  parts.push(category || 'files', uuid);
  return parts.join('/');
}

async function upload(objectKey, buffer, contentType) {
  if (!configured) throw new Error('R2 not configured');
  await client.send(new PutObjectCommand({
    Bucket: R2_BUCKET_NAME, Key: objectKey, Body: buffer, ContentType: contentType,
  }));
  return { objectKey };
}

async function deleteObject(objectKey) {
  if (!configured) throw new Error('R2 not configured');
  await client.send(new DeleteObjectCommand({ Bucket: R2_BUCKET_NAME, Key: objectKey }));
}

async function exists(objectKey) {
  if (!configured) throw new Error('R2 not configured');
  try {
    await client.send(new HeadObjectCommand({ Bucket: R2_BUCKET_NAME, Key: objectKey }));
    return true;
  } catch (err) {
    if (err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404) return false;
    throw err;
  }
}

// A signed PUT URL the browser uploads directly to — the file bytes never
// pass through this Render server, avoiding its request-size/timeout
// limits. Short-lived (5 minutes) since it's only meant to be used once,
// immediately.
async function getUploadUrl(objectKey, contentType, expiresInSeconds = 300) {
  if (!configured) throw new Error('R2 not configured');
  const cmd = new PutObjectCommand({ Bucket: R2_BUCKET_NAME, Key: objectKey, ContentType: contentType });
  return getSignedUrl(client, cmd, { expiresIn: expiresInSeconds });
}

// A signed GET URL for downloading/viewing a protected file. Short-lived
// (default 5 minutes) — the frontend requests a fresh one each time
// rather than caching it, since anyone holding the URL can use it until
// it expires.
async function getSignedUrlForObject(objectKey, expiresInSeconds = 300) {
  if (!configured) throw new Error('R2 not configured');
  const cmd = new GetObjectCommand({ Bucket: R2_BUCKET_NAME, Key: objectKey });
  return getSignedUrl(client, cmd, { expiresIn: expiresInSeconds });
}

module.exports = {
  isConfigured,
  buildObjectKey,
  upload,
  delete: deleteObject,
  exists,
  getUploadUrl,
  getSignedUrl: getSignedUrlForObject,
  ALLOWED_MIME_TYPES,
  MAX_FILE_SIZE_BYTES,
};
