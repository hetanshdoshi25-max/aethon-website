// Vercel serverless function: sends the website support form to the Aethon Chat inbox
// through Gmail, with any attached screenshots.
//
// Needs two environment variables in the Vercel project (Settings > Environment Variables):
//   GMAIL_USER          aethonchat@gmail.com
//   GMAIL_APP_PASSWORD  a 16-character Google App Password (not the normal Gmail password)
// Optional:
//   SUPPORT_TO          where to deliver messages (defaults to GMAIL_USER)

const nodemailer = require('nodemailer');

const MAX_FILES = 3;
const MAX_FILE_BYTES = 2.5 * 1024 * 1024;
const MAX_TOTAL_BYTES = 4 * 1024 * 1024;
const TYPES = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Best-effort limit per IP (each warm instance keeps its own count).
const hits = new Map();
function tooMany(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 10 * 60 * 1000);
  list.push(now);
  hits.set(ip, list);
  return list.length > 5;
}

const line = (v, max) => String(v == null ? '' : v).replace(/[\r\n\t]+/g, ' ').trim().slice(0, max);
const text = (v, max) => String(v == null ? '' : v).replace(/\r\n/g, '\n').trim().slice(0, max);

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'method_not_allowed' });
  }
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) return res.status(503).json({ ok: false, error: 'not_configured' });

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (_) { body = null; }
  }
  if (!body || typeof body !== 'object') return res.status(400).json({ ok: false, error: 'bad_request' });

  // Honeypot: real people never fill this hidden field.
  if (body.website) return res.status(200).json({ ok: true });

  const ip = line(req.headers['x-forwarded-for'], 100).split(',')[0].trim() || 'unknown';
  if (tooMany(ip)) return res.status(429).json({ ok: false, error: 'too_many' });

  const name = line(body.name, 100);
  const email = line(body.email, 200);
  const topic = line(body.topic, 60) || 'Support';
  const windows = line(body.windows, 40);
  const message = text(body.message, 5000);
  if (!name || !message || !EMAIL_RE.test(email)) return res.status(400).json({ ok: false, error: 'missing_fields' });

  const files = Array.isArray(body.files) ? body.files.slice(0, MAX_FILES) : [];
  const attachments = [];
  let total = 0;
  for (let i = 0; i < files.length; i++) {
    const f = files[i] || {};
    const ext = TYPES[f.type];
    if (!ext || typeof f.data !== 'string') return res.status(400).json({ ok: false, error: 'bad_file' });
    const buf = Buffer.from(f.data, 'base64');
    total += buf.length;
    if (!buf.length || buf.length > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES) {
      return res.status(413).json({ ok: false, error: 'file_too_large' });
    }
    attachments.push({ filename: `screenshot-${i + 1}.${ext}`, content: buf, contentType: f.type });
  }

  const mail = [
    message,
    '',
    '---',
    `Topic: ${topic}`,
    `Windows: ${windows || 'not given'}`,
    `From: ${name} <${email}>`,
    `Screenshots: ${attachments.length}`,
    'Sent from the support form on aethonchat.com',
  ].join('\n');

  try {
    const transport = nodemailer.createTransport({ service: 'gmail', auth: { user, pass } });
    await transport.sendMail({
      from: { name: 'Aethon Chat Support Form', address: user },
      to: process.env.SUPPORT_TO || user,
      replyTo: { name, address: email },
      subject: `[Aethon Chat Support] ${topic} - ${name}`,
      text: mail,
      attachments,
    });
    return res.status(200).json({ ok: true });
  } catch (err) {
    // Log only the error code, never the message content or the user's details.
    console.error('support mail failed:', err && (err.code || err.responseCode || 'unknown'));
    return res.status(502).json({ ok: false, error: 'send_failed' });
  }
};
