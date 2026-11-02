// POST /api/oauth/refresh  { provider, refresh_token }  ->  { access_token, expires_in }
// Google access tokens last an hour; the phone asks here for a new one.
const { refresh } = require('../_oauth');

const hits = new Map();
function tooMany(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 60_000);
  list.push(now);
  hits.set(ip, list);
  return list.length > 30;
}

module.exports = async function refreshRoute(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'method_not_allowed' });
  }
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  if (tooMany(ip)) return res.status(429).json({ error: 'too_many' });
  let body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      body = null;
    }
  }
  const provider = String(body?.provider || '');
  const rt = String(body?.refresh_token || '');
  if (!['google', 'slack'].includes(provider) || rt.length < 10 || rt.length > 2048) return res.status(400).json({ error: 'bad_request' });
  try {
    const out = await refresh(provider, rt);
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json(out);
  } catch (e) {
    console.error('oauth refresh failed:', provider, e && e.message ? String(e.message).slice(0, 60) : 'unknown');
    return res.status(401).json({ error: 'refresh_failed' });
  }
};
