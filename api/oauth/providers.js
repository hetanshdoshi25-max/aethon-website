// GET /api/oauth/providers – which connector sign-ins are switched on.
// The Android app shows the others as "Coming soon" instead of letting a sign-in fail.
// Only true/false per provider is returned; no keys or secrets.
const { PROVIDERS, creds } = require('../_oauth');

module.exports = function providers(req, res) {
  const out = {};
  for (const p of Object.keys(PROVIDERS)) out[p] = !!creds(p);
  let ready = true;
  try {
    ready = !!process.env.OAUTH_STATE_SECRET && process.env.OAUTH_STATE_SECRET.length >= 16;
  } catch {
    ready = false;
  }
  if (!ready) for (const p of Object.keys(out)) out[p] = false;
  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.end(JSON.stringify({ providers: out }));
};
