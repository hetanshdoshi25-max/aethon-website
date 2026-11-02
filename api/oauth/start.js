// GET /api/oauth/start?provider=google&k=<phone's one-time key>&n=<nonce>
// Opens the provider's sign-in page. Called by the Aethon Chat Android app.
const { PROVIDERS, REDIRECT_URI, creds, makeState, backToApp } = require('../_oauth');

module.exports = async function start(req, res) {
  const q = req.query || {};
  const provider = String(q.provider || '');
  const k = String(q.k || '');
  const n = String(q.n || '');
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(n)) {
    res.statusCode = 400;
    return res.end('Bad request');
  }
  if (!PROVIDERS[provider] || !/^[A-Za-z0-9_-]{40,50}$/.test(k)) return backToApp(res, { error: 'bad_request', n, p: provider });
  const c = creds(provider);
  if (!c) return backToApp(res, { error: 'not_configured', n, p: provider });

  let state;
  try {
    state = makeState({ p: provider, k, n });
  } catch {
    return backToApp(res, { error: 'not_configured', n, p: provider });
  }

  const cfg = PROVIDERS[provider];
  const params = new URLSearchParams({
    client_id: c.id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    state,
    ...cfg.extra,
  });
  if (cfg.scope) params.set('scope', cfg.scope);
  res.statusCode = 302;
  res.setHeader('Location', `${cfg.authorize}?${params.toString()}`);
  res.setHeader('Cache-Control', 'no-store');
  res.end();
};
