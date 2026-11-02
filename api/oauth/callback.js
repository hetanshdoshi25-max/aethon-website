// GET /api/oauth/callback?code=...&state=...   (the provider sends the user here)
// Swaps the code for a token, encrypts it for the phone and returns to the app.
const { readState, exchange, sealForPhone, backToApp } = require('../_oauth');

module.exports = async function callback(req, res) {
  const q = req.query || {};
  let st = null;
  try {
    st = readState(q.state);
  } catch {
    st = null;
  }
  if (!st) {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.end('This sign-in link is not valid. Please start again from the Aethon Chat app.');
  }
  const { p, k, n } = st;
  if (st.expired) return backToApp(res, { error: 'expired', n, p });
  if (q.error) return backToApp(res, { error: String(q.error).slice(0, 40), n, p });
  if (!q.code) return backToApp(res, { error: 'no_code', n, p });

  try {
    const tokens = await exchange(p, String(q.code));
    const d = sealForPhone(k, tokens);
    return backToApp(res, { d, n, p });
  } catch (e) {
    // Only the error code is logged – never tokens or account details.
    console.error('oauth callback failed:', p, e && e.message ? String(e.message).slice(0, 60) : 'unknown');
    const code = e && /^[a-z_]+$/.test(String(e.message)) ? String(e.message) : 'token_failed';
    return backToApp(res, { error: code, n, p });
  }
};
