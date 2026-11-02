// Shared code for the Aethon Chat connector sign-in (files starting with "_" are not
// turned into their own API routes by Vercel).
//
// The phone app starts a sign-in at /api/oauth/start, the provider sends the user back
// to /api/oauth/callback, and this server swaps the one-time code for a token with the
// app secret (which must never be inside the phone app). The token is then encrypted
// with a one-time key that only the phone knows and handed back to the app through
// aethon://oauth. Nothing is stored on this server.
//
// Environment variables (Vercel → Settings → Environment Variables):
//   OAUTH_STATE_SECRET                     any long random text (signs the sign-in state)
//   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
//   GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
//   NOTION_CLIENT_ID / NOTION_CLIENT_SECRET
//   SLACK_CLIENT_ID  / SLACK_CLIENT_SECRET
// A provider without its two variables simply shows "not switched on yet" in the app.

const crypto = require('crypto');

const SITE = 'https://www.aethonchat.com';
const REDIRECT_URI = `${SITE}/api/oauth/callback`;
const APP_RETURN = 'aethon://oauth';
const STATE_MAX_AGE_MS = 15 * 60 * 1000;

const PROVIDERS = {
  google: {
    env: 'GOOGLE',
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
    scope: [
      'openid',
      'email',
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/calendar.events',
    ].join(' '),
    extra: { access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true' },
  },
  github: {
    env: 'GITHUB',
    authorize: 'https://github.com/login/oauth/authorize',
    scope: 'repo notifications read:user',
    extra: { allow_signup: 'false' },
  },
  notion: {
    env: 'NOTION',
    authorize: 'https://api.notion.com/v1/oauth/authorize',
    scope: '',
    extra: { owner: 'user' },
  },
  slack: {
    env: 'SLACK',
    authorize: 'https://slack.com/oauth/v2/authorize',
    // Slack: user-token scopes go in user_scope, so Aethon acts as the user.
    scope: '',
    extra: { user_scope: 'channels:read,channels:history,groups:read,groups:history,chat:write,users:read' },
  },
};

function creds(p) {
  const cfg = PROVIDERS[p];
  if (!cfg) return null;
  const id = process.env[`${cfg.env}_CLIENT_ID`];
  const secret = process.env[`${cfg.env}_CLIENT_SECRET`];
  return id && secret ? { id, secret } : null;
}

const b64url = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64url = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

function stateSecret() {
  const s = process.env.OAUTH_STATE_SECRET;
  if (!s || s.length < 16) throw new Error('OAUTH_STATE_SECRET is missing');
  return s;
}

/** state = base64url(json) "." hmac  – tamper-proof, expires after 15 minutes. */
function makeState(data) {
  const body = b64url(JSON.stringify({ ...data, t: Date.now() }));
  const sig = b64url(crypto.createHmac('sha256', stateSecret()).update(body).digest());
  return `${body}.${sig}`;
}

function readState(state) {
  const [body, sig] = String(state || '').split('.');
  if (!body || !sig) return null;
  const want = b64url(crypto.createHmac('sha256', stateSecret()).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let data;
  try {
    data = JSON.parse(fromB64url(body).toString('utf8'));
  } catch {
    return null;
  }
  if (!data || typeof data.t !== 'number') return null;
  if (Date.now() - data.t > STATE_MAX_AGE_MS) return { ...data, expired: true };
  return data;
}

/** AES-256-GCM with the phone's one-time key. Output: iv(12) | ciphertext | tag(16), base64url. */
function sealForPhone(keyB64url, payload) {
  const key = fromB64url(keyB64url);
  if (key.length !== 32) throw new Error('bad key');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(payload), 'utf8'), c.final()]);
  return b64url(Buffer.concat([iv, ct, c.getAuthTag()]));
}

function backToApp(res, params) {
  const qs = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join('&');
  const url = `${APP_RETURN}?${qs}`;
  // A plain redirect, plus a tiny page with a button in case the browser does not follow
  // custom app links on its own.
  res.statusCode = 302;
  res.setHeader('Location', url);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(
    `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Aethon Chat</title>` +
      `<body style="background:#04080B;color:#E6F4F6;font-family:system-ui;text-align:center;padding:48px 20px">` +
      `<p>Returning to Aethon Chat…</p><p><a style="color:#00F2FF" href="${url.replace(/"/g, '&quot;')}">Open Aethon Chat</a></p></body>`,
  );
}

async function postForm(url, form, headers = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', ...headers },
    body: new URLSearchParams(form).toString(),
  });
  const json = await res.json().catch(() => ({}));
  return { ok: res.ok, json };
}

/** Swaps the sign-in code for tokens. Returns { at, rt, exp, acct }. */
async function exchange(p, code) {
  const c = creds(p);
  if (!c) throw new Error('not_configured');

  if (p === 'google') {
    const { ok, json } = await postForm('https://oauth2.googleapis.com/token', {
      code,
      client_id: c.id,
      client_secret: c.secret,
      redirect_uri: REDIRECT_URI,
      grant_type: 'authorization_code',
    });
    if (!ok || !json.access_token) throw new Error(json.error || 'token_failed');
    let acct = 'Google account';
    try {
      const idp = JSON.parse(fromB64url(String(json.id_token).split('.')[1]).toString('utf8'));
      if (idp.email) acct = idp.email;
    } catch {
      /* keep default */
    }
    return { at: json.access_token, rt: json.refresh_token, exp: json.expires_in, acct };
  }

  if (p === 'github') {
    const { ok, json } = await postForm('https://github.com/login/oauth/access_token', {
      code,
      client_id: c.id,
      client_secret: c.secret,
      redirect_uri: REDIRECT_URI,
    });
    if (!ok || !json.access_token) throw new Error(json.error || 'token_failed');
    let acct = 'GitHub';
    try {
      const u = await fetch('https://api.github.com/user', {
        headers: { Authorization: `Bearer ${json.access_token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'AethonChat' },
      }).then((r) => r.json());
      if (u.login) acct = u.login;
    } catch {
      /* keep default */
    }
    return { at: json.access_token, rt: json.refresh_token, exp: json.expires_in, acct };
  }

  if (p === 'notion') {
    const res = await fetch('https://api.notion.com/v1/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Basic ${Buffer.from(`${c.id}:${c.secret}`).toString('base64')}`,
        'Notion-Version': '2022-06-28',
      },
      body: JSON.stringify({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI }),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || !json.access_token) throw new Error(json.error || 'token_failed');
    const acct = json.owner?.user?.person?.email || json.workspace_name || 'Notion';
    return { at: json.access_token, acct };
  }

  if (p === 'slack') {
    const { ok, json } = await postForm('https://slack.com/api/oauth.v2.access', {
      code,
      client_id: c.id,
      client_secret: c.secret,
      redirect_uri: REDIRECT_URI,
    });
    const user = json.authed_user || {};
    if (!ok || !json.ok || !user.access_token) throw new Error(json.error || 'token_failed');
    return { at: user.access_token, rt: user.refresh_token, exp: user.expires_in, acct: json.team?.name ? `${json.team.name} workspace` : 'Slack' };
  }

  throw new Error('unknown_provider');
}

/** New access token from a refresh token (Google, and Slack if token rotation is on). */
async function refresh(p, refreshToken) {
  const c = creds(p);
  if (!c) throw new Error('not_configured');
  if (p === 'google') {
    const { ok, json } = await postForm('https://oauth2.googleapis.com/token', {
      client_id: c.id,
      client_secret: c.secret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    });
    if (!ok || !json.access_token) throw new Error(json.error || 'refresh_failed');
    return { access_token: json.access_token, expires_in: json.expires_in, refresh_token: json.refresh_token };
  }
  if (p === 'slack') {
    const { ok, json } = await postForm('https://slack.com/api/oauth.v2.access', {
      client_id: c.id,
      client_secret: c.secret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    });
    if (!ok || !json.ok || !json.access_token) throw new Error(json.error || 'refresh_failed');
    return { access_token: json.access_token, expires_in: json.expires_in, refresh_token: json.refresh_token };
  }
  throw new Error('no_refresh');
}

module.exports = { PROVIDERS, REDIRECT_URI, creds, makeState, readState, sealForPhone, backToApp, exchange, refresh };
