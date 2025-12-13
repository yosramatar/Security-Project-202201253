// backend/oidc.js
// Generic OIDC SSO integration for HealthCureAlpha

let Issuer;

async function getIssuer() {
  if (!Issuer) {
    const mod = await import('openid-client');
    Issuer = mod.Issuer;
  }
  return Issuer;
}

let oidcClient = null;

async function initOidcClient() {
  const issuerUrl = process.env.OIDC_ISSUER_URL;
  const clientId = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const redirectUri = process.env.OIDC_REDIRECT_URI;
  if (!issuerUrl || !clientId || !clientSecret || !redirectUri) {
    throw new Error('OIDC env vars missing');
  }
  // SSRF protection: Only allow OIDC issuer URLs from allowlist
  const { isSafeOutboundUrl } = require('./security');
  const allowedOidcDomains = [
    'login.microsoftonline.com',
    'accounts.google.com',
    'auth0.com',
    'okta.com',
    'github.com',
    'apple.com',
    'auth.healthcurealpha.com'
  ];
  if (!isSafeOutboundUrl(issuerUrl, allowedOidcDomains)) {
    throw new Error('OIDC issuer URL is not allowed or is unsafe');
  }
  const IssuerClass = await getIssuer();
  const issuer = await IssuerClass.discover(issuerUrl);
  oidcClient = new issuer.Client({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: [redirectUri],
    response_types: ['code'],
  });
}

function getOidcClient() {
  if (!oidcClient) throw new Error('OIDC client not initialized');
  return oidcClient;
}

function getAuthUrl(state, nonce) {
  const client = getOidcClient();
  return client.authorizationUrl({
    scope: 'openid email profile',
    state,
    nonce,
  });
}

async function handleCallback(code, state, nonce) {
  const client = getOidcClient();
  const params = { code, state };
  const tokenSet = await client.callback(process.env.OIDC_REDIRECT_URI, params, { nonce });
  const userinfo = await client.userinfo(tokenSet.access_token);
  return { tokenSet, userinfo };
}

module.exports = {
  initOidcClient,
  getAuthUrl,
  handleCallback,
};
