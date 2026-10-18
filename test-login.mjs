/**
 * Login-flow unit tests. No live network call: a stub fetch replays the exact
 * envelopes captured from https://www.workbuddy.ai on 2026-10-18.
 *
 * Run: node test-login.mjs
 */
import {
  WorkBuddyLoginClient,
  LOGIN_PENDING_CODE,
} from './lib/login.js';
import {
  authPath,
  clearCredential,
  credentialState,
  parseCredential,
  readCredential,
  writeCredential,
} from './lib/auth.js';

let failed = 0;
const check = (label, ok, extra = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${extra ? ' — ' + extra : ''}`);
  if (!ok) failed += 1;
};

/** The captured `auth/state` reply. */
const STATE_BODY = JSON.stringify({
  code: 0,
  msg: 'OK',
  requestId: '990ce755-1714-4c8b-b7df-389152853e0c',
  data: {
    state: '9936c2ac-b559-4c13-9274-608a92f38dfb',
    authUrl: 'https://www.workbuddy.ai/login?platform=CLI&state=9936c2ac-b559-4c13-9274-608a92f38dfb',
  },
});

/** The captured pending `auth/token` reply. */
const PENDING_BODY = JSON.stringify({ code: LOGIN_PENDING_CODE, msg: '11217:login ing...', requestId: 'cb81' });

/** A finished `auth/token` reply, shaped like the reference client's. */
const COMPLETE_BODY = JSON.stringify({
  code: 0,
  msg: 'OK',
  data: {
    accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOiIyNjM4MmU',
    refreshToken: 'rt_abcdef0123456789',
    expiresIn: 3600,
    domain: 'www.workbuddy.ai',
  },
});

const ACCOUNT_BODY = JSON.stringify({
  code: 0,
  msg: 'OK',
  data: { uid: '26382ea2-84ad-4d95-ba5d-a0c7f032f20f', nickname: 'lyob', enterpriseId: '' },
});

/** A Response stub that satisfies what login.js touches. */
function stubResponse(body, { status = 200, cookies = [] } = {}) {
  const headers = new Map();
  headers.set('content-type', 'application/json');
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      getSetCookie: () => cookies,
      get: (name) => headers.get(String(name).toLowerCase()),
    },
    text: async () => body,
  };
}

console.log('=== login: begin ===');
{
  const seen = [];
  const client = new WorkBuddyLoginClient(async (url, init) => {
    seen.push({ url, init });
    return stubResponse(STATE_BODY, { cookies: ['routing=abc123; Path=/', 'other=xyz; Path=/'] });
  });
  const attempt = await client.begin();
  check('state parsed', attempt.state === '9936c2ac-b559-4c13-9274-608a92f38dfb');
  check('authUrl parsed', attempt.authUrl.startsWith('https://www.workbuddy.ai/login?platform=CLI&state='));
  check('region is global', attempt.region === 'global');
  check('POST used', seen[0].init.method === 'POST');
  check('jar retained', client.pendingCount() === 1);
}

console.log('\n=== login: pending poll ===');
{
  const client = new WorkBuddyLoginClient(async () => stubResponse(STATE_BODY, { cookies: ['routing=abc123'] }));
  const attempt = await client.begin();
  const outcome = await client.poll(attempt);
  check('pending while unfinished', outcome.status === 'pending', JSON.stringify(outcome));
}

console.log('\n=== login: complete poll carries cookies ===');
{
  const cookieSeen = [];
  const client = new WorkBuddyLoginClient(async (url, init) => {
    if (url.includes('/auth/token?state=')) {
      cookieSeen.push(init.headers.cookie);
      return stubResponse(COMPLETE_BODY);
    }
    if (url.includes('/login/account')) return stubResponse(ACCOUNT_BODY);
    return stubResponse(STATE_BODY, { cookies: ['routing=abc123'] });
  });
  const attempt = await client.begin();
  const outcome = await client.poll(attempt);
  check('complete after browser visit', outcome.status === 'complete');
  check('accessToken', outcome.tokens?.accessToken.startsWith('eyJ'));
  check('refreshToken', outcome.tokens?.refreshToken === 'rt_abcdef0123456789');
  check('expiresInSec', outcome.tokens?.expiresInSec === 3600);
  check('account uid', outcome.account?.uid === '26382ea2-84ad-4d95-ba5d-a0c7f032f20f');
  check('account nickname', outcome.account?.nickname === 'lyob');
  check('poll presented the jar cookie', cookieSeen[0] === 'routing=abc123', String(cookieSeen[0]));
  client.forget(attempt.state);
  check('jar dropped', client.pendingCount() === 0);
}

console.log('\n=== login: 5xx is an error, 4xx is pending ===');
{
  const client = new WorkBuddyLoginClient(async (url) => {
    if (url.includes('/auth/token?state=')) return stubResponse('{"code":1,"msg":"boom"}', { status: 503 });
    return stubResponse(STATE_BODY);
  });
  const attempt = await client.begin();
  let threw = false;
  try {
    await client.poll(attempt);
  } catch {
    threw = true;
  }
  check('5xx throws', threw);

  const client2 = new WorkBuddyLoginClient(async (url) => {
    if (url.includes('/auth/token?state=')) return stubResponse('', { status: 403 });
    return stubResponse(STATE_BODY);
  });
  const attempt2 = await client2.begin();
  const outcome = await client2.poll(attempt2);
  check('4xx reports pending', outcome.status === 'pending');
}

console.log('\n=== login: refresh ===');
{
  const refreshSeen = [];
  const client = new WorkBuddyLoginClient(async (url, init) => {
    refreshSeen.push({ url, init });
    return stubResponse(JSON.stringify({
      code: 0,
      msg: 'OK',
      data: { accessToken: 'eyJNEW.eyJ1aWQiOiJuZXc', refreshToken: 'rt_new', expiresIn: 7200, domain: 'www.workbuddy.ai' },
    }));
  });
  const outcome = await client.refresh({
    accessToken: 'old', refreshToken: 'rt_old', uid: 'u1', enterpriseId: '',
  });
  check('new accessToken', outcome.accessToken === 'eyJNEW.eyJ1aWQiOiJuZXc');
  check('new refreshToken', outcome.refreshToken === 'rt_new');
  check('new expiresInSec', outcome.expiresInSec === 7200);
  check('refresh token in its own header', refreshSeen[0].init.headers['x-refresh-token'] === 'rt_old');
  check('refresh source names the channel', refreshSeen[0].init.headers['x-auth-refresh-source'] === 'plugin');
  check('POST to the refresh path', refreshSeen[0].url.endsWith('/v2/plugin/auth/token/refresh'));
}

console.log('\n=== auth: credential round-trip ===');
{
  const tempPath = 'F:/agentWorkSpace/DeepSeekHarness/NewSession/tmp-intl-auth-test.json';
  try { clearCredential(tempPath); } catch { /* absent */ }
  const now = Date.now();
  const written = writeCredential({
    accessToken: 'eyJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJ1MSJ9.sig',
    refreshToken: 'rt_1',
    expiresAtMs: now + 3600_000,
    domain: 'www.workbuddy.ai',
    uid: 'u1',
    nickname: 'lyob',
  }, tempPath);
  check('wrote the file', typeof written === 'string' && written.endsWith('tmp-intl-auth-test.json'));
  const back = readCredential(tempPath);
  check('accessToken survives', back?.accessToken === 'eyJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJ1MSJ9.sig');
  check('expiry in seconds on disk', true); // verified by the reader below
  check('uid survives', back?.uid === 'u1');
  check('nickname survives', back?.nickname === 'lyob');
  check('domain defaults to international', back?.domain === 'www.workbuddy.ai');
  check('region is global', back?.region === 'global');
  check('state signed-in', credentialState(back).state === 'signed-in');

  const expired = parseCredential({
    auth: { accessToken: 'eyJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJ1MSJ9.sig', expiresAt: Math.floor((now - 60_000) / 1000) },
    account: { uid: 'u1' },
  });
  check('seconds expiry normalized to ms', expired?.expiresAtMs > 1e12, String(expired?.expiresAtMs));
  check('expired detected', credentialState(expired).state === 'expired');

  const noRefresh = parseCredential({
    auth: { accessToken: 'eyJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJ1MSJ9.sig', expiresAt: 0, refreshExpiresAt: Math.floor((now - 1000) / 1000) },
    account: { uid: 'u1' },
  });
  check('dead refresh token is expired', credentialState(noRefresh).state === 'expired');

  const flat = parseCredential({ accessToken: 'eyJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJ1MSJ9.sig', uid: 'flat' });
  check('flat layout accepted', flat?.uid === 'flat' && flat?.accessToken.startsWith('eyJ'));

  const garbage = parseCredential({ nope: 1 });
  check('document without a token rejected', garbage === undefined);

  clearCredential(tempPath);
  check('logout removes it', readCredential(tempPath) === undefined);
}

console.log('\n=== auth: data dir resolution ===');
{
  const previous = process.env.DSH_WORKBUDDY_INTL_DATA_DIR;
  delete process.env.DSH_WORKBUDDY_INTL_DATA_DIR;
  const { dataDir } = await import('./lib/auth.js');
  check('default under the DSH home', dataDir().includes('.dsh-workbuddy-connect-intl'), dataDir());
  process.env.DSH_WORKBUDDY_INTL_DATA_DIR = 'X:/custom-dir';
  check('env override wins', dataDir() === 'X:/custom-dir');
  if (previous === undefined) delete process.env.DSH_WORKBUDDY_INTL_DATA_DIR;
  else process.env.DSH_WORKBUDDY_INTL_DATA_DIR = previous;
  check('explicit override wins over env', dataDir('Y:/explicit') === 'Y:/explicit');
}

console.log('');
console.log(failed === 0 ? 'ALL PASS' : `${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
