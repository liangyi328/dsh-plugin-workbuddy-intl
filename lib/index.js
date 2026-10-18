/**
 * WorkBuddy International provider for DeepSeek Harness.
 *
 * Registers one LLM provider route (`workbuddy-intl` by default) against the
 * international WorkBuddy gateway at https://www.workbuddy.ai. The gateway
 * protocol is the same OpenAI Chat Completions surface the domestic
 * (workbuddy.cn) edition serves; only the origin differs.
 *
 * The token is resolved in this order:
 *   1. a credential stored through the DSH credentials service (`apiKeyEnv`)
 *   2. the same name in the launching environment
 *
 * There is deliberately no on-disk session discovery here: the international
 * desktop client encrypts its session at rest (AES-256-GCM, key wrapped in
 * `~/.workbuddy-ai/keyblob` behind a protector key this plugin cannot derive),
 * so a token cannot be read from disk. Paste it once into the Models page and
 * the credentials service keeps it.
 *
 * This module imports only the packages it declares as dependencies (pnpm
 * installs them alongside the plugin). Host services arrive through `ctx`.
 */
import fs from 'node:fs';
import z from '@deepseek-ai/schemastery';
import { WorkBuddyAdapter, WorkBuddyError } from './adapter.js';
import { CATALOG_STAMP, loadCatalog, workBuddyHome } from './catalog.js';
import { tokenExpiry, userIdFromToken } from './auth.js';
import { credentialState, readCredential, writeCredential } from './auth.js';
import { WorkBuddyLoginClient, LOGIN_PENDING_CODE } from './login.js';
import { ContextWindowStore, defaultStorePath, effectiveContextWindow, isAdjustable, optionsFor } from './ctx-window.js';
import { TARGET as MENU_TARGET, stripPatch, isPatched } from './menu-patch.js';

const name = 'llm-workbuddy-intl';
// `clientModules` lets uninstallMenuPatch restore the built-in model menu
// bundle in memory, undoing the row injected by an earlier plugin version.
const inject = ['llm', 'clientModules'];
const DEFAULT_PROVIDER = 'workbuddy-intl';
const DEFAULT_TOKEN_REF = 'WORKBUDDY_INTL_AUTH_TOKEN';
// The gateway verifies that the caller looks like an official client; this is
// the identity string the shipped CLI sends.
const DEFAULT_CLIENT_UA = 'CLI/2.162.0 CodeBuddy/2.162.0';
// The international gateway origin. The `/v2` suffix carries the OpenAI-
// compatible chat surface, exactly as on the domestic edition.
const DEFAULT_BASE_URL = 'https://www.workbuddy.ai/v2';
const CREDENTIAL_REF_PATTERN = /^[A-Z][A-Z0-9_]*$/;

const Config = z.object({
  provider: z.string().default(DEFAULT_PROVIDER),
  displayName: z.string().default('WorkBuddy (Intl)'),
  baseURL: z.string().default(DEFAULT_BASE_URL),
  apiKeyEnv: z.string().role('credential-ref').default(DEFAULT_TOKEN_REF).volatile(),
  userId: z.string().default('').volatile(),
  clientUserAgent: z.string().default(DEFAULT_CLIENT_UA).volatile(),
  clientHeaders: z.dict(z.string()).default({}).volatile(),
  // Where this plugin keeps its own login credential (device-authorization
  // login, not a pasted token). Empty uses $DSH_HOME/.dsh-workbuddy-connect-intl.
  authPath: z.string().default('').volatile(),
  // Where the international catalog is read from. Empty uses the default
  // (~/.workbuddy-ai), which is where the international client keeps it.
  workBuddyHome: z.string().default(''),
  accountConfigPath: z.string().default(''),
  baseProductJsonPath: z.string().default(''),
  // Where the per-model context-length choice is persisted. Empty places it in
  // the WorkBuddy home directory; 'off' disables persistence entirely.
  contextWindowStorePath: z.string().default(''),
  scope: z.string().default('cli'),
  includeBaseOnly: z.boolean().default(false),
  onlyModels: z.array(z.string()).default([]),
  multiplierInName: z.boolean().default(true),
  reasoningEffortField: z.string().default('reasoning_effort'),
  defaultContextWindow: z.number().default(262144),
  defaultMaxTokens: z.number().default(32768),
  requestTimeoutMs: z.number().default(600000),
  // The international gateway rate-limits bursts (HTTP 429, business code
  // 14003) with no `Retry-After`. Two knobs keep a turn from ever failing:
  // a minimum gap between chat sends, and how many times a 429 is retried
  // in the adapter (with escalating back-off) before the caller sees it.
  rateLimitMinGapMs: z.number().default(700),
  rateLimitRetries: z.number().default(3),
  catalogRefreshMs: z.number().default(60000),
  debugLogPath: z.string().default(''),
});

/** Read every field once per operation, so a settings edit applies to the next call. */
function plainOptions(config) {
  return {
    provider: config.provider,
    displayName: config.displayName,
    baseURL: config.baseURL,
    apiKeyEnv: config.apiKeyEnv.get(),
    userId: config.userId.get(),
    clientUserAgent: config.clientUserAgent.get(),
    clientHeaders: { ...config.clientHeaders.get() },
    authPath: config.authPath.get(),
    workBuddyHome: config.workBuddyHome,
    accountConfigPath: config.accountConfigPath,
    baseProductJsonPath: config.baseProductJsonPath,
    contextWindowStorePath: config.contextWindowStorePath,
    scope: config.scope,
    includeBaseOnly: config.includeBaseOnly,
    onlyModels: [...config.onlyModels],
    multiplierInName: config.multiplierInName,
    reasoningEffortField: config.reasoningEffortField,
    defaultContextWindow: config.defaultContextWindow,
    defaultMaxTokens: config.defaultMaxTokens,
    requestTimeoutMs: config.requestTimeoutMs,
    rateLimitMinGapMs: config.rateLimitMinGapMs,
    rateLimitRetries: config.rateLimitRetries,
    catalogRefreshMs: config.catalogRefreshMs,
    debugLogPath: config.debugLogPath,
  };
}

/** Accept either a raw token or a pasted `Authorization` header value. */
function normalizeToken(raw) {
  const trimmed = raw.trim();
  return trimmed.toLowerCase().startsWith('bearer ') ? trimmed.slice(7).trim() : trimmed;
}

/** A credential must be a header-safe non-empty string. */
function assertUsableToken(raw, refName) {
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new WorkBuddyError(`workbuddy-intl: the token resolved from ${refName} is blank`, 'INVALID_CREDENTIAL');
  }
  if (!/^[\x21-\x7E]+$/.test(raw.trim())) {
    throw new WorkBuddyError(
      `workbuddy-intl: the token resolved from ${refName} contains characters no HTTP header can carry`,
      'INVALID_CREDENTIAL',
    );
  }
  return raw;
}

/** The client-identity headers the gateway's channel verification expects. */
function identityHeadersFor(current) {
  let host = '';
  try {
    host = new URL(current.baseURL).host;
  } catch {
    host = '';
  }
  return {
    'user-agent': current.clientUserAgent,
    'x-product': 'SaaS',
    'x-codebuddy-request': '1',
    ...(host.length > 0 ? { 'x-domain': host } : {}),
    ...current.clientHeaders,
  };
}

/**
 * Restore the built-in model-menu bundle to its pristine bytes, undoing the
 * in-memory "上下文窗口" row injection from an earlier plugin version. Like the
 * patch itself it only rewrites the in-memory record, so nothing on disk is
 * touched; runs once per boot and is skipped when the bundle is already clean.
 *
 * @param ctx - host plugin context (needs clientModules, or a scoped child of it).
 * @param debugLog - optional diagnostics sink.
 */
function uninstallMenuPatch(ctx, debugLog) {
  debugLog('menu patch: uninstall invoked');
  try {
    const registry = ctx.clientModules;
    if (!registry || !registry.table) {
      debugLog('menu patch: clientModules unavailable; skipped');
      return;
    }
    const record = registry.table.get(MENU_TARGET);
    if (!record) {
      debugLog(`menu patch: "${MENU_TARGET}" not in table yet; skipped`);
      return;
    }
    const text = record.bundle?.toString('utf8');
    if (text === undefined) {
      debugLog('menu patch: record has no bundle; skipped');
      return;
    }
    if (!isPatched(text)) {
      debugLog('menu patch: already pristine');
      return;
    }
    const restored = stripPatch(text);
    if (restored === null) {
      // The marker is present but the block cannot be located: the patched
      // bytes no longer match this plugin's shape (e.g. a DSH update was
      // composed on top). Leave the bundle alone rather than corrupt it.
      debugLog('menu patch: marker present but strip failed; skipped');
      return;
    }
    record.bundle = Buffer.from(restored, 'utf8');
    // Invalidate any already-composed response so the served bytes change too.
    try {
      registry.responses?.clear();
      registry.batchResponses?.clear();
      registry.previousBatchResponses?.clear();
      registry.composed = registry.compose?.();
    } catch {
      /* recomposition is best-effort; a later HMR flush would do it anyway */
    }
    debugLog(`menu patch: removed (${text.length} -> ${restored.length})`);
  } catch (error) {
    debugLog(`menu patch: FAILED ${error?.message ?? error}`);
  }
}

function apply(ctx, config) {
  // Log before anything that can throw: this single line separates "the module
  // was never imported" from "apply() ran and failed here".
  try {
    const target = config?.debugLogPath;
    if (typeof target === 'string' && target.length > 0) {
      fs.appendFileSync(target, `${new Date().toISOString()} apply() entered (code=v2)\n`);
    }
  } catch {
    /* ignore */
  }

  const options = () => plainOptions(config);
  options(); // fail loud on a malformed configuration rather than at first request

  const provider = options().provider;
  let cache;
  let loadedAt = 0;

  // Per-model context-length choices. The store is created once here (rather than
  // per call) so a value written through the HTTP route is immediately visible
  // to the adapter's `resolveModel`, and it re-reads its backing file when stale.
  const storePath = (() => {
    const configured = options().contextWindowStorePath;
    if (configured === 'off') return '';
    if (typeof configured === 'string' && configured.length > 0) return configured;
    return defaultStorePath(workBuddyHome(options().workBuddyHome));
  })();
  const selections = new ContextWindowStore({ file: storePath });

  /** Opt-in breadcrumb trail; a silent startup failure is otherwise invisible. */
  const debugLog = (message) => {
    const target = options().debugLogPath;
    if (typeof target !== 'string' || target.length === 0) return;
    try {
      fs.appendFileSync(target, `${new Date().toISOString()} ${message}\n`);
    } catch {
      /* diagnostics are best-effort and never fail the plugin */
    }
  };

  // Remove the "上下文窗口" row an earlier plugin version injected into the
  // built-in model menu. The menu exposes no slot and its component is not
  // exported, so the restore is also done at the byte level, in memory only.
  // Must run after `debugLog` exists (const bindings are not hoisted).
  uninstallMenuPatch(ctx, debugLog);

  // The client half (额度 pill + 上下文选择器) lives in this same package, but
  // `clientModules` only re-reads bundle bytes through `rebuilt()` — the HMR
  // module watch does not cover plugin files on this host, so a reload alone
  // would keep serving the previous client.js. Publishing our own bundle at
  // apply() makes every reload ship the current client half; unchanged files
  // keep the graph as-is (the call is a no-op), so this is safe on restart.
  try {
    const registry = ctx.clientModules;
    if (registry !== undefined && typeof registry.rebuilt === 'function') {
      // The client bundle is keyed by the PACKAGE name (what package.json
      // declares and the boot graph advertises), not by this loader row id.
      const rev = registry.rebuilt('dsh-plugin-workbuddy-intl');
      debugLog(`client bundle: rebuilt -> ${rev ?? '<unchanged>'}`);
    }
  } catch (error) {
    debugLog(`client bundle: rebuilt FAILED ${error?.message ?? error}`);
  }

  const getCatalog = () => {
    const current = options();
    const now = Date.now();
    if (cache === undefined || now - loadedAt > current.catalogRefreshMs) {
      cache = loadCatalog({
        workBuddyHome: current.workBuddyHome,
        accountConfigPath: current.accountConfigPath,
        baseProductJsonPath: current.baseProductJsonPath,
        scope: current.scope,
        includeBaseOnly: current.includeBaseOnly,
        onlyModels: current.onlyModels,
      });
      loadedAt = now;
      // A model that left the catalog (or lost its adjustable lengths) can no
      // longer honour a stored choice, so drop it rather than carry it forever.
      try {
        selections.prune(cache.models.map((model) => model.id));
      } catch {
        /* pruning is best-effort; a stale entry is ignored at resolve time */
      }
      ctx.logger?.info?.(`llm-workbuddy-intl: loaded ${cache.models.length} models from ${cache.source ?? '<none>'}`);
    }
    return cache;
  };

  // The plugin's own credential, obtained through the device-authorization
  // login in login.js. Refresh happens transparently: an expired access token
  // is exchanged for a fresh one before the request goes out, so a signed-in
  // plugin keeps working without the user re-authorizing.
  const loginClient = new WorkBuddyLoginClient();
  let credential = readCredential(options().authPath);
  let refreshInFlight;

  const persist = (next) => {
    credential = next;
    try {
      writeCredential(next, options().authPath);
    } catch (error) {
      debugLog(`auth: persist FAILED ${error?.message ?? error}`);
    }
  };

  /** A fresh access token, refreshing (and persisting) when it has expired. */
  const ensureFreshToken = async () => {
    const state = credentialState(credential);
    if (state.state === 'signed-in') return credential;
    if (state.state === 'signed-out') {
      throw new WorkBuddyError(
        `workbuddy-intl: not signed in. Run \`dsh plugin --profile web exec dsh-plugin-workbuddy-intl login\`, `
        + 'or use the login button in the plugin settings card. Signing in opens a browser page; '
        + 'no API key and no WorkBuddy desktop app are required.',
        'MISSING_CREDENTIAL',
      );
    }
    if (credential?.refreshToken === undefined || credential.refreshToken === '') {
      throw new WorkBuddyError(
        'workbuddy-intl: the stored token expired and carries no refresh token; sign in again',
        'AUTH',
      );
    }
    // Coalesce concurrent turns: one refresh serves them all, and the second
    // caller observes the already-refreshed credential.
    if (refreshInFlight === undefined) {
      refreshInFlight = (async () => {
        debugLog('auth: refreshing expired access token');
        const outcome = await loginClient.refresh(credential);
        persist({
          ...credential,
          accessToken: outcome.accessToken,
          refreshToken: outcome.refreshToken ?? credential.refreshToken,
          expiresAtMs: outcome.expiresInSec !== undefined
            ? Date.now() + outcome.expiresInSec * 1000
            : credential.expiresAtMs,
          domain: outcome.domain ?? credential.domain,
        });
        debugLog('auth: refresh ok');
      })().finally(() => { refreshInFlight = undefined; });
    }
    await refreshInFlight;
    return credential;
  };

  const resolveConnection = async () => {
    const current = options();
    const refName = typeof current.apiKeyEnv === 'string' && current.apiKeyEnv.length > 0
      ? current.apiKeyEnv
      : DEFAULT_TOKEN_REF;

    // 1. An explicitly pasted token still wins: a user who keeps control of
    //    the credential is never overridden by the plugin's own login.
    const credentials = ctx.get('credentials');
    if (credentials !== undefined && CREDENTIAL_REF_PATTERN.test(refName)) {
      const hit = await credentials.resolve(refName).catch(() => undefined);
      if (hit !== undefined && typeof hit.value === 'string') {
        const token = normalizeToken(assertUsableToken(hit.value, refName));
        const expiry = tokenExpiry(token);
        if (expiry !== undefined && expiry <= Date.now()) {
          throw new WorkBuddyError(
            `workbuddy-intl: the pasted token expired at ${new Date(expiry).toISOString()}; `
            + 'paste a fresh one, or sign in through the plugin so it refreshes itself',
            'AUTH',
          );
        }
        const userId = current.userId.length > 0 ? current.userId : userIdFromToken(token);
        return { baseURL: current.baseURL, token, userId, source: `stored credential ${refName}` };
      }
    }
    const ambient = process.env[refName];
    if (typeof ambient === 'string' && ambient.length > 0) {
      const token = normalizeToken(assertUsableToken(ambient, refName));
      const userId = current.userId.length > 0 ? current.userId : userIdFromToken(token);
      return { baseURL: current.baseURL, token, userId, source: `environment ${refName}` };
    }

    // 2. The plugin's own device-authorization login.
    const fresh = await ensureFreshToken();
    return {
      baseURL: current.baseURL,
      token: fresh.accessToken,
      userId: fresh.uid ?? '',
      source: 'plugin login',
    };
  };

  // No quota indicator on the international edition: the domestic
  // `/billing/meter/get-user-resource-free-packages` endpoint is served by
  // www.workbuddy.cn and its package codes are domestic free-tier grants, so it
  // does not apply to a workbuddy.ai account. The client half is shared with
  // the domestic plugin and renders nothing when this route reports `null`.
  const fetchQuota = async () => null;

  // Image blocks carry only a durable reference (no bytes), so the adapter needs
  // a way to read them back. The host attachments service is reached by name and
  // duck-typed: importing it would re-introduce the resolution failure this
  // plugin avoids, since a plugin must stay import-free of host packages.
  const attachments = {
    async imageDataUrl(ref) {
      const service = ctx.get('attachments');
      if (service === undefined) return undefined;
      const hostPath = typeof service.imageHostPath === 'function'
        ? service.imageHostPath(ref)
        : undefined;
      if (typeof hostPath !== 'string' || hostPath.length === 0) return undefined;
      const bytes = await fs.promises.readFile(hostPath).catch(() => undefined);
      if (bytes === undefined) return undefined;
      const mediaType = ref?.mediaType ?? 'image/png';
      return `data:${mediaType};base64,${bytes.toString('base64')}`;
    },
  };

  const adapter = new WorkBuddyAdapter({
    provider,
    displayName: options().displayName,
    multiplierInName: options().multiplierInName,
    reasoningEffortField: options().reasoningEffortField,
    requestTimeoutMs: options().requestTimeoutMs,
    rateLimitMinGapMs: options().rateLimitMinGapMs,
    rateLimitRetries: options().rateLimitRetries,
    defaultContextWindow: options().defaultContextWindow,
    defaultMaxTokens: options().defaultMaxTokens,
    identityHeaders: () => identityHeadersFor(options()),
    getCatalog,
    selections,
    resolveConnection,
    attachments,
    // Diagnostics only: a request the runtime retries is otherwise invisible,
    // so every wire failure is appended to the debug log with its status and
    // the gateway's own message (which carries the business code, e.g. 14003).
    onFailure: ({ url, status, code, detail }) => {
      debugLog(`request FAILED: [${code}] HTTP ${status} url=${url} detail=${detail}`);
    },
  });

  const settingsNs = ctx.fiber.entry?.options.id ?? name;
  debugLog(`settings: ns=${settingsNs}`);
  ctx.llm.registerConfigurableProviders([{
    provider,
    displayName: options().displayName,
    settingsNs,
    settingsPath: [],
  }]);
  ctx.llm.registerAdapter([provider], adapter);

  // Startup self-check: proves the module loaded, the catalog read, and whether
  // a token is resolvable — the three things that fail silently otherwise.
  debugLog(`apply: provider=${provider} scope=${options().scope} baseURL=${options().baseURL}`);
  try {
    const loaded = getCatalog();
    debugLog(`catalog: ${loaded.models.length} models from ${loaded.source ?? '<none>'} stamp=${CATALOG_STAMP}`);
  } catch (error) {
    debugLog(`catalog FAILED: ${error?.message ?? error}`);
  }
  void resolveConnection().then(
    (connection) => debugLog(`token: resolved from ${connection.source ?? 'unknown'} userId=${connection.userId ? '<set>' : '<missing>'}`),
    (error) => debugLog(`token FAILED: [${error?.code ?? '?'}] ${error?.message ?? error}`),
  );

  /**
   * The context-length view the client renders: every catalog model with the
   * lengths it offers (or none, when it is not adjustable) and the budget now in
   * force for it.
   *
   * `provider`/`providerName` identify the owning provider group: the unified
   * picker fetches this route alongside the OpenCode one and groups rows under
   * these headings (the 上级分类), so the payload must name itself.
   */
  const contextWindowView = () => {
    const catalog = getCatalog();
    return {
      provider,
      providerName: options().displayName,
      storePath: storePath.length > 0 ? storePath : undefined,
      models: catalog.models.map((model) => {
        const options = optionsFor(model);
        const selected = selections.get(model.id);
        return {
          id: model.id,
          name: model.name,
          displayName: model.displayName ?? model.name,
          adjustable: options !== undefined,
          ...(options === undefined ? {} : { options }),
          selected: selected ?? null,
          effective: effectiveContextWindow(model, selected) ?? null,
        };
      }),
    };
  };

  /**
   * Commit one model's context length.
   *
   * The value is validated against that model's own supported lengths rather
   * than merely being a positive integer: a client must not be able to widen a
   * model past the ceiling the WorkBuddy catalogue declares for it.
   */
  const setContextWindow = (modelId, value) => {
    const catalog = getCatalog();
    const model = catalog.models.find((entry) => entry.id === modelId);
    if (model === undefined) {
      return { error: `unknown model "${modelId}"` };
    }
    if (!isAdjustable(model)) {
      return { error: `model "${modelId}" has no adjustable context window` };
    }
    if (value === null) {
      selections.set(model.id, undefined);
      return { ok: true, model: model.id, effective: effectiveContextWindow(model, undefined) ?? null };
    }
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
      return { error: `"${String(value)}" is not a context length` };
    }
    const allowed = optionsFor(model);
    if (!allowed.includes(value)) {
      return { error: `${value} is not offered by "${modelId}" (allowed: ${allowed.join(', ')})` };
    }
    selections.set(model.id, value);
    debugLog(`context: ${model.id} -> ${value}`);
    return { ok: true, model: model.id, effective: value };
  };

  /** Read a JSON request body, tolerating an empty or malformed one. */
  const readJsonBody = (req) => new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      // A picker payload is a few hundred bytes; anything larger is a mistake or
      // an attack, and must not be buffered.
      if (raw.length > 64 * 1024) {
        raw = '';
        resolve(undefined);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (raw.length === 0) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve(undefined);
      }
    });
    req.on('error', () => resolve(undefined));
  });

  // Quota endpoint for the Web input-box indicator. The client half fetches
  // `/workbuddy/quota` (same-origin, authenticated by the browser cookie); this
  // host half owns the WorkBuddy token, so the access token never reaches the
  // browser. Register through the optional web carrier so this plugin also
  // works in a headless (cli) scope without a webServer.
  debugLog('route: requesting webServer+connection');
  ctx.inject(['webServer', 'connection'], (webCtx) => {
    debugLog('route: inject callback entered');
    webCtx.effect(() => {
      try {
        const dispose = webCtx.webServer.register({
          kind: 'exact',
          path: '/workbuddy-intl/quota',
          handler: async (req, res) => {
            const admission = webCtx.connection.admit(req);
            if ('rejection' in admission) {
              res.writeHead(admission.rejection);
              res.end(admission.rejection === 401 ? 'unauthorized' : 'forbidden');
              return;
            }
            try {
              const quota = await fetchQuota();
              res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
              res.end(JSON.stringify(quota));
            } catch (error) {
              res.writeHead(502);
              res.end(JSON.stringify({ error: error?.message ?? String(error) }));
            }
          },
        });
        // Context-length selection. GET reports what each model offers and what is
        // in force; POST commits one model's choice after host-side validation.
        const disposeContext = webCtx.webServer.register({
          kind: 'exact',
          path: '/workbuddy-intl/context-window',
          handler: async (req, res) => {
            const admission = webCtx.connection.admit(req);
            if ('rejection' in admission) {
              res.writeHead(admission.rejection);
              res.end(admission.rejection === 401 ? 'unauthorized' : 'forbidden');
              return;
            }
            const send = (status, payload) => {
              res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
              res.end(JSON.stringify(payload));
            };
            try {
              if ((req.method ?? 'GET').toUpperCase() === 'GET') {
                send(200, contextWindowView());
                return;
              }
              if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
                send(405, { error: 'method not allowed' });
                return;
              }
              const body = await readJsonBody(req);
              if (body === undefined || typeof body.model !== 'string') {
                send(400, { error: 'expected a JSON body with a "model" field' });
                return;
              }
              const value = body.contextWindow === null ? null : body.contextWindow;
              const result = setContextWindow(body.model, value);
              if (result.error !== undefined) {
                send(400, { error: result.error });
                return;
              }
              send(200, result);
            } catch (error) {
              debugLog(`context: route FAILED ${error?.message ?? error}`);
              send(500, { error: error?.message ?? String(error) });
            }
          },
        });
        debugLog('route: /workbuddy-intl/quota + /workbuddy-intl/context-window registered');
        return () => {
          dispose();
          disposeContext();
        };
      } catch (error) {
        debugLog(`route: FAILED ${error?.message ?? error}`);
        throw error;
      }
    }, 'llm-workbuddy-intl: /workbuddy-intl routes');
  });
}

export { Config, apply, inject, name };
