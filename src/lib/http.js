// Minimal HTTP plumbing: a router for services, a JSON client, and requests
// signed with RFC 9421 HTTP Message Signatures.
import http from 'node:http';
import { publicOf, JoseError } from './crypto.js';
import { signRequest, verifyRequest, SignatureError, DEFAULT_COMPONENTS } from './httpsig.js';

export class HttpError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function createApp(name) {
  const routes = [];
  const add = (method, pattern, handler) => {
    const keys = [];
    const regex = new RegExp(
      '^' +
        pattern.replace(/\/:([a-zA-Z_]+)/g, (_, k) => {
          keys.push(k);
          return '/([^/]+)';
        }) +
        '$',
    );
    routes.push({ method, regex, keys, handler });
  };

  const handler = async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const route = routes.find((r) => r.method === req.method && r.regex.test(url.pathname));
    const send = (status, body, headers = {}) => {
      const isHtml = typeof body === 'string';
      res.writeHead(status, {
        'content-type': isHtml ? 'text/html; charset=utf-8' : 'application/json',
        'cache-control': 'no-store',
        ...headers,
      });
      res.end(isHtml ? body : JSON.stringify(body, null, 2));
    };
    if (!route) return send(404, { error: 'not_found', message: `${req.method} ${url.pathname}` });
    try {
      const match = url.pathname.match(route.regex);
      const params = Object.fromEntries(route.keys.map((k, i) => [k, decodeURIComponent(match[i + 1])]));
      let body = null;
      let raw = '';
      if (req.method !== 'GET') {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        raw = Buffer.concat(chunks).toString('utf8');
        if (raw && (req.headers['content-type'] ?? '').includes('application/x-www-form-urlencoded')) {
          body = Object.fromEntries(new URLSearchParams(raw)); // OAuth endpoints (RFC 6749 §3.2)
        } else if (raw) {
          try {
            body = JSON.parse(raw);
          } catch {
            throw new HttpError(400, 'invalid_json', 'request body is not valid JSON');
          }
        }
      }
      const ctx = { req, url, params, query: Object.fromEntries(url.searchParams), body, rawBody: raw, headers: req.headers };
      const result = await route.handler(ctx);
      if (result && result.__raw) return send(result.status ?? 200, result.body, result.contentType ? { ...result.headers, 'content-type': result.contentType } : result.headers);
      send(200, result ?? {});
    } catch (err) {
      if (err instanceof HttpError) return send(err.status, { error: err.code, message: err.message, details: err.details });
      if (err instanceof JoseError) return send(400, { error: err.code, message: err.message });
      console.error(`[${name}]`, err);
      send(500, { error: 'internal_error', message: err.message });
    }
  };

  return {
    get: (p, h) => add('GET', p, h),
    post: (p, h) => add('POST', p, h),
    put: (p, h) => add('PUT', p, h),
    handler,
    listen(port, host = '127.0.0.1') {
      const server = http.createServer({ maxHeaderSize: 64 * 1024 }, handler);
      return new Promise((resolve) => server.listen(port, host, () => resolve(server)));
    },
  };
}

export const html = (body, status = 200) => ({ __raw: true, status, body });
/** A non-JSON response such as an entity statement or a status list token. */
export const typed = (body, contentType, status = 200) => ({ __raw: true, status, body, contentType });

/**
 * Stop a server and drop its keep-alive connections, then give clients a
 * moment to notice, so a server restarted on the same port is not hit through
 * a stale pooled socket.
 */
export async function closeServer(server) {
  await new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  });
  await new Promise((resolve) => setTimeout(resolve, 50));
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class ServiceError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export async function callJson(method, url, body, headers = {}) {
  let res;
  try {
    res = await fetch(url, {
      method,
      headers: { 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
  } catch (err) {
    throw new ServiceError(0, 'unreachable', `could not reach ${url}: ${err.cause?.code ?? err.message}`);
  }
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new ServiceError(res.status, 'bad_response', `non-JSON response from ${url}`);
  }
  if (!res.ok) throw new ServiceError(res.status, json.error ?? 'error', json.message ?? res.statusText, json.details);
  return json;
}

export const getJson = (url, headers) => callJson('GET', url, undefined, headers);
export const postJson = (url, body, headers) => callJson('POST', url, body, headers);

// ---------------------------------------------------------------------------
// Signed requests: RFC 9421 HTTP Message Signatures over the method, target
// URI, Content-Digest (RFC 9530) and Content-Type. The target URI binds the
// request to the receiving service; created + nonce give replay protection.
// ---------------------------------------------------------------------------

export const REQUEST_SIGNATURE_TAG = 'aaf-request';

/**
 * Build a signed JSON request. keyid names the signer in the receiving
 * service's terms; with embedJwk the public key travels in the body as
 * signer_jwk and keyid becomes "jkt:<thumbprint>".
 */
export function buildSignedRequest(method, url, params, key, { keyid, embedJwk = false } = {}) {
  const payload = embedJwk ? { ...params, signer_jwk: publicOf(key.publicJwk) } : params;
  const body = JSON.stringify(payload ?? {});
  const headers = signRequest({
    method, url, body, key, keyid: embedJwk ? `jkt:${key.kid}` : keyid, tag: REQUEST_SIGNATURE_TAG,
    headers: { 'content-type': 'application/json' },
  });
  return { body, headers };
}

export async function sendSigned(method, url, params, key, opts) {
  const { body, headers } = buildSignedRequest(method, url, params, key, opts);
  let res;
  try {
    res = await fetch(url, { method, headers, body, signal: AbortSignal.timeout(5000) });
  } catch (err) {
    throw new ServiceError(0, 'unreachable', `could not reach ${url}: ${err.cause?.code ?? err.message}`);
  }
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    throw new ServiceError(res.status, 'bad_response', `non-JSON response from ${url}`);
  }
  if (!res.ok) throw new ServiceError(res.status, json.error ?? 'error', json.message ?? json.error_description ?? res.statusText, json.details);
  return json;
}

export const postSigned = (url, params, key, opts) => sendSigned('POST', url, params, key, opts);

/**
 * Server side. Returns verify(ctx, resolveKey) -> { header: { kid, jwk? }, payload, jwk, thumbprint }.
 * resolveKey({ kid }) is consulted only for named keyids; "jkt:" keys come from the body.
 *
 * publicBaseUrl: the base URL callers use to reach this service (its published
 * endpoint). Signatures cover the full target URI, so behind a TLS proxy the
 * service must reconstruct https://public-host/... rather than the http://
 * address it actually listens on.
 */
export function createSignatureVerifier({ publicBaseUrl } = {}) {
  const base = publicBaseUrl ? publicBaseUrl.replace(/\/$/, '') : null;
  const replay = new Map();
  return async function verifySigned(ctx, resolveKey) {
    let verified;
    try {
      verified = await verifyRequest({
        method: ctx.req.method,
        url: base ? `${base}${ctx.req.url}` : `http://${ctx.headers.host}${ctx.req.url}`,
        headers: ctx.headers,
        body: ctx.rawBody,
        resolveKey: (keyid) => resolveKey({ kid: keyid }),
        tag: REQUEST_SIGNATURE_TAG,
        required: DEFAULT_COMPONENTS,
        replay,
      });
    } catch (err) {
      if (err instanceof SignatureError) throw new HttpError(401, err.code, err.message);
      throw err;
    }
    const selfPresented = verified.keyid.startsWith('jkt:');
    const { signer_jwk: _ignored, ...payload } = ctx.body ?? {};
    return {
      header: { kid: verified.keyid, ...(selfPresented ? { jwk: verified.jwk } : {}) },
      payload,
      jwk: verified.jwk,
      thumbprint: verified.thumbprint,
    };
  };
}
