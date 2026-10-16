const B2_SERVICE = 's3';
const EMPTY_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

// ── B2 account configuration ──────────────────────────────────
// Multi-account support: each entry below becomes a URL prefix on
// the worker:  /<accountName>/<bucket>/<key>...
//
// Define accounts here in code, or set the B2_ACCOUNTS environment
// variable (JSON) in the Worker settings — the env variable takes
// precedence and keeps credentials out of source code.
//
// B2_ACCOUNTS example:
//   {"main":{"endpoint":"s3.us-west-004.backblazeb2.com","region":"us-west-004","keyId":"...","applicationKey":"...","label":"Main"}}
//
// The legacy single-account env vars (B2_ENDPOINT, B2_REGION,
// B2_KEY_ID, B2_APPLICATION_KEY) still work when no named accounts
// are configured — URLs then keep the old /<bucket>/<key> shape.
const ACCOUNTS = {
  // 'account01': {
  //   endpoint: 's3.us-west-004.backblazeb2.com',
  //   region: 'us-west-004',
  //   keyId: 'YOUR_KEY_ID',
  //   applicationKey: 'YOUR_APPLICATION_KEY',
  //   label: 'Account 01' // optional display name
  // },
  // 'account02': {
  //   endpoint: 's3.us-west-004.backblazeb2.com',
  //   region: 'us-west-004',
  //   keyId: 'YOUR_KEY_ID',
  //   applicationKey: 'YOUR_APPLICATION_KEY',
  //   label: 'Account 02'
  // },
  // 'account03': {
  //   endpoint: 's3.us-west-004.backblazeb2.com',
  //   region: 'us-west-004',
  //   keyId: 'YOUR_KEY_ID',
  //   applicationKey: 'YOUR_APPLICATION_KEY',
  //   label: 'Account 03'
  // },
  // 'account04': {
  //   endpoint: 's3.us-west-004.backblazeb2.com',
  //   region: 'us-west-004',
  //   keyId: 'YOUR_KEY_ID',
  //   applicationKey: 'YOUR_APPLICATION_KEY',
  //   label: 'Account 04'
  // },
  // 'account05': {
  //   endpoint: 's3.us-west-004.backblazeb2.com',
  //   region: 'us-west-004',
  //   keyId: 'YOUR_KEY_ID',
  //   applicationKey: 'YOUR_APPLICATION_KEY',
  //   label: 'Account 05'
  // }
};

// ── CORS configuration ────────────────────────────────────────
// Set CORS_ORIGIN to a specific origin (e.g. 'https://example.com')
// or '*' for any origin. You can also set the CORS_ORIGIN env var
// in Worker settings to override this at deploy time.
const DEFAULT_CORS_ORIGIN = '*';

function loadAccounts(env) {
  if (env.B2_ACCOUNTS) {
    try {
      const parsed = JSON.parse(env.B2_ACCOUNTS);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (e) {
      // Invalid JSON in B2_ACCOUNTS — fall back to the static config.
    }
  }
  return ACCOUNTS;
}

function hasLegacyAccount(env) {
  return Boolean(
    env.B2_ENDPOINT && env.B2_REGION &&
    env.B2_KEY_ID && env.B2_APPLICATION_KEY
  );
}

function legacyAccount(env) {
  return {
    endpoint: env.B2_ENDPOINT,
    region: env.B2_REGION,
    keyId: env.B2_KEY_ID,
    applicationKey: env.B2_APPLICATION_KEY,
    label: env.B2_LABEL || undefined
  };
}

function decodePathPart(part) {
  try {
    return decodeURIComponent(part);
  } catch (e) {
    return part;
  }
}

// ── CORS helpers ─────────────────────────────────────────────

function corsOrigin(env) {
  return env.CORS_ORIGIN || DEFAULT_CORS_ORIGIN;
}

// Headers that allow the browser to read cross-origin responses.
// Expose Content-Range and Content-Length so JS players can read
// range info; Accept-Ranges so they know seeking is supported.
function corsHeaders(env) {
  const origin = corsOrigin(env);
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Range, If-Range, If-None-Match, If-Modified-Since',
    'Access-Control-Expose-Headers': 'Content-Range, Content-Length, Accept-Ranges, ETag, Last-Modified',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}

// Apply CORS headers to an existing Headers object (mutates it).
function applyCorsToHeaders(headers, env) {
  const cors = corsHeaders(env);
  for (const [k, v] of Object.entries(cors)) {
    headers.set(k, v);
  }
  return headers;
}

// ── AWS Signature V4 helpers ──────────────────────────────────

async function hmacSha256(key, message) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  return crypto.subtle.sign('HMAC', cryptoKey, enc.encode(message));
}

function bufferToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmacSha256Hex(key, message) {
  return bufferToHex(await hmacSha256(key, message));
}

async function sha256Hex(message) {
  const enc = new TextEncoder();
  return bufferToHex(
    await crypto.subtle.digest('SHA-256', enc.encode(message))
  );
}

async function getSigningKey(secretKey, date, region, service) {
  const kDate = await hmacSha256(
    new TextEncoder().encode('AWS4' + secretKey),
    date
  );
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);

  return hmacSha256(kService, 'aws4_request');
}

function awsEncode(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    c => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

function buildCanonicalQueryString(searchParams) {
  const params = [];

  for (const [key, value] of searchParams.entries()) {
    params.push([awsEncode(key), awsEncode(value)]);
  }

  params.sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 :
    a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0
  );

  return params.map(p => p[0] + '=' + p[1]).join('&');
}

async function createSignedHeaders(
  method,
  targetUrl,
  body,
  accessKey,
  secretKey,
  region,
  extraHeaders = {}
) {
  const parsedUrl = new URL(targetUrl);
  const datetime = new Date()
    .toISOString()
    .replace(/[:-]|\.\d{3}/g, '');
  const date = datetime.substring(0, 8);

  const contentSha256 = body
    ? await sha256Hex(body)
    : EMPTY_SHA256;

  // Start with mandatory SigV4 headers, then merge any extra headers
  // (e.g. Range, If-Range, If-None-Match, If-Modified-Since) so they are
  // included in the canonical request and covered by the signature.
  const headersToSign = {
    host: parsedUrl.host,
    'x-amz-content-sha256': contentSha256,
    'x-amz-date': datetime
  };

  // Normalize extra header keys to lowercase and merge.
  for (const [k, v] of Object.entries(extraHeaders)) {
    headersToSign[k.toLowerCase()] = v;
  }

  const sortedKeys = Object.keys(headersToSign).sort();

  const canonicalHeaders = sortedKeys
    .map(k => k + ':' + headersToSign[k].trim() + '\n')
    .join('');

  const signedHeaders = sortedKeys.join(';');

  const canonicalRequest = [
    method,
    parsedUrl.pathname,
    buildCanonicalQueryString(parsedUrl.searchParams),
    canonicalHeaders,
    signedHeaders,
    contentSha256
  ].join('\n');

  const credentialScope =
    date + '/' + region + '/' + B2_SERVICE + '/aws4_request';

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    datetime,
    credentialScope,
    await sha256Hex(canonicalRequest)
  ].join('\n');

  const signingKey = await getSigningKey(
    secretKey,
    date,
    region,
    B2_SERVICE
  );

  const signature = await hmacSha256Hex(signingKey, stringToSign);

  const authorization =
    'AWS4-HMAC-SHA256 Credential=' +
    accessKey + '/' + credentialScope +
    ', SignedHeaders=' + signedHeaders +
    ', Signature=' + signature;

  // Build the final headers object with proper casing.
  const result = {
    Host: parsedUrl.host,
    'x-amz-content-sha256': contentSha256,
    'x-amz-date': datetime,
    Authorization: authorization
  };

  for (const [k, v] of Object.entries(extraHeaders)) {
    result[k] = v;
  }

  return result;
}

// ── HTML and XML helpers ──────────────────────────────────────

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[ch]);
}

function decodeXml(value) {
  return value.replace(
    /&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi,
    (match, entity) => {
      if (entity === 'amp') return '&';
      if (entity === 'lt') return '<';
      if (entity === 'gt') return '>';
      if (entity === 'quot') return '"';
      if (entity === 'apos') return "'";

      if (entity.startsWith('#x')) {
        return String.fromCodePoint(parseInt(entity.slice(2), 16));
      }

      if (entity.startsWith('#')) {
        return String.fromCodePoint(parseInt(entity.slice(1), 10));
      }

      return match;
    }
  );
}

function xmlTag(block, tag) {
  const match = block.match(
    new RegExp('<' + tag + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + tag + '>')
  );

  return match ? decodeXml(match[1]) : '';
}

// URL helpers. accountName is null in legacy single-account mode.
function accountUrl(accountName) {
  return '/' + encodeURIComponent(accountName) + '/';
}

function bucketUrl(accountName, bucketName) {
  return accountName
    ? accountUrl(accountName) + encodeURIComponent(bucketName)
    : '/' + encodeURIComponent(bucketName);
}

function objectPath(accountName, bucketName, key) {
  return bucketUrl(accountName, bucketName) + '/' +
    key.split('/').map(encodeURIComponent).join('/');
}

function renderError(status, xmlText) {
  return new Response(xmlText, {
    status,
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

// ── HTML file listing renderer ────────────────────────────────

function renderListing(bucketName, prefix, xmlText, accountName) {
  const items = [
    ...xmlText.matchAll(/<Contents(?:\s[^>]*)?>([\s\S]*?)<\/Contents>/g)
  ].map(([, block]) => ({
    key: xmlTag(block, 'Key'),
    size: Number(xmlTag(block, 'Size') || 0),
    modified: xmlTag(block, 'LastModified')
  })).filter(item => item.key !== '');

  const prefixes = [
    ...xmlText.matchAll(
      /<CommonPrefixes(?:\s[^>]*)?>([\s\S]*?)<\/CommonPrefixes>/g
    )
  ].map(([, block]) => xmlTag(block, 'Prefix')).filter(Boolean);

  const parentPrefix = prefix
    ? prefix.replace(/\/$/, '').split('/').slice(0, -1).join('/')
    : '';

  const parentUrl = parentPrefix
    ? objectPath(accountName, bucketName, parentPrefix + '/')
    : bucketUrl(accountName, bucketName);

  let html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(bucketName)}</title>
<style>
body {
  font-family: system-ui, sans-serif;
  max-width: 1000px;
  margin: 2rem auto;
  padding: 0 1rem;
  color: #222;
}
h1 { overflow-wrap: anywhere; }
table { width: 100%; border-collapse: collapse; }
th, td {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 1px solid #eee;
  overflow-wrap: anywhere;
}
th { background: #f7f7f7; }
a { color: #d96b00; text-decoration: none; }
a:hover { text-decoration: underline; }
.size, .modified { white-space: nowrap; }
@media(max-width:600px) {
  th, td { padding: 8px 4px; font-size: 13px; }
  .modified { white-space: normal; }
}
</style>
</head>
<body>
<h1>📦 ${escapeHtml(bucketName)}</h1>
<p><a href="${accountName ? accountUrl(accountName) : '/'}">← Buckets</a>`;

  if (prefix) {
    html += ` / <a href="${parentUrl}">Parent folder</a> / ${
      escapeHtml(prefix)
    }`;
  } else {
    html += ' /';
  }

  html += `</p>
<table>
<thead>
<tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>
</thead>
<tbody>`;

  for (const name of prefixes) {
    const display = name.startsWith(prefix)
      ? name.slice(prefix.length)
      : name;

    html += `<tr>
<td><a href="${objectPath(accountName, bucketName, name)}">📁 ${
      escapeHtml(display)
    }</a></td>
<td>—</td>
<td>—</td>
</tr>`;
  }

  for (const item of items) {
    if (item.key === prefix) continue;

    const display = item.key.startsWith(prefix)
      ? item.key.slice(prefix.length)
      : item.key;

    const size = item.size;
    const sizeStr = size >= 1048576
      ? (size / 1048576).toFixed(1) + ' MB'
      : size >= 1024
        ? (size / 1024).toFixed(1) + ' KB'
        : size + ' B';

    html += `<tr>
<td><a href="${objectPath(accountName, bucketName, item.key)}">📄 ${
      escapeHtml(display)
    }</a></td>
<td class="size">${sizeStr}</td>
<td class="modified">${escapeHtml(item.modified)}</td>
</tr>`;
  }

  if (items.length === 0 && prefixes.length === 0) {
    html += `<tr><td colspan="3">No files found in this folder.</td></tr>`;
  }

  html += `</tbody></table></body></html>`;

  return html;
}

function renderBuckets(xmlText, accountName, label) {
  const buckets = [
    ...xmlText.matchAll(/<Bucket(?:\s[^>]*)?>([\s\S]*?)<\/Bucket>/g)
  ].map(([, block]) => xmlTag(block, 'Name')).filter(Boolean);

  const heading = label || (accountName || 'B2 Buckets');

  let html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(heading)}</title>
<style>
body { font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem; }
a { color:#d96b00;text-decoration:none; }
a:hover { text-decoration:underline; }
li { margin:12px 0; }
</style>
</head>
<body>
<h1>📦 ${escapeHtml(heading)}</h1>`;

  if (accountName) {
    html += `<p><a href="/">← Accounts</a></p>`;
  }

  html += `<ul>`;

  for (const bucket of buckets) {
    html += `<li><a href="${bucketUrl(accountName, bucket)}">📁 ${
      escapeHtml(bucket)
    }</a></li>`;
  }

  html += `</ul></body></html>`;
  return html;
}

function renderAccounts(accounts) {
  const names = Object.keys(accounts);

  let html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>B2 Accounts</title>
<style>
body { font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem; }
a { color:#d96b00;text-decoration:none; }
a:hover { text-decoration:underline; }
li { margin:12px 0; }
</style>
</head>
<body>
<h1>📦 Backblaze B2 Accounts</h1>
<ul>`;

  for (const name of names) {
    const label = accounts[name].label || name;
    html += `<li><a href="${accountUrl(name)}">📁 ${
      escapeHtml(label)
    }</a></li>`;
  }

  html += `</ul></body></html>`;
  return html;
}

// ── Main Cloudflare Worker ────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;

    // ── Handle CORS preflight (OPTIONS) ──────────────────────
    // Browsers send an OPTIONS preflight before cross-origin
    // fetch() / XHR / crossorigin video requests. Respond with
    // the allowed methods and headers so the real request follows.
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(env)
      });
    }

    const cacheTTL = Math.max(
      0,
      Number.parseInt(env.CACHE_TTL || '86400', 10) || 0
    );

    const accounts = loadAccounts(env);
    const accountNames = Object.keys(accounts);
    const multiAccount = accountNames.length > 0;
    const legacy = hasLegacyAccount(env) ? legacyAccount(env) : null;

    if (!multiAccount && !legacy) {
      return new Response('Worker configuration is incomplete.', {
        status: 500
      });
    }

    if (!['GET', 'HEAD', 'PUT', 'POST', 'DELETE'].includes(method)) {
      return new Response('Method not allowed', {
        status: 405,
        headers: { Allow: 'GET, HEAD, PUT, POST, DELETE' }
      });
    }

    const pathParts = url.pathname
      .split('/')
      .filter(Boolean)
      .map(decodePathPart);
    const acceptHtml =
      request.headers.get('Accept')?.includes('text/html') ?? false;

    // Root: account index (multi-account) or bucket list (legacy).
    if (pathParts.length === 0) {
      if (multiAccount) {
        return new Response(renderAccounts(accounts), {
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store'
          }
        });
      }

      const b2Url = 'https://' + legacy.endpoint + '/';

      const signedHeaders = await createSignedHeaders(
        'GET',
        b2Url,
        '',
        legacy.keyId,
        legacy.applicationKey,
        legacy.region
      );

      const resp = await fetch(b2Url, {
        method: 'GET',
        headers: signedHeaders
      });

      const xmlText = await resp.text();

      if (!resp.ok) return renderError(resp.status, xmlText);

      if (!acceptHtml) {
        return new Response(xmlText, {
          headers: { 'Content-Type': 'application/xml; charset=utf-8' }
        });
      }

      return new Response(renderBuckets(xmlText, null, legacy.label), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store'
        }
      });
    }

    // Resolve the account and the bucket/key segments.
    let account;
    let accountName = null;
    let bucketName;
    let prefix;

    if (multiAccount) {
      accountName = pathParts[0];
      account = accounts[accountName];

      if (!account) {
        return new Response('Unknown B2 account: ' + accountName, {
          status: 404,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }

      bucketName = pathParts[1];
      prefix = pathParts.slice(2).join('/');
    } else {
      account = legacy;
      bucketName = pathParts[0];
      prefix = pathParts.slice(1).join('/');
    }

    const endpoint = account.endpoint;
    const region = account.region;

    // Preserve the trailing slash for folder listing requests.
    if (url.pathname.endsWith('/') && prefix && !prefix.endsWith('/')) {
      prefix += '/';
    }

    const isListingRequest =
      url.pathname.endsWith('/') ||
      (multiAccount ? pathParts.length <= 2 : pathParts.length <= 1);

    // Bucket/folder listing.
    if (
      isListingRequest &&
      (method === 'GET' || method === 'HEAD')
    ) {
      // Account root: list buckets.
      if (!bucketName) {
        const b2Url = 'https://' + endpoint + '/';

        const signedHeaders = await createSignedHeaders(
          'GET',
          b2Url,
          '',
          account.keyId,
          account.applicationKey,
          region
        );

        const resp = await fetch(b2Url, {
          method: 'GET',
          headers: signedHeaders
        });

        const xmlText = await resp.text();

        if (!resp.ok) return renderError(resp.status, xmlText);

        if (!acceptHtml) {
          return new Response(method === 'HEAD' ? null : xmlText, {
            status: resp.status,
            headers: {
              'Content-Type': 'application/xml; charset=utf-8',
              'Cache-Control': 'no-store'
            }
          });
        }

        return new Response(
          method === 'HEAD'
            ? null
            : renderBuckets(xmlText, accountName, account.label),
          {
            status: resp.status,
            headers: {
              'Content-Type': 'text/html; charset=utf-8',
              'Cache-Control': 'no-store'
            }
          }
        );
      }

      const listParams = new URLSearchParams();
      listParams.set('list-type', '2');
      listParams.set('delimiter', '/');

      if (prefix) listParams.set('prefix', prefix);

      const b2Url =
        'https://' + endpoint + '/' +
        awsEncode(bucketName) + '?' + listParams.toString();

      const signedHeaders = await createSignedHeaders(
        'GET',
        b2Url,
        '',
        account.keyId,
        account.applicationKey,
        region
      );

      const b2Response = await fetch(b2Url, {
        method: 'GET',
        headers: signedHeaders
      });

      const xmlText = await b2Response.text();

      if (!b2Response.ok) {
        return renderError(b2Response.status, xmlText);
      }

      if (!acceptHtml) {
        return new Response(method === 'HEAD' ? null : xmlText, {
          status: b2Response.status,
          headers: {
            'Content-Type': 'application/xml; charset=utf-8',
            'Cache-Control': 'no-store'
          }
        });
      }

      return new Response(
        method === 'HEAD'
          ? null
          : renderListing(bucketName, prefix, xmlText, accountName),
        {
          status: b2Response.status,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store'
          }
        }
      );
    }

    // ── File proxy with HTTP Range support ───────────────────
    // Rebuild the B2 path from the decoded segments (dropping the
    // account prefix) and preserve the incoming query string.
    const keyParts = multiAccount
      ? pathParts.slice(2)
      : pathParts.slice(1);

    const b2Url =
      'https://' + endpoint + '/' +
      awsEncode(bucketName) + '/' +
      keyParts.map(awsEncode).join('/') + url.search;

    // Collect Range and conditional headers from the client request.
    // These are forwarded to B2 AND included in the SigV4 signature.
    const rangeHeader = request.headers.get('Range');
    const ifRangeHeader = request.headers.get('If-Range');
    const ifNoneMatchHeader = request.headers.get('If-None-Match');
    const ifModifiedSinceHeader = request.headers.get('If-Modified-Since');

    const cache = caches.default;
    const cacheKey = new Request(url.toString(), { method: 'GET' });

    // Only cache full-object GET responses (no Range, no conditional
    // headers). Range requests must go to origin for a proper 206.
    const isConditionalRequest =
      rangeHeader ||
      ifRangeHeader ||
      ifNoneMatchHeader ||
      ifModifiedSinceHeader;

    const canUseCache =
      method === 'GET' &&
      !isConditionalRequest &&
      cacheTTL > 0;

    if (canUseCache) {
      const cached = await cache.match(cacheKey);

      if (cached) {
        const headers = new Headers(cached.headers);
        headers.set('CF-Cache-Status', 'HIT');
        // Ensure Accept-Ranges is present on cache hits too.
        if (!headers.has('Accept-Ranges')) {
          headers.set('Accept-Ranges', 'bytes');
        }
        // Add CORS headers to cached responses too.
        applyCorsToHeaders(headers, env);

        return new Response(cached.body, {
          status: cached.status,
          statusText: cached.statusText,
          headers
        });
      }
    }

    const body =
      method !== 'GET' && method !== 'HEAD'
        ? await request.text()
        : '';

    // Build the set of extra headers to sign alongside the mandatory
    // SigV4 headers. Including Range in the signature ensures B2
    // honours the byte-range request reliably.
    const extraHeaders = {};

    if (rangeHeader) extraHeaders['range'] = rangeHeader;
    if (ifRangeHeader) extraHeaders['if-range'] = ifRangeHeader;
    if (ifNoneMatchHeader) extraHeaders['if-none-match'] = ifNoneMatchHeader;
    if (ifModifiedSinceHeader) extraHeaders['if-modified-since'] = ifModifiedSinceHeader;

    const signedHeaders = await createSignedHeaders(
      method,
      b2Url,
      body,
      account.keyId,
      account.applicationKey,
      region,
      extraHeaders
    );

    const b2Response = await fetch(b2Url, {
      method,
      headers: signedHeaders,
      body: body || undefined
    });

    // Cache complete successful GET responses only (status 200, no
    // Range or conditional headers in the original request).
    if (
      canUseCache &&
      b2Response.status === 200
    ) {
      const toCache = b2Response.clone();
      const cacheHeaders = new Headers(toCache.headers);

      cacheHeaders.set('Cache-Control', 'public, max-age=' + cacheTTL);
      // Store Accept-Ranges in the cached copy so cache hits
      // advertise byte-range support to media players.
      cacheHeaders.set('Accept-Ranges', 'bytes');
      // Store CORS headers in the cached copy so cache hits
      // include them without re-applying.
      applyCorsToHeaders(cacheHeaders, env);

      ctx.waitUntil(
        cache.put(
          cacheKey,
          new Response(toCache.body, {
            status: toCache.status,
            statusText: toCache.statusText,
            headers: cacheHeaders
          })
        )
      );
    }

    // Build the response headers to send back to the client.
    const responseHeaders = new Headers(b2Response.headers);

    // Always advertise byte-range support on file responses so media
    // players know they can issue Range requests for seeking.
    if (!responseHeaders.has('Accept-Ranges')) {
      responseHeaders.set('Accept-Ranges', 'bytes');
    }

    responseHeaders.set(
      'CF-Cache-Status',
      canUseCache ? 'MISS' : 'BYPASS'
    );

    // ── Apply CORS headers to all file responses ────────────
    // This enables cross-origin fetch(), XHR, crossorigin video,
    // and canvas drawImage access from other origins.
    applyCorsToHeaders(responseHeaders, env);

    // For 304 Not Modified responses, return an empty body with the
    // correct status and headers (B2 sends these in response to
    // If-None-Match / If-Modified-Since conditional requests).
    if (b2Response.status === 304) {
      return new Response(null, {
        status: 304,
        statusText: b2Response.statusText,
        headers: responseHeaders
      });
    }

    // For HEAD requests, return headers only — no body. Media
    // players use HEAD to probe Content-Length and Accept-Ranges
    // before issuing Range requests for seeking.
    if (method === 'HEAD') {
      return new Response(null, {
        status: b2Response.status,
        statusText: b2Response.statusText,
        headers: responseHeaders
      });
    }

    // For 206 Partial Content (Range requests) and 200 (full
    // object), stream the body through. The Content-Range and
    // Content-Length headers from B2 are already in responseHeaders.
    return new Response(b2Response.body, {
      status: b2Response.status,
      statusText: b2Response.statusText,
      headers: responseHeaders
    });
  }
};
