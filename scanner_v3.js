#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';

const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /warning.*mysql/i,
  /mysql.*server version/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /pg_query\(/i,
  /postgresql.*error/i,
  /syntax error at or near/i,
  /sqlite_error/i,
  /sqlite exception/i,
  /sqlstate/i,
  /odbc sql server driver/i,
  /microsoft ole db provider for sql server/i,
  /ora-\d{5}/i,
  /you have an error in your sql syntax/i
];

const INTERESTING_RESPONSE_HEADERS = [
  'server',
  'x-powered-by',
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'cache-control',
  'set-cookie'
];

const DEFAULT_PAYLOADS = [
  { type: 'error-quote', value: `'` },
  { type: 'delimiter', value: `;` },
  { type: 'boolean-true-str', value: `' AND '1'='1` },
  { type: 'boolean-false-str', value: `' AND '1'='2` },
  { type: 'boolean-true-num', value: `1 AND 1=1` },
  { type: 'boolean-false-num', value: `1 AND 1=2` }
];

const EXTENDED_PAYLOADS = [
  { type: 'union-probe', value: `' UNION SELECT NULL--` },
  { type: 'time-probe', value: `' OR SLEEP(3)--` },
  { type: 'comment-close', value: `')--` }
];

function parseArgs(argv) {
  const args = { headers: [] };
  for (const item of argv.slice(2)) {
    if (!item.startsWith('--')) {
      if (!args.target) args.target = item;
      continue;
    }
    const [key, rawVal = 'true'] = item.slice(2).split('=');
    if (key === 'header') args.headers.push(rawVal);
    else args[key] = rawVal;
  }

  const safeMode = String(args.safe ?? 'true') !== 'false';
  const includeExtendedPayloads = String(args['extended-payloads'] ?? 'false') === 'true';

  return {
    target: args.target,
    maxPages: Number(args['max-pages'] ?? 15),
    timeout: Number(args.timeout ?? 8000),
    delay: Number(args.delay ?? 250),
    sameOrigin: String(args['same-origin'] ?? 'true') !== 'false',
    out: args.out ?? 'report.json',
    cookie: args.cookie ?? null,
    headers: args.headers,
    allowHttpFallback: String(args['allow-http-fallback'] ?? 'false') === 'true',
    userAgent: args['user-agent'] ?? 'scan-node/3.0 (+OWASP-WSTG-aligned)',
    safeMode,
    includeExtendedPayloads,
    payloads: includeExtendedPayloads && !safeMode
      ? [...DEFAULT_PAYLOADS, ...EXTENDED_PAYLOADS]
      : DEFAULT_PAYLOADS,
    concurrency: Math.max(1, Number(args.concurrency ?? 1))
  };
}

function normalizeUrl(input) {
  let value = String(input ?? '').trim();
  if (!value) throw new Error('Target URL is empty');
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  try {
    const u = new URL(value);
    if (!u.pathname) u.pathname = '/';
    u.hash = '';
    return u.toString();
  } catch {
    throw new Error(`Invalid target URL: ${input}`);
  }
}

function withHttpFallback(url) {
  const u = new URL(url);
  if (u.protocol === 'https:') {
    u.protocol = 'http:';
    return u.toString();
  }
  return url;
}

function shouldRetryWithHttp(error) {
  if (!error) return false;
  const code = error.code || error.cause?.code;
  return [
    'ECONNRESET',
    'ECONNREFUSED',
    'ENOTFOUND',
    'EHOSTUNREACH',
    'UND_ERR_CONNECT_TIMEOUT',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'ERR_SSL_WRONG_VERSION_NUMBER',
    'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION'
  ].includes(code);
}

async function fetchWithFallback(url, options = {}, allowHttpFallback = false) {
  try {
    return await fetch(url, options);
  } catch (error) {
    if (allowHttpFallback && new URL(url).protocol === 'https:' && shouldRetryWithHttp(error)) {
      const fallbackUrl = withHttpFallback(url);
      console.warn(`[warn] HTTPS failed for ${url}; retrying with HTTP -> ${fallbackUrl}`);
      return await fetch(fallbackUrl, options);
    }
    throw error;
  }
}

function isHtml(res) {
  const ct = res.headers.get('content-type') || '';
  return ct.includes('text/html');
}

function bodyMetrics(text) {
  return {
    length: text.length,
    title: (text.match(/<title[^>]*>([^<]{0,200})<\/title>/i)?.[1] || '').trim(),
    sqlErrors: SQL_ERROR_PATTERNS.filter((re) => re.test(text)).map((re) => re.toString())
  };
}

function stripNoise(text) {
  return text
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/\d{2}:\d{2}:\d{2}/g, '')
    .replace(/csrf[^\s"'>]*/gi, 'csrf')
    .replace(/nonce[^\s"'>]*/gi, 'nonce')
    .replace(/\s+/g, ' ')
    .slice(0, 20000);
}

function similarity(a, b) {
  if (!a && !b) return 1;
  const len = Math.max(a.length, b.length) || 1;
  let same = 0;
  const min = Math.min(a.length, b.length);
  for (let i = 0; i < min; i++) if (a[i] === b[i]) same++;
  return same / len;
}

function classifyFinding(ev) {
  if (ev.sqlError && ev.statusChanged) return 'high';
  if (ev.sqlError) return 'high';
  if (ev.booleanDifferential && ev.consistent) return 'medium';
  if (ev.statusChanged || ev.largeBodyDelta) return 'low';
  return null;
}

function buildHeaders({ cookie, headers, userAgent }) {
  const out = {
    'user-agent': userAgent || 'scan-node/3.0',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
  };
  if (cookie) out.cookie = cookie;
  for (const item of headers) {
    const idx = item.indexOf(':');
    if (idx > 0) out[item.slice(0, idx).trim()] = item.slice(idx + 1).trim();
  }
  return out;
}

function pickInterestingHeaders(headers) {
  const out = {};
  for (const key of INTERESTING_RESPONSE_HEADERS) {
    const val = headers.get(key);
    if (val) out[key] = val;
  }
  return out;
}

async function fetchWithTimeout(url, init, timeout, allowHttpFallback) {
  const started = Date.now();
  const response = await fetchWithFallback(
    url,
    { ...init, signal: AbortSignal.timeout(timeout), redirect: 'follow' },
    allowHttpFallback
  );
  const text = await response.text();
  return { response, text, ms: Date.now() - started };
}

function extractLinks(baseUrl, html, sameOrigin) {
  const found = new Set();
  for (const m of html.matchAll(/<a\b[^>]*href=["']([^"'#]+)["']/gi)) {
    try {
      const u = new URL(m[1], baseUrl);
      u.hash = '';
      if (['http:', 'https:'].includes(u.protocol)) found.add(u.toString());
    } catch {}
  }
  if (!sameOrigin) return [...found];
  const origin = new URL(baseUrl).origin;
  return [...found].filter((u) => new URL(u).origin === origin);
}

function extractGetParams(url) {
  const u = new URL(url);
  return [...u.searchParams.keys()].map((name) => ({
    type: 'query',
    method: 'GET',
    action: u.origin + u.pathname,
    name,
    source: url
  }));
}

function extractForms(baseUrl, html) {
  const forms = [];
  for (const formMatch of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = formMatch[1];
    const inner = formMatch[2];
    const method = (attrs.match(/method=["']?([^"'\s>]+)/i)?.[1] || 'GET').toUpperCase();
    const actionRaw = attrs.match(/action=["']([^"']+)["']/i)?.[1] || baseUrl;
    let action;
    try { action = new URL(actionRaw, baseUrl).toString(); } catch { action = baseUrl; }
    const names = new Set();
    for (const input of inner.matchAll(/<(input|textarea|select)\b[^>]*name=["']([^"']+)["'][^>]*>/gi)) {
      names.add(input[2]);
    }
    for (const name of names) forms.push({ type: 'form', method, action, name, source: baseUrl });
  }
  return forms;
}

function setParamInUrl(url, key, value) {
  const u = new URL(url);
  u.searchParams.set(key, value);
  return u.toString();
}

function summarizeResult(r) {
  return {
    finalUrl: r.finalUrl,
    status: r.status,
    ms: r.ms,
    length: r.metrics.length,
    title: r.metrics.title,
    sqlErrors: r.metrics.sqlErrors,
    headers: r.headers
  };
}

function evaluateSingle(base, probe) {
  const sim = similarity(stripNoise(base.bodySnippet), stripNoise(probe.bodySnippet));
  return {
    statusChanged: base.status !== probe.status,
    largeBodyDelta: Math.abs(base.metrics.length - probe.metrics.length) > Math.max(120, Math.round(base.metrics.length * 0.15)),
    sqlError: probe.metrics.sqlErrors.length > 0,
    latencyIncreaseMs: probe.ms - base.ms,
    similarity: Number(sim.toFixed(4)),
    booleanDifferential: sim < 0.90,
    consistent: true
  };
}

async function sendVector(vector, value, opts, commonHeaders) {
  try {
    if (vector.method === 'GET') {
      const url = setParamInUrl(vector.action.includes('?') ? vector.action : vector.source, vector.name, value);
      const { response, text, ms } = await fetchWithTimeout(
        url,
        { method: 'GET', headers: commonHeaders },
        opts.timeout,
        opts.allowHttpFallback
      );
      const metrics = bodyMetrics(text);
      return {
        ok: true,
        finalUrl: response.url,
        status: response.status,
        ms,
        metrics,
        headers: pickInterestingHeaders(response.headers),
        bodySnippet: text.slice(0, 20000)
      };
    }

    const body = new URLSearchParams({ [vector.name]: value }).toString();
    const headers = { ...commonHeaders, 'content-type': 'application/x-www-form-urlencoded' };
    const { response, text, ms } = await fetchWithTimeout(
      vector.action,
      { method: vector.method, headers, body },
      opts.timeout,
      opts.allowHttpFallback
    );
    const metrics = bodyMetrics(text);
    return {
      ok: true,
      finalUrl: response.url,
      status: response.status,
      ms,
      metrics,
      headers: pickInterestingHeaders(response.headers),
      bodySnippet: text.slice(0, 20000)
    };
  } catch (error) {
    return {
      ok: false,
      finalUrl: vector.action,
      status: 0,
      ms: 0,
      metrics: { length: 0, title: '', sqlErrors: [] },
      headers: {},
      bodySnippet: '',
      error: String(error?.message || error)
    };
  }
}

async function testVector(vector, opts, commonHeaders) {
  const baselineValue = 'scannerbaseline';
  const baseline = await sendVector(vector, baselineValue, opts, commonHeaders);
  await sleep(opts.delay);

  const probes = [];
  for (const payload of opts.payloads) {
    probes.push({ payload, result: await sendVector(vector, payload.value, opts, commonHeaders) });
    await sleep(opts.delay);
  }

  const findings = [];
  for (const { payload, result } of probes) {
    const ev = evaluateSingle(baseline, result);
    const confidence = classifyFinding(ev);
    if (confidence) {
      findings.push({
        category: 'A05:2025-Injection',
        vector,
        payload: payload.value,
        payloadType: payload.type,
        confidence,
        evidence: ev,
        baseline: summarizeResult(baseline),
        response: summarizeResult(result)
      });
    }
  }

  const byType = Object.fromEntries(probes.map((p) => [p.payload.type, p.result]));
  const boolPairs = [
    ['boolean-true-str', 'boolean-false-str'],
    ['boolean-true-num', 'boolean-false-num']
  ];

  for (const [t1, t2] of boolPairs) {
    const a = byType[t1], b = byType[t2];
    if (!a || !b) continue;
    const sim = similarity(stripNoise(a.bodySnippet), stripNoise(b.bodySnippet));
    const changed = a.status !== b.status || Math.abs(a.metrics.length - b.metrics.length) > 80 || sim < 0.90;
    if (changed) {
      findings.push({
        category: 'A05:2025-Injection',
        vector,
        payload: `${t1} vs ${t2}`,
        payloadType: 'boolean-differential',
        confidence: 'medium',
        evidence: {
          booleanDifferential: true,
          consistent: true,
          statusA: a.status,
          statusB: b.status,
          lenA: a.metrics.length,
          lenB: b.metrics.length,
          similarity: Number(sim.toFixed(4))
        },
        baseline: summarizeResult(baseline),
        response: { a: summarizeResult(a), b: summarizeResult(b) }
      });
    }
  }

  return { vector, baseline: summarizeResult(baseline), findings };
}

function assessHeaders(headers, finalUrl) {
  const findings = [];
  const url = new URL(finalUrl);
  const isHttps = url.protocol === 'https:';

  if (isHttps && !headers['strict-transport-security']) {
    findings.push({
      category: 'A02:2025-Security-Misconfiguration',
      confidence: 'low',
      title: 'Missing HSTS on HTTPS response',
      evidence: { finalUrl, header: 'strict-transport-security' }
    });
  }

  if (!headers['content-security-policy']) {
    findings.push({
      category: 'A02:2025-Security-Misconfiguration',
      confidence: 'low',
      title: 'Missing Content-Security-Policy header',
      evidence: { finalUrl, header: 'content-security-policy' }
    });
  }

  if (!headers['x-content-type-options']) {
    findings.push({
      category: 'A02:2025-Security-Misconfiguration',
      confidence: 'low',
      title: 'Missing X-Content-Type-Options header',
      evidence: { finalUrl, header: 'x-content-type-options' }
    });
  }

  return findings;
}

function assessCookies(headers, finalUrl) {
  const findings = [];
  const setCookie = headers['set-cookie'];
  if (!setCookie) return findings;

  const lower = setCookie.toLowerCase();
  if (!lower.includes('httponly')) {
    findings.push({
      category: 'A07:2025-Identification-and-Authentication-Failures',
      confidence: 'low',
      title: 'Set-Cookie without HttpOnly',
      evidence: { finalUrl, header: 'set-cookie' }
    });
  }
  if (!lower.includes('secure')) {
    findings.push({
      category: 'A07:2025-Identification-and-Authentication-Failures',
      confidence: 'low',
      title: 'Set-Cookie without Secure',
      evidence: { finalUrl, header: 'set-cookie' }
    });
  }
  if (!lower.includes('samesite')) {
    findings.push({
      category: 'A07:2025-Identification-and-Authentication-Failures',
      confidence: 'low',
      title: 'Set-Cookie without SameSite attribute',
      evidence: { finalUrl, header: 'set-cookie' }
    });
  }
  return findings;
}

function assessFormsPassive(forms) {
  const findings = [];
  for (const form of forms) {
    if (form.method === 'GET') {
      findings.push({
        category: 'A02:2025-Security-Misconfiguration',
        confidence: 'info',
        title: 'Form using GET method discovered',
        evidence: { action: form.action, name: form.name, source: form.source }
      });
    }
  }
  return findings;
}

async function crawl(opts) {
  const startUrl = normalizeUrl(opts.target);
  const commonHeaders = buildHeaders({ cookie: opts.cookie, headers: opts.headers, userAgent: opts.userAgent });

  const queue = [startUrl];
  const seen = new Set();
  const pages = [];
  const vectors = [];
  const passiveFindings = [];

  while (queue.length && pages.length < opts.maxPages) {
    const url = queue.shift();
    if (seen.has(url)) continue;
    seen.add(url);

    let fetched;
    try {
      fetched = await fetchWithTimeout(url, { method: 'GET', headers: commonHeaders }, opts.timeout, opts.allowHttpFallback);
    } catch (error) {
      pages.push({ url, error: String(error?.message || error) });
      continue;
    }

    const { response, text, ms } = fetched;
    const headers = pickInterestingHeaders(response.headers);
    const page = {
      url,
      finalUrl: response.url,
      status: response.status,
      ms,
      headers,
      metrics: bodyMetrics(text)
    };
    pages.push(page);

    passiveFindings.push(...assessHeaders(headers, response.url));
    passiveFindings.push(...assessCookies(headers, response.url));

    if (!isHtml(response)) continue;

    const links = extractLinks(response.url, text, opts.sameOrigin);
    for (const link of links) if (!seen.has(link)) queue.push(link);

    const pageForms = extractForms(response.url, text);
    const pageParams = extractGetParams(response.url);
    passiveFindings.push(...assessFormsPassive(pageForms));
    vectors.push(...pageForms, ...pageParams);
  }

  const unique = new Map();
  for (const v of vectors) {
    unique.set(`${v.method}|${v.action}|${v.name}|${v.source}`, v);
  }

  const activeResults = [];
  if (!opts.safeMode) {
    for (const vector of unique.values()) {
      activeResults.push(await testVector(vector, opts, commonHeaders));
    }
  }

  return {
    meta: {
      startedAt: new Date().toISOString(),
      target: startUrl,
      maxPages: opts.maxPages,
      sameOrigin: opts.sameOrigin,
      safeMode: opts.safeMode,
      allowHttpFallback: opts.allowHttpFallback,
      payloadCount: opts.payloads.length,
      userAgent: opts.userAgent,
      methodology: {
        references: [
          'OWASP WSTG - latest',
          'OWASP Top 10:2025',
          'A05:2025 - Injection',
          'A02:2025 - Security Misconfiguration'
        ]
      }
    },
    pages,
    vectors: [...unique.values()],
    passiveFindings,
    activeResults,
    summary: {
      pagesVisited: pages.length,
      vectorsDiscovered: unique.size,
      passiveFindingCount: passiveFindings.length,
      activeFindingCount: activeResults.reduce((n, r) => n + r.findings.length, 0)
    }
  };
}

async function main() {
  const opts = parseArgs(process.argv);
  const { target } = opts;

  if (!target) {
    console.error('Usage: node scanner-v3.js <url> [--max-pages=20] [--same-origin=true|false] [--allow-http-fallback=true|false] [--safe=true|false] [--extended-payloads=true|false] [--cookie=...] [--header="K: V"]');
    console.error('Example: node scanner-v3.js example.com --allow-http-fallback=true --safe=true');
    process.exit(1);
  }

  const report = await crawl(opts);
  await writeFile(opts.out, JSON.stringify(report, null, 2), 'utf8');

  console.log(JSON.stringify({
    ok: true,
    out: opts.out,
    pagesVisited: report.summary.pagesVisited,
    vectorsDiscovered: report.summary.vectorsDiscovered,
    passiveFindingCount: report.summary.passiveFindingCount,
    activeFindingCount: report.summary.activeFindingCount,
    safeMode: report.meta.safeMode
  }, null, 2));
}

main().catch((err) => {
  console.error(err?.stack || String(err));
  process.exit(1);
});
