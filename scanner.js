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

const PAYLOADS = [
  { type: 'error-quote', value: `'` },
  { type: 'delimiter', value: `;` },
  { type: 'boolean-true-str', value: `' AND '1'='1` },
  { type: 'boolean-false-str', value: `' AND '1'='2` },
  { type: 'boolean-true-num', value: `1 AND 1=1` },
  { type: 'boolean-false-num', value: `1 AND 1=2` }
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
  return {
    target: args.target,
    maxPages: Number(args['max-pages'] ?? 15),
    timeout: Number(args.timeout ?? 8000),
    delay: Number(args.delay ?? 250),
    sameOrigin: String(args['same-origin'] ?? 'true') !== 'false',
    out: args.out ?? 'report.json',
    cookie: args.cookie ?? null,
    headers: args.headers
  };
}

function normalizeUrl(input) {
  const u = new URL(input);
  if (!u.pathname) u.pathname = '/';
  u.hash = '';
  return u.toString();
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

function buildHeaders(opts) {
  const headers = {
    'user-agent': 'Authorized-SQLi-Heuristic-Scanner/1.0',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
  };
  if (opts.cookie) headers.cookie = opts.cookie;
  for (const item of opts.headers) {
    const idx = item.indexOf(':');
    if (idx > 0) headers[item.slice(0, idx).trim()] = item.slice(idx + 1).trim();
  }
  return headers;
}

async function fetchWithTimeout(url, init, timeout) {
  const started = Date.now();
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(timeout), redirect: 'follow' });
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

async function testVector(vector, opts, commonHeaders) {
  const baselineValue = 'scannerbaseline';
  const baseline = await sendVector(vector, baselineValue, opts, commonHeaders);
  await sleep(opts.delay);
  const probes = [];
  for (const payload of PAYLOADS) {
    probes.push({ payload, result: await sendVector(vector, payload.value, opts, commonHeaders) });
    await sleep(opts.delay);
  }

  const findings = [];
  for (const { payload, result } of probes) {
    const ev = evaluateSingle(baseline, result);
    const confidence = classifyFinding(ev);
    if (confidence) {
      findings.push({
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

function summarizeResult(r) {
  return {
    finalUrl: r.finalUrl,
    status: r.status,
    ms: r.ms,
    length: r.metrics.length,
    title: r.metrics.title,
    sqlErrors: r.metrics.sqlErrors
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
      const { response, text, ms } = await fetchWithTimeout(url, { method: 'GET', headers: commonHeaders }, opts.timeout);
      const metrics = bodyMetrics(text);
      return {
        ok: true,
        finalUrl: response.url,
        status: response.status,
        ms,
        metrics,
        bodySnippet: text.slice(0, 20000)
      };
    }
    const body = new URLSearchParams({ [vector.name]: value }).toString();
    const headers = { ...commonHeaders, 'content-type': 'application/x-www-form-urlencoded' };
    const { response, text, ms } = await fetchWithTimeout(vector.action, { method: vector.method, headers, body }, opts.timeout);
    const metrics = bodyMetrics(text);
    return {
      ok: true,
      finalUrl: response.url,
      status: response.status,
      ms,
      metrics,
      bodySnippet: text.slice(0, 20000)
    };
  } catch (error) {
    return {
      ok: false,
      finalUrl: vector.action,
      status: 0,
      ms: opts.timeout,
      metrics: { length: 0, title: '', sqlErrors: [] },
      bodySnippet: '',
      error: error?.name || String(error)
    };
  }
}

async function crawl(startUrl, opts, commonHeaders) {
  const queue = [normalizeUrl(startUrl)];
  const seen = new Set();
  const pages = [];
  const vectors = [];

  while (queue.length && pages.length < opts.maxPages) {
    const url = queue.shift();
    if (!url || seen.has(url)) continue;
    seen.add(url);
    try {
      const { response, text, ms } = await fetchWithTimeout(url, { method: 'GET', headers: commonHeaders }, opts.timeout);
      const page = { url: response.url, status: response.status, ms, html: isHtml(response) ? text : '' };
      pages.push({ url: page.url, status: page.status, ms });
      if (!page.html) continue;
      for (const v of extractGetParams(page.url)) vectors.push(v);
      for (const v of extractForms(page.url, page.html)) vectors.push(v);
      for (const link of extractLinks(page.url, page.html, opts.sameOrigin)) if (!seen.has(link)) queue.push(link);
      await sleep(opts.delay);
    } catch {
      pages.push({ url, status: 0, ms: opts.timeout, error: 'fetch_failed' });
    }
  }

  const uniq = new Map();
  for (const v of vectors) {
    const key = [v.method, v.action, v.name, v.type, v.source].join('|');
    if (!uniq.has(key)) uniq.set(key, v);
  }
  return { pages, vectors: [...uniq.values()] };
}

async function main() {
  const opts = parseArgs(process.argv);
  if (!opts.target) {
    console.error('Uso: node scanner.js https://alvo.exemplo [--max-pages=15] [--timeout=8000] [--delay=250] [--out=report.json]');
    process.exit(1);
  }

  const commonHeaders = buildHeaders(opts);
  const crawlData = await crawl(opts.target, opts, commonHeaders);
  const results = [];

  for (const vector of crawlData.vectors) {
    const tested = await testVector(vector, opts, commonHeaders);
    results.push(tested);
  }

  const findings = results.flatMap((r) => r.findings);
  const report = {
    scanner: 'sqli-scanner-defensivo',
    generatedAt: new Date().toISOString(),
    target: opts.target,
    options: {
      maxPages: opts.maxPages,
      timeout: opts.timeout,
      delay: opts.delay,
      sameOrigin: opts.sameOrigin
    },
    pagesVisited: crawlData.pages,
    vectorsDiscovered: crawlData.vectors,
    findings,
    stats: {
      pages: crawlData.pages.length,
      vectors: crawlData.vectors.length,
      findings: findings.length,
      high: findings.filter((f) => f.confidence === 'high').length,
      medium: findings.filter((f) => f.confidence === 'medium').length,
      low: findings.filter((f) => f.confidence === 'low').length
    }
  };

  await writeFile(new URL(`./${opts.out}`, import.meta.url), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report.stats));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
