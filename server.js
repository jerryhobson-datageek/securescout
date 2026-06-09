'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const url = require('url');

const CONFIG_PATH = path.join(__dirname, 'config.json');
let config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

// In-memory results cache
const cache = {};

// ── SSL Certificate Check ────────────────────────────────────────────────────
function checkSSL(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.destroy();

        if (!cert || !cert.subject) {
          return resolve({ ok: false, error: 'No certificate returned' });
        }

        const validTo = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const now = new Date();
        const daysLeft = Math.floor((validTo - now) / 86400000);

        resolve({
          ok: true,
          subject: cert.subject.CN || cert.subject.O || host,
          issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Unknown') : 'Unknown',
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysLeft,
          protocol,
          cipher: cipher ? cipher.name : 'Unknown',
          fingerprint: cert.fingerprint256 || cert.fingerprint || '',
          selfSigned: cert.issuer && cert.subject &&
            JSON.stringify(cert.issuer) === JSON.stringify(cert.subject),
          altNames: cert.subjectaltname
            ? cert.subjectaltname.replace(/DNS:/g, '').split(', ')
            : []
        });
      } catch (e) {
        socket.destroy();
        resolve({ ok: false, error: e.message });
      }
    });
    socket.on('error', (e) => resolve({ ok: false, error: e.message }));
    socket.setTimeout(8000, () => { socket.destroy(); resolve({ ok: false, error: 'Timeout' }); });
  });
}

// ── TLS Version Probe ────────────────────────────────────────────────────────
function probeTLS(host, port, tlsVersion) {
  return new Promise((resolve) => {
    const opts = {
      host, port, servername: host,
      rejectUnauthorized: false,
      minVersion: tlsVersion,
      maxVersion: tlsVersion
    };
    const socket = tls.connect(opts, () => {
      const proto = socket.getProtocol();
      socket.destroy();
      resolve({ supported: true, protocol: proto });
    });
    socket.on('error', () => resolve({ supported: false }));
    socket.setTimeout(5000, () => { socket.destroy(); resolve({ supported: false }); });
  });
}

// ── HTTP/2 Probe ─────────────────────────────────────────────────────────────
function probeHTTP2(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host, port, servername: host,
      rejectUnauthorized: false,
      ALPNProtocols: ['h2', 'http/1.1']
    }, () => {
      const proto = socket.alpnProtocol;
      socket.destroy();
      resolve(proto === 'h2');
    });
    socket.on('error', () => resolve(false));
    socket.setTimeout(5000, () => { socket.destroy(); resolve(false); });
  });
}

// ── Security Headers + WAF + Server Info ────────────────────────────────────
function fetchHeaders(targetUrl) {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const lib = parsed.protocol === 'https:' ? https : http;
    const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);

    const start = Date.now();
    const req = lib.request({
      hostname: parsed.hostname,
      port,
      path: parsed.pathname || '/',
      method: 'GET',
      rejectUnauthorized: false,
      headers: {
        'User-Agent': 'Mozilla/5.0 (SecureScout/1.0)',
        'Accept': 'text/html,application/xhtml+xml,*/*',
        'Accept-Language': 'en-US,en;q=0.9'
      }
    }, (res) => {
      const elapsed = Date.now() - start;
      res.destroy();
      resolve({ ok: true, status: res.statusCode, headers: res.headers, elapsed });
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ ok: false, error: 'Timeout' }); });
    req.end();
  });
}

// Probe with suspicious payload to test WAF blocking
function probeWAF(targetUrl) {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const lib = parsed.protocol === 'https:' ? https : http;
    const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);

    const req = lib.request({
      hostname: parsed.hostname,
      port,
      path: '/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&id=1%20UNION%20SELECT%201--',
      method: 'GET',
      rejectUnauthorized: false,
      headers: { 'User-Agent': 'Mozilla/5.0 (SecureScout/1.0)', 'Accept': '*/*' }
    }, (res) => {
      res.destroy();
      resolve({ status: res.statusCode, headers: res.headers });
    });
    req.on('error', () => resolve({ status: null, headers: {} }));
    req.setTimeout(8000, () => { req.destroy(); resolve({ status: null, headers: {} }); });
    req.end();
  });
}

function analyzeSecurityHeaders(headers) {
  const checks = [
    {
      key: 'strict-transport-security',
      label: 'HSTS',
      weight: 20,
      grade: (v) => {
        if (!v) return { pass: false, note: 'Missing' };
        const maxAge = parseInt((v.match(/max-age=(\d+)/) || [])[1] || 0);
        if (maxAge >= 31536000) return { pass: true, note: `max-age=${maxAge}` };
        return { pass: 'warn', note: `max-age too short (${maxAge})` };
      }
    },
    {
      key: 'content-security-policy',
      label: 'CSP',
      weight: 20,
      grade: (v) => v
        ? { pass: true, note: v.length > 80 ? v.substring(0, 77) + '...' : v }
        : { pass: false, note: 'Missing' }
    },
    {
      key: 'x-frame-options',
      label: 'X-Frame-Options',
      weight: 10,
      grade: (v) => v
        ? { pass: true, note: v }
        : { pass: false, note: 'Missing — clickjacking risk' }
    },
    {
      key: 'x-content-type-options',
      label: 'X-Content-Type-Options',
      weight: 10,
      grade: (v) => v === 'nosniff'
        ? { pass: true, note: 'nosniff' }
        : { pass: false, note: v ? `Unexpected: ${v}` : 'Missing' }
    },
    {
      key: 'referrer-policy',
      label: 'Referrer-Policy',
      weight: 10,
      grade: (v) => v
        ? { pass: true, note: v }
        : { pass: 'warn', note: 'Missing (browser default applies)' }
    },
    {
      key: 'permissions-policy',
      label: 'Permissions-Policy',
      weight: 10,
      grade: (v) => v
        ? { pass: true, note: v.length > 60 ? v.substring(0, 57) + '...' : v }
        : { pass: 'warn', note: 'Missing' }
    },
    {
      key: 'x-xss-protection',
      label: 'X-XSS-Protection',
      weight: 5,
      grade: (v) => {
        if (!v) return { pass: 'warn', note: 'Missing (legacy header)' };
        if (v.startsWith('1; mode=block')) return { pass: true, note: v };
        if (v === '0') return { pass: 'warn', note: 'Disabled' };
        return { pass: 'warn', note: v };
      }
    },
    {
      key: 'cache-control',
      label: 'Cache-Control',
      weight: 5,
      grade: (v) => v
        ? { pass: true, note: v }
        : { pass: 'warn', note: 'Not set' }
    }
  ];

  let score = 0;
  let maxScore = 0;
  const results = [];

  for (const check of checks) {
    maxScore += check.weight;
    const val = headers[check.key];
    const result = check.grade(val);
    if (result.pass === true) score += check.weight;
    else if (result.pass === 'warn') score += check.weight * 0.5;
    results.push({ label: check.label, pass: result.pass, note: result.note, present: !!val });
  }

  const pct = Math.round((score / maxScore) * 100);
  let grade;
  if (pct >= 90) grade = 'A';
  else if (pct >= 75) grade = 'B';
  else if (pct >= 55) grade = 'C';
  else if (pct >= 35) grade = 'D';
  else grade = 'F';

  return { grade, score: pct, checks: results };
}

function detectWAF(headers, probeResult) {
  const h = headers;
  const ph = probeResult.headers || {};
  const allHeaders = { ...h, ...ph };
  const headerStr = JSON.stringify(allHeaders).toLowerCase();

  const signatures = [
    { name: 'Cloudflare', keys: ['cf-ray', 'cf-cache-status', 'cf-request-id'], server: 'cloudflare' },
    { name: 'AWS WAF / CloudFront', keys: ['x-amz-cf-id', 'x-amz-request-id'], server: null },
    { name: 'Sucuri', keys: ['x-sucuri-id', 'x-sucuri-cache'], server: 'sucuri' },
    { name: 'Imperva / Incapsula', keys: ['x-iinfo', 'x-cdn'], server: 'incapsula' },
    { name: 'Akamai', keys: ['x-akamai-transformed', 'akamai-origin-hop'], server: 'akamaighost' },
    { name: 'F5 BIG-IP', keys: ['x-wa-info', 'x-cnection', 'x-forwarded-for'], server: 'big-ip' },
    { name: 'Barracuda WAF', keys: ['barra_counter_session', 'bwce'], server: null },
    { name: 'Fastly', keys: ['x-fastly-request-id', 'x-served-by'], server: 'fastly' },
    { name: 'Nginx (with ModSecurity)', keys: [], server: null, pattern: 'mod_security' },
    { name: 'Nginx Proxy Manager', keys: [], server: 'nginx', pattern: null }
  ];

  const blocked = probeResult.status === 403 || probeResult.status === 406 ||
    probeResult.status === 429 || probeResult.status === 444 || probeResult.status === 400;

  let detected = null;
  for (const sig of signatures) {
    const keyMatch = sig.keys.some(k => allHeaders[k] !== undefined);
    const serverVal = (allHeaders['server'] || '').toLowerCase();
    const serverMatch = sig.server && serverVal.includes(sig.server);
    const patternMatch = sig.pattern && headerStr.includes(sig.pattern);
    if (keyMatch || serverMatch || patternMatch) {
      detected = sig.name;
      break;
    }
  }

  return {
    detected: !!detected || blocked,
    name: detected || (blocked ? 'Unknown WAF (probe blocked)' : null),
    probeBlocked: blocked,
    probeStatus: probeResult.status,
    confidence: detected ? 'high' : (blocked ? 'medium' : 'none')
  };
}

function analyzeServer(headers, ip) {
  const server = headers['server'] || 'Unknown';
  const powered = headers['x-powered-by'] || null;
  const via = headers['via'] || null;
  const httpVersion = headers[':status'] ? 'HTTP/2' : 'HTTP/1.1';

  // Detect server software
  let software = 'Unknown';
  const sl = server.toLowerCase();
  if (sl.includes('nginx')) software = 'Nginx';
  else if (sl.includes('apache')) software = 'Apache';
  else if (sl.includes('iis')) software = 'Microsoft IIS';
  else if (sl.includes('cloudflare')) software = 'Cloudflare';
  else if (sl.includes('openresty')) software = 'OpenResty (Nginx)';
  else if (sl.includes('litespeed')) software = 'LiteSpeed';
  else if (sl.includes('caddy')) software = 'Caddy';
  else if (server !== 'Unknown') software = server;

  return {
    raw: server,
    software,
    poweredBy: powered,
    via,
    ip: ip || 'Unknown'
  };
}

// ── Full scan for one service ────────────────────────────────────────────────
async function scanService(service) {
  const parsed = new URL(service.url);
  const host = parsed.hostname;
  const isHTTPS = parsed.protocol === 'https:';
  // sslHost allows HTTP-only internal URLs to still check the public SSL cert
  const sslHost = service.sslHost || host;
  const checkSsl = isHTTPS || !!service.sslHost;

  const [ssl, headersResult, probeResult, tls12, tls13, http2, dnsResult] = await Promise.all([
    checkSsl ? checkSSL(sslHost) : Promise.resolve({ ok: false, error: 'Not HTTPS' }),
    fetchHeaders(service.url),
    probeWAF(service.url),
    checkSsl ? probeTLS(sslHost, 443, 'TLSv1.2') : Promise.resolve({ supported: false }),
    checkSsl ? probeTLS(sslHost, 443, 'TLSv1.3') : Promise.resolve({ supported: false }),
    checkSsl ? probeHTTP2(sslHost) : Promise.resolve(false),
    dns.lookup(sslHost).catch(() => null)
  ]);

  const ip = dnsResult ? dnsResult.address : null;
  const headers = headersResult.ok ? headersResult.headers : {};

  return {
    name: service.name,
    url: service.url,
    scannedAt: new Date().toISOString(),
    reachable: headersResult.ok,
    responseTime: headersResult.elapsed || null,
    httpStatus: headersResult.status || null,
    ssl,
    securityHeaders: headersResult.ok ? analyzeSecurityHeaders(headers) : null,
    waf: headersResult.ok ? detectWAF(headers, probeResult) : null,
    server: headersResult.ok ? analyzeServer(headers, ip) : null,
    browserSupport: {
      tls12: tls12.supported,
      tls13: tls13.supported,
      http2,
      notes: buildBrowserNotes(tls12.supported, tls13.supported, http2)
    }
  };
}

function buildBrowserNotes(tls12, tls13, http2) {
  const notes = [];
  if (tls13) notes.push('Modern browsers (TLS 1.3)');
  if (tls12) notes.push('Legacy browsers (TLS 1.2)');
  if (!tls12 && !tls13) notes.push('TLS not detected — may be HTTP only');
  if (http2) notes.push('HTTP/2 supported');
  else notes.push('HTTP/1.1 only');

  // Browser compatibility
  if (tls13 && http2) notes.push('Chrome 70+, Firefox 63+, Safari 12.1+, Edge 79+');
  else if (tls12) notes.push('Chrome 30+, Firefox 27+, Safari 7+, IE 11+');
  return notes;
}

// ── HTTP Server ──────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET',
    'Content-Type': 'application/json'
  };

  if (pathname === '/') {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  if (pathname === '/api/services') {
    res.writeHead(200, cors);
    res.end(JSON.stringify(config.services.map(s => ({ name: s.name, url: s.url }))));
    return;
  }

  if (pathname === '/api/scan/all') {
    res.writeHead(200, cors);
    const results = await Promise.all(config.services.map(s => {
      cache[s.url] = null; // invalidate
      return scanService(s).then(r => { cache[s.url] = r; return r; });
    }));
    res.end(JSON.stringify(results));
    return;
  }

  if (pathname === '/api/scan') {
    const target = parsed.query.url;
    const service = config.services.find(s => s.url === target);
    if (!service) {
      res.writeHead(404, cors);
      res.end(JSON.stringify({ error: 'Service not found' }));
      return;
    }
    res.writeHead(200, cors);
    const result = await scanService(service);
    cache[service.url] = result;
    res.end(JSON.stringify(result));
    return;
  }

  if (pathname === '/api/results') {
    res.writeHead(200, cors);
    res.end(JSON.stringify(Object.values(cache).filter(Boolean)));
    return;
  }

  res.writeHead(404, cors);
  res.end(JSON.stringify({ error: 'Not found' }));
});

const PORT = config.port || 3001;
server.listen(PORT, () => {
  console.log(`SecureScout running on http://localhost:${PORT}`);
  // Initial scan
  console.log('Running initial scan...');
  Promise.all(config.services.map(s => scanService(s).then(r => { cache[s.url] = r; })))
    .then(() => console.log('Initial scan complete.'));
});

// Auto-rescan
if (config.scanIntervalMinutes > 0) {
  setInterval(() => {
    config.services.forEach(s => scanService(s).then(r => { cache[s.url] = r; }));
  }, config.scanIntervalMinutes * 60 * 1000);
}
