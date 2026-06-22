'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const CONFIG_PATH = path.join(__dirname, 'config.json');
const HISTORY_PATH = path.join(__dirname, 'history.json');

let config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));

// ── History ───────────────────────────────────────────────────────────────────
const HISTORY_MAX = 30;
let history = {};
try { history = JSON.parse(fs.readFileSync(HISTORY_PATH, 'utf8')); } catch {}

function saveHistory() {
  fs.writeFileSync(HISTORY_PATH, JSON.stringify(history));
}

function appendHistory(result) {
  const key = result.url;
  if (!history[key]) history[key] = [];
  history[key].push({
    scannedAt: result.scannedAt,
    grade: result.securityHeaders?.grade || null,
    sslDaysLeft: result.ssl?.ok ? result.ssl.daysLeft : null,
    reachable: result.reachable,
    responseTime: result.responseTime || null
  });
  if (history[key].length > HISTORY_MAX) history[key] = history[key].slice(-HISTORY_MAX);
  saveHistory();
}

// ── Auth ──────────────────────────────────────────────────────────────────────
const sessions = new Map(); // token → { userId, username, role, expires }

// Migrate old single-password format to users array
if (config.auth && !config.users) {
  delete config.auth;
  config.users = [];
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}
if (!Array.isArray(config.users)) config.users = [];

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const attempt = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
  } catch { return false; }
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId: user.id, username: user.username, role: user.role, expires: Date.now() + 24 * 60 * 60 * 1000 });
  return token;
}

function getSession(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || Date.now() > session.expires) { sessions.delete(token); return null; }
  return session;
}

function saveConfig() {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

setInterval(() => {
  const now = Date.now();
  for (const [token, s] of sessions) if (now > s.expires) sessions.delete(token);
}, 3600000);

// ── Login Rate Limiting ──────────────────────────────────────────────────────
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const loginAttempts = new Map(); // ip → { count, firstAttempt }

function getClientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress;
}

function isRateLimited(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > LOGIN_WINDOW_MS) { loginAttempts.delete(ip); return false; }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}

function recordLoginFailure(ip) {
  const entry = loginAttempts.get(ip);
  if (!entry || Date.now() - entry.firstAttempt > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: Date.now() });
  } else {
    entry.count++;
  }
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts) if (now - entry.firstAttempt > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
}, 3600000);

// ── Discord Alerts ────────────────────────────────────────────────────────────
async function sendDiscord(message) {
  const webhookUrl = config.discordWebhook;
  if (!webhookUrl) return;
  try {
    const body = JSON.stringify({ content: message });
    const parsed = new URL(webhookUrl);
    const lib = parsed.protocol === 'https:' ? https : http;
    await new Promise((resolve) => {
      const req = lib.request(parsed, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      }, (res) => { res.resume(); resolve(); });
      req.on('error', resolve);
      req.setTimeout(8000, () => { req.destroy(); resolve(); });
      req.write(body);
      req.end();
    });
  } catch {}
}

function checkAlerts(prev, next) {
  if (!prev) return;
  const name = next.name;

  // Site went down
  if (prev.reachable && !next.reachable) {
    sendDiscord(`🔴 **${name}** is DOWN\n${next.url}`);
  }
  // Site came back up
  if (!prev.reachable && next.reachable) {
    sendDiscord(`🟢 **${name}** is back UP\n${next.url}`);
  }
  // SSL expiring (crossing below 30 days)
  if (next.reachable && next.ssl?.ok && next.ssl.daysLeft < 30) {
    const prevDays = prev.sslDaysLeft ?? (prev.ssl?.ok ? prev.ssl.daysLeft : null);
    if (prevDays === null || prevDays >= 30) {
      sendDiscord(`⚠️ **${name}** SSL cert expires in **${next.ssl.daysLeft} days**\nSubject: ${next.ssl.subject}`);
    }
  }
  // Grade dropped
  const gradeOrder = ['A', 'B', 'C', 'D', 'F'];
  const prevGrade = prev.grade ?? prev.securityHeaders?.grade;
  const nextGrade = next.securityHeaders?.grade;
  if (prevGrade && nextGrade && gradeOrder.indexOf(nextGrade) > gradeOrder.indexOf(prevGrade)) {
    sendDiscord(`📉 **${name}** security header grade dropped **${prevGrade} → ${nextGrade}**\n${next.url}`);
  }
}

// ── SSL Certificate Check ─────────────────────────────────────────────────────
function checkSSL(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.destroy();
        if (!cert || !cert.subject) return resolve({ ok: false, error: 'No certificate returned' });
        const validTo = new Date(cert.valid_to);
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
      } catch (e) { socket.destroy(); resolve({ ok: false, error: e.message }); }
    });
    socket.on('error', (e) => resolve({ ok: false, error: e.message }));
    socket.setTimeout(8000, () => { socket.destroy(); resolve({ ok: false, error: 'Timeout' }); });
  });
}

// ── DNS Security Check ────────────────────────────────────────────────────────
function dohQuery(host, type) {
  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'cloudflare-dns.com',
      path: `/dns-query?name=${encodeURIComponent(host)}&type=${type}`,
      method: 'GET',
      headers: { 'Accept': 'application/dns-json' }
    }, (res) => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(6000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

function apexDomain(host) {
  const parts = host.split('.');
  return parts.length > 2 ? parts.slice(-2).join('.') : host;
}

async function checkDNS(host) {
  const apex = apexDomain(host);

  // CAA: try the specific host first, fall back to apex
  async function resolveCaaWithFallback() {
    const r = await dns.resolveCaa(host).catch(() => []);
    if (r.length) return r;
    return dns.resolveCaa(apex).catch(() => []);
  }

  const [aRec, caaRec, nsRec, txtRec, dmarcRec, dsResult, dnskeyResult] = await Promise.allSettled([
    dns.resolve4(host).catch(() => []),
    resolveCaaWithFallback(),
    dns.resolveNs(apex).catch(() => []),
    dns.resolveTxt(apex).catch(() => []),
    dns.resolveTxt('_dmarc.' + apex).catch(() => []),
    dohQuery(host, 'DS'),
    dohQuery(host, 'DNSKEY')
  ]);

  const ips       = aRec.status       === 'fulfilled' ? aRec.value       : [];
  const caa       = caaRec.status     === 'fulfilled' ? caaRec.value     : [];
  const ns        = nsRec.status      === 'fulfilled' ? nsRec.value      : [];
  const txt       = txtRec.status     === 'fulfilled' ? txtRec.value.flat() : [];
  const dmarcTxt  = dmarcRec.status   === 'fulfilled' ? dmarcRec.value.flat() : [];
  const dsData    = dsResult.status   === 'fulfilled' ? dsResult.value   : null;
  const dnskeyData = dnskeyResult.status === 'fulfilled' ? dnskeyResult.value : null;

  // DNSSEC: AD flag = Authenticated Data, or DS records present
  const dnssecEnabled = !!(
    dsData?.AD ||
    dnskeyData?.AD ||
    (dsData?.Answer?.length > 0) ||
    (dnskeyData?.Answer?.length > 0)
  );

  // CAA: surface which issuers are authorised
  const caaIssuers = caa
    .filter(r => r.issue || r.issuewild)
    .map(r => r.issue || r.issuewild)
    .filter(Boolean)
    .filter(v => v.trim() !== ';');

  // SPF
  const spf = txt.find(t => t.startsWith('v=spf1')) || null;

  // DMARC
  const dmarcRecord = dmarcTxt.find(t => t.startsWith('v=DMARC1')) || null;
  const dmarcPolicy = dmarcRecord ? (dmarcRecord.match(/[;, ]p=([a-z]+)/i) || [])[1] || null : null;

  return {
    ok: true,
    ips,
    nameservers: ns.sort(),
    caaPresent: caa.length > 0,
    caaIssuers,
    dnssecEnabled,
    spf,
    dmarc: { present: !!dmarcRecord, record: dmarcRecord, policy: dmarcPolicy }
  };
}

// ── TLS Version Probe ─────────────────────────────────────────────────────────
function probeTLS(host, port, tlsVersion) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, minVersion: tlsVersion, maxVersion: tlsVersion },
      () => { const proto = socket.getProtocol(); socket.destroy(); resolve({ supported: true, protocol: proto }); }
    );
    socket.on('error', () => resolve({ supported: false }));
    socket.setTimeout(5000, () => { socket.destroy(); resolve({ supported: false }); });
  });
}

// ── HTTP/2 Probe ──────────────────────────────────────────────────────────────
function probeHTTP2(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'] },
      () => { const proto = socket.alpnProtocol; socket.destroy(); resolve(proto === 'h2'); }
    );
    socket.on('error', () => resolve(false));
    socket.setTimeout(5000, () => { socket.destroy(); resolve(false); });
  });
}

// ── HTTP→HTTPS Redirect Check ─────────────────────────────────────────────────
function checkHTTPRedirect(host) {
  return new Promise((resolve) => {
    const req = http.request({
      hostname: host, port: 80, path: '/', method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0 (SecureScout/1.0)', 'Accept': '*/*' }
    }, (res) => {
      res.destroy();
      const location = res.headers['location'] || '';
      const isRedirect = res.statusCode >= 300 && res.statusCode < 400;
      resolve({
        checked: true,
        status: res.statusCode,
        redirects: isRedirect && location.startsWith('https://'),
        location: location || null
      });
    });
    req.on('error', () => resolve({ checked: false, redirects: false, status: null, location: null }));
    req.setTimeout(5000, () => { req.destroy(); resolve({ checked: false, redirects: false, status: null, location: null }); });
    req.end();
  });
}

// ── Fetch Headers ─────────────────────────────────────────────────────────────
function fetchHeaders(targetUrl) {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const lib = parsed.protocol === 'https:' ? https : http;
    const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);
    const start = Date.now();
    const req = lib.request({
      hostname: parsed.hostname, port, path: parsed.pathname || '/', method: 'GET',
      rejectUnauthorized: false,
      headers: { 'User-Agent': 'Mozilla/5.0 (SecureScout/1.0)', 'Accept': 'text/html,application/xhtml+xml,*/*', 'Accept-Language': 'en-US,en;q=0.9' }
    }, (res) => { const elapsed = Date.now() - start; res.destroy(); resolve({ ok: true, status: res.statusCode, headers: res.headers, elapsed }); });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ ok: false, error: 'Timeout' }); });
    req.end();
  });
}

// ── WAF Probe ─────────────────────────────────────────────────────────────────
function probeWAF(targetUrl) {
  return new Promise((resolve) => {
    const parsed = new URL(targetUrl);
    const lib = parsed.protocol === 'https:' ? https : http;
    const port = parsed.port || (parsed.protocol === 'https:' ? 443 : 80);
    const req = lib.request({
      hostname: parsed.hostname, port,
      path: '/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&id=1%20UNION%20SELECT%201--',
      method: 'GET', rejectUnauthorized: false,
      headers: { 'User-Agent': 'Mozilla/5.0 (SecureScout/1.0)', 'Accept': '*/*' }
    }, (res) => { res.destroy(); resolve({ status: res.statusCode, headers: res.headers }); });
    req.on('error', () => resolve({ status: null, headers: {} }));
    req.setTimeout(8000, () => { req.destroy(); resolve({ status: null, headers: {} }); });
    req.end();
  });
}

// ── Security Headers ──────────────────────────────────────────────────────────
function analyzeSecurityHeaders(headers) {
  const checks = [
    {
      key: 'strict-transport-security', label: 'HSTS', weight: 20,
      fix: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
      grade: (v) => {
        if (!v) return { pass: false, note: 'Missing' };
        const maxAge = parseInt((v.match(/max-age=(\d+)/) || [])[1] || 0);
        return maxAge >= 31536000 ? { pass: true, note: `max-age=${maxAge}` } : { pass: 'warn', note: `max-age too short (${maxAge})` };
      }
    },
    {
      key: 'content-security-policy', label: 'CSP', weight: 20,
      fix: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;",
      grade: (v) => v ? { pass: true, note: v.length > 80 ? v.substring(0, 77) + '...' : v } : { pass: false, note: 'Missing' }
    },
    {
      key: 'x-frame-options', label: 'X-Frame-Options', weight: 10,
      fix: 'add_header X-Frame-Options "SAMEORIGIN" always;',
      grade: (v) => v ? { pass: true, note: v } : { pass: false, note: 'Missing — clickjacking risk' }
    },
    {
      key: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 10,
      fix: 'add_header X-Content-Type-Options "nosniff" always;',
      grade: (v) => v === 'nosniff' ? { pass: true, note: 'nosniff' } : { pass: false, note: v ? `Unexpected: ${v}` : 'Missing' }
    },
    {
      key: 'referrer-policy', label: 'Referrer-Policy', weight: 10,
      fix: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
      grade: (v) => v ? { pass: true, note: v } : { pass: 'warn', note: 'Missing (browser default applies)' }
    },
    {
      key: 'permissions-policy', label: 'Permissions-Policy', weight: 10,
      fix: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;',
      grade: (v) => v ? { pass: true, note: v.length > 60 ? v.substring(0, 57) + '...' : v } : { pass: 'warn', note: 'Missing' }
    },
    {
      key: 'x-xss-protection', label: 'X-XSS-Protection', weight: 5,
      fix: 'add_header X-XSS-Protection "1; mode=block" always;',
      grade: (v) => {
        if (!v) return { pass: 'warn', note: 'Missing (legacy header)' };
        if (v.startsWith('1; mode=block')) return { pass: true, note: v };
        return { pass: 'warn', note: v === '0' ? 'Disabled' : v };
      }
    },
    {
      key: 'cache-control', label: 'Cache-Control', weight: 5,
      fix: 'add_header Cache-Control "no-store, no-cache, must-revalidate" always;',
      grade: (v) => v ? { pass: true, note: v } : { pass: 'warn', note: 'Not set' }
    }
  ];

  let score = 0, maxScore = 0;
  const results = [];

  for (const check of checks) {
    maxScore += check.weight;
    const val = headers[check.key];
    const result = check.grade(val);
    if (result.pass === true) score += check.weight;
    else if (result.pass === 'warn') score += check.weight * 0.5;
    results.push({
      label: check.label,
      pass: result.pass,
      note: result.note,
      present: !!val,
      fix: result.pass !== true ? check.fix : null
    });
  }

  const pct = Math.round((score / maxScore) * 100);
  const grade = pct >= 90 ? 'A' : pct >= 75 ? 'B' : pct >= 55 ? 'C' : pct >= 35 ? 'D' : 'F';
  return { grade, score: pct, checks: results };
}

// ── Cookie Security ───────────────────────────────────────────────────────────
function analyzeCookies(headers) {
  const raw = headers['set-cookie'];
  if (!raw || raw.length === 0) return { count: 0, cookies: [] };

  const sessionPattern = /^(sess(ion)?|auth|token|sid|jwt|user|login|remember|csrf|id)/i;

  const cookies = raw.map(line => {
    const parts = line.split(';').map(p => p.trim());
    const name = (parts[0] || '').split('=')[0].trim();
    const attrs = parts.slice(1).map(p => p.toLowerCase());

    const secure   = attrs.some(a => a === 'secure');
    const httpOnly = attrs.some(a => a === 'httponly');
    const ssAttr   = attrs.find(a => a.startsWith('samesite='));
    const sameSite = ssAttr ? ssAttr.split('=')[1] : null;
    const sessionLike = sessionPattern.test(name);

    const issues = [];
    if (!secure)   issues.push('Missing Secure');
    if (!httpOnly) issues.push('Missing HttpOnly');
    if (!sameSite) issues.push('Missing SameSite');
    else if (sameSite === 'none' && !secure) issues.push('SameSite=None without Secure');

    return { name, secure, httpOnly, sameSite, sessionLike, issues };
  });

  return { count: cookies.length, cookies };
}

// ── WAF Detection ─────────────────────────────────────────────────────────────
function detectWAF(headers, probeResult) {
  const allHeaders = { ...headers, ...(probeResult.headers || {}) };
  const headerStr = JSON.stringify(allHeaders).toLowerCase();
  const signatures = [
    { name: 'Cloudflare', keys: ['cf-ray', 'cf-cache-status', 'cf-request-id'], server: 'cloudflare' },
    { name: 'AWS WAF / CloudFront', keys: ['x-amz-cf-id', 'x-amz-request-id'], server: null },
    { name: 'Sucuri', keys: ['x-sucuri-id', 'x-sucuri-cache'], server: 'sucuri' },
    { name: 'Imperva / Incapsula', keys: ['x-iinfo', 'x-cdn'], server: 'incapsula' },
    { name: 'Akamai', keys: ['x-akamai-transformed', 'akamai-origin-hop'], server: 'akamaighost' },
    { name: 'F5 BIG-IP', keys: ['x-wa-info', 'x-cnection'], server: 'big-ip' },
    { name: 'Barracuda WAF', keys: ['barra_counter_session', 'bwce'], server: null },
    { name: 'Fastly', keys: ['x-fastly-request-id', 'x-served-by'], server: 'fastly' },
    { name: 'Nginx (with ModSecurity)', keys: [], server: null, pattern: 'mod_security' }
  ];
  const blocked = [403, 406, 429, 444, 400].includes(probeResult.status);
  let detected = null;
  for (const sig of signatures) {
    const keyMatch = sig.keys.some(k => allHeaders[k] !== undefined);
    const serverMatch = sig.server && (allHeaders['server'] || '').toLowerCase().includes(sig.server);
    const patternMatch = sig.pattern && headerStr.includes(sig.pattern);
    if (keyMatch || serverMatch || patternMatch) { detected = sig.name; break; }
  }
  return {
    detected: !!detected || blocked,
    name: detected || (blocked ? 'Unknown WAF (probe blocked)' : null),
    probeBlocked: blocked,
    probeStatus: probeResult.status,
    confidence: detected ? 'high' : blocked ? 'medium' : 'none'
  };
}

// ── Server Info ───────────────────────────────────────────────────────────────
function analyzeServer(headers, ip) {
  const server = headers['server'] || 'Unknown';
  const sl = server.toLowerCase();
  let software = 'Unknown';
  if (sl.includes('nginx')) software = 'Nginx';
  else if (sl.includes('apache')) software = 'Apache';
  else if (sl.includes('iis')) software = 'Microsoft IIS';
  else if (sl.includes('cloudflare')) software = 'Cloudflare';
  else if (sl.includes('openresty')) software = 'OpenResty (Nginx)';
  else if (sl.includes('litespeed')) software = 'LiteSpeed';
  else if (sl.includes('caddy')) software = 'Caddy';
  else if (server !== 'Unknown') software = server;
  return { raw: server, software, poweredBy: headers['x-powered-by'] || null, via: headers['via'] || null, ip: ip || 'Unknown' };
}

// ── Browser Support ───────────────────────────────────────────────────────────
function buildBrowserNotes(tls12, tls13, http2) {
  const notes = [];
  if (tls13) notes.push('Modern browsers (TLS 1.3)');
  if (tls12) notes.push('Legacy browsers (TLS 1.2)');
  if (!tls12 && !tls13) notes.push('TLS not detected — may be HTTP only');
  notes.push(http2 ? 'HTTP/2 supported' : 'HTTP/1.1 only');
  if (tls13 && http2) notes.push('Chrome 70+, Firefox 63+, Safari 12.1+, Edge 79+');
  else if (tls12) notes.push('Chrome 30+, Firefox 27+, Safari 7+, IE 11+');
  return notes;
}

// ── Full Scan ─────────────────────────────────────────────────────────────────
async function scanService(service) {
  const parsed = new URL(service.url);
  const host = parsed.hostname;
  const isHTTPS = parsed.protocol === 'https:';
  const sslHost = service.sslHost || host;
  const checkSsl = isHTTPS || !!service.sslHost;

  const [ssl, headersResult, probeResult, tls12, tls13, http2, dnsChecks, httpRedirect] = await Promise.all([
    checkSsl ? checkSSL(sslHost) : Promise.resolve({ ok: false, error: 'Not HTTPS' }),
    fetchHeaders(service.url),
    probeWAF(service.url),
    checkSsl ? probeTLS(sslHost, 443, 'TLSv1.2') : Promise.resolve({ supported: false }),
    checkSsl ? probeTLS(sslHost, 443, 'TLSv1.3') : Promise.resolve({ supported: false }),
    checkSsl ? probeHTTP2(sslHost) : Promise.resolve(false),
    checkDNS(sslHost),
    isHTTPS ? checkHTTPRedirect(host) : Promise.resolve({ checked: false, redirects: false, status: null, location: null })
  ]);

  const ip = dnsChecks.ips?.[0] || null;
  const headers = headersResult.ok ? headersResult.headers : {};

  const result = {
    name: service.name,
    url: service.url,
    scannedAt: new Date().toISOString(),
    reachable: headersResult.ok,
    responseTime: headersResult.elapsed || null,
    httpStatus: headersResult.status || null,
    ssl,
    dns: dnsChecks,
    securityHeaders: headersResult.ok ? analyzeSecurityHeaders(headers) : null,
    httpRedirect,
    waf: headersResult.ok ? detectWAF(headers, probeResult) : null,
    cookies: headersResult.ok ? analyzeCookies(headers) : null,
    server: headersResult.ok ? analyzeServer(headers, ip) : null,
    browserSupport: {
      tls12: tls12.supported,
      tls13: tls13.supported,
      http2,
      notes: buildBrowserNotes(tls12.supported, tls13.supported, http2)
    }
  };

  // Alerts: compare against last known state
  const prev = history[service.url]?.[history[service.url].length - 1];
  checkAlerts(prev, result);

  appendHistory(result);
  return result;
}

// ── In-memory cache ───────────────────────────────────────────────────────────
const cache = {};

// ── Public Status Page ────────────────────────────────────────────────────────
function getPublicStatus() {
  const publicSvcs = config.services.filter(s => s.public);
  return {
    title: config.statusPageTitle || 'System Status',
    lastUpdated: new Date().toISOString(),
    services: publicSvcs.map(s => {
      const r = cache[s.url];
      if (!r) return { name: s.name, status: 'unknown', grade: null, sslDaysLeft: null, responseTime: null, scannedAt: null };
      let status = 'operational';
      if (!r.reachable) {
        status = 'outage';
      } else {
        const grade = r.securityHeaders?.grade;
        const daysLeft = r.ssl?.ok ? r.ssl.daysLeft : null;
        if (daysLeft !== null && daysLeft < 14) status = 'outage';
        else if (grade === 'D' || grade === 'F' || (daysLeft !== null && daysLeft < 30)) status = 'degraded';
      }
      return { name: s.name, status, grade: r.securityHeaders?.grade || null, sslDaysLeft: r.ssl?.ok ? r.ssl.daysLeft : null, responseTime: r.responseTime || null, scannedAt: r.scannedAt || null };
    })
  };
}

const STATUS_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>System Status</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f1117;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
.page{max-width:760px;margin:0 auto;padding:48px 20px 40px}
.hd{text-align:center;margin-bottom:36px}
.hd-logo{font-size:2.8rem;margin-bottom:6px}
.hd-name{font-size:1.4rem;font-weight:700;letter-spacing:-.5px}
.hd-name span{color:#22d3ee}
.hd-sub{color:#8892b0;font-size:.8rem;margin-top:4px}
.banner{border-radius:14px;padding:16px 22px;margin-bottom:22px;display:flex;align-items:center;gap:14px}
.banner.ok{background:rgba(74,222,128,.09);border:1px solid rgba(74,222,128,.28)}
.banner.warn{background:rgba(251,191,36,.09);border:1px solid rgba(251,191,36,.28)}
.banner.err{background:rgba(248,113,113,.09);border:1px solid rgba(248,113,113,.28)}
.banner.info{background:rgba(46,50,80,.5);border:1px solid rgba(96,165,250,.2)}
.bdot{width:14px;height:14px;border-radius:50%;flex-shrink:0}
.bdot.ok{background:#4ade80;animation:pg 2s infinite}
.bdot.warn{background:#fbbf24}
.bdot.err{background:#f87171;animation:pr 1s infinite}
.bdot.info{background:#2e3250}
@keyframes pg{0%,100%{opacity:1}50%{opacity:.55}}
@keyframes pr{0%,100%{opacity:1}50%{opacity:.4}}
.btext{font-size:1.05rem;font-weight:700}
.btext.ok{color:#4ade80}.btext.warn{color:#fbbf24}.btext.err{color:#f87171}.btext.info{color:#8892b0}
.bmeta{font-size:.73rem;color:#8892b0;margin-top:2px}
.list{display:grid;gap:8px;margin-bottom:28px}
.row{background:#1a1d27;border:1px solid #2e3250;border-radius:10px;padding:13px 18px;display:flex;align-items:center;gap:12px}
.rdot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.rdot.operational{background:#4ade80}.rdot.degraded{background:#fbbf24}
.rdot.outage{background:#f87171}.rdot.unknown{background:#2e3250}
.rname{flex:1;font-weight:600;font-size:.88rem}
.rmeta{display:flex;gap:7px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.gc{width:26px;height:26px;border-radius:6px;display:inline-flex;align-items:center;justify-content:center;font-size:.78rem;font-weight:800}
.gA{background:rgba(74,222,128,.2);color:#4ade80}.gB{background:rgba(96,165,250,.2);color:#60a5fa}
.gC{background:rgba(251,191,36,.2);color:#fbbf24}.gD{background:rgba(251,146,60,.2);color:#fb923c}
.gF{background:rgba(248,113,113,.2);color:#f87171}.g-{background:rgba(46,50,80,.5);color:#8892b0}
.ssl{font-size:.67rem;padding:2px 7px;border-radius:8px;font-weight:600}
.ssl-ok{background:rgba(74,222,128,.1);color:#4ade80;border:1px solid rgba(74,222,128,.3)}
.ssl-w{background:rgba(251,191,36,.1);color:#fbbf24;border:1px solid rgba(251,191,36,.3)}
.ssl-c{background:rgba(248,113,113,.1);color:#f87171;border:1px solid rgba(248,113,113,.3)}
.rt{font-size:.7rem;color:#8892b0;min-width:48px;text-align:right}
.slabel{font-size:.7rem;font-weight:600;min-width:76px;text-align:right}
.slabel.operational{color:#4ade80}.slabel.degraded{color:#fbbf24}
.slabel.outage{color:#f87171}.slabel.unknown{color:#8892b0}
.empty{text-align:center;padding:48px;color:#8892b0;font-size:.85rem;line-height:1.7}
.rbar{text-align:center;font-size:.7rem;color:#8892b0;margin-bottom:14px}
.foot{text-align:center;color:#8892b0;font-size:.7rem;border-top:1px solid #2e3250;padding-top:14px}
.foot a{color:#22d3ee;text-decoration:none}
@media(max-width:480px){.rt,.ssl{display:none}.slabel{min-width:60px}}
</style>
</head>
<body>
<div class="page">
  <div class="hd">
    <div class="hd-logo">🛡️</div>
    <div class="hd-name">Secure<span>Scout</span></div>
    <div class="hd-sub" id="pageTitle">System Status</div>
  </div>
  <div class="banner" id="banner">
    <div class="bdot" id="bdot"></div>
    <div>
      <div class="btext" id="btext">Loading…</div>
      <div class="bmeta" id="bmeta"></div>
    </div>
  </div>
  <div class="list" id="list"></div>
  <div class="rbar" id="rbar"></div>
  <div class="foot">Powered by <a href="/">SecureScout</a></div>
</div>
<script>
var countdown = 60;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function ago(iso){if(!iso)return 'never';var d=Math.floor((Date.now()-new Date(iso))/1000);return d<60?d+'s ago':d<3600?Math.floor(d/60)+'m ago':Math.floor(d/3600)+'h ago'}
function sslChip(days){if(days===null||days===undefined)return '';var cls=days>30?'ssl-ok':days>14?'ssl-w':'ssl-c';return '<span class="ssl '+cls+'">'+days+'d SSL</span>'}
function gradeChip(g){if(!g)return '<span class="gc g-">—</span>';return '<span class="gc g'+g+'">'+g+'</span>'}
function render(data){
  var title=data.title||'System Status';
  document.getElementById('pageTitle').textContent=title;
  document.title=title+' \xb7 SecureScout';
  var svcs=data.services||[];
  var overall=svcs.length===0?'none':svcs.some(function(s){return s.status==='outage'})?'outage':svcs.some(function(s){return s.status==='degraded'||s.status==='unknown'})?'warn':'ok';
  var bclass={outage:'err',warn:'warn',ok:'ok',none:'info'}[overall]||'warn';
  var labels={ok:'All Systems Operational',warn:'Partial Degradation',err:'Service Outage',info:'No Public Services Configured'};
  document.getElementById('banner').className='banner '+bclass;
  var dot=document.getElementById('bdot');dot.className='bdot '+bclass;
  var bt=document.getElementById('btext');bt.className='btext '+bclass;bt.textContent=labels[bclass]||'Status Unknown';
  document.getElementById('bmeta').textContent='Updated '+ago(data.lastUpdated)+' \xb7 '+svcs.length+' service'+(svcs.length!==1?'s':'')+' monitored';
  var list=document.getElementById('list');
  if(svcs.length===0){list.innerHTML='<div class="empty">No public services configured yet.<br>An admin can mark services as public from the dashboard.</div>';return}
  list.innerHTML=svcs.map(function(s){
    var sl={operational:'Operational',degraded:'Degraded',outage:'Outage',unknown:'Unknown'}[s.status]||s.status;
    return '<div class="row">'+
      '<div class="rdot '+s.status+'"></div>'+
      '<div class="rname">'+esc(s.name)+'</div>'+
      '<div class="rmeta">'+gradeChip(s.grade)+sslChip(s.sslDaysLeft)+(s.responseTime?'<span class="rt">'+s.responseTime+' ms</span>':'')+
      '<span class="slabel '+s.status+'">'+sl+'</span></div></div>'
  }).join('')
}
async function load(){try{var r=await fetch('/api/public/status');if(r.ok)render(await r.json())}catch(e){}countdown=60}
function tick(){countdown--;var rb=document.getElementById('rbar');if(countdown<=0){load()}else{rb.textContent='Refreshes in '+countdown+'s'}}
load();setInterval(tick,1000);
</script>
</body>
</html>`;

// ── HTTP Server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  const json = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, DELETE, PATCH, OPTIONS', 'Content-Type': 'application/json' };

  // ── Security headers on every response (the frontend is a single inline
  // <script>/<style> page with onclick handlers, hence 'unsafe-inline') ──
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

  if (req.method === 'OPTIONS') { res.writeHead(204, json); res.end(); return; }

  // ── Public routes (no auth) ──
  if (pathname === '/api/setup' && req.method === 'POST') {
    const setupIp = getClientIp(req);
    if (isRateLimited(setupIp)) { res.writeHead(429, json); res.end(JSON.stringify({ error: 'Too many attempts. Try again later.' })); return; }
    recordLoginFailure(setupIp);
    if (config.users.length > 0) { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Setup already complete' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(body);
        if (!username || username.trim().length < 3) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Username must be at least 3 characters' })); return; }
        if (!password || password.length < 8) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Password must be at least 8 characters' })); return; }
        const user = { id: crypto.randomUUID(), username: username.trim().toLowerCase(), password: hashPassword(password), role: 'admin', createdAt: new Date().toISOString() };
        config.users.push(user);
        saveConfig();
        const token = createSession(user);
        res.writeHead(200, json);
        res.end(JSON.stringify({ token, role: user.role, username: user.username }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    const ip = getClientIp(req);
    if (isRateLimited(ip)) { res.writeHead(429, json); res.end(JSON.stringify({ error: 'Too many login attempts. Try again later.' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { username, password } = JSON.parse(body);
        if (!config.users.length) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'No users configured' })); return; }
        const user = config.users.find(u => u.username === username?.trim().toLowerCase());
        if (!user || !verifyPassword(password, user.password)) {
          recordLoginFailure(ip);
          res.writeHead(401, json); res.end(JSON.stringify({ error: 'Invalid username or password' })); return;
        }
        loginAttempts.delete(ip);
        const token = createSession(user);
        res.writeHead(200, json);
        res.end(JSON.stringify({ token, role: user.role, username: user.username }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  // ── Status (public, returns auth context) ──
  if (pathname === '/api/status') {
    const session = getSession(req);
    res.writeHead(200, json);
    res.end(JSON.stringify({ setupDone: config.users.length > 0, authenticated: !!session, role: session?.role || null, username: session?.username || null }));
    return;
  }

  if (pathname === '/api/public/status' && req.method === 'GET') {
    res.writeHead(200, { ...json, 'Cache-Control': 'no-cache' });
    res.end(JSON.stringify(getPublicStatus()));
    return;
  }

  if (pathname === '/') {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  if (pathname === '/status' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(STATUS_PAGE_HTML);
    return;
  }

  // ── Auth required for all routes below ──
  const session = getSession(req);
  if (!session) { res.writeHead(401, json); res.end(JSON.stringify({ error: 'Unauthorized' })); return; }

  if (pathname === '/api/logout' && req.method === 'POST') {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (token) sessions.delete(token);
    res.writeHead(200, json); res.end(JSON.stringify({ ok: true })); return;
  }

  if (pathname === '/api/change-password' && req.method === 'POST') {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { currentPassword, newPassword } = JSON.parse(body);
        const user = config.users.find(u => u.id === session.userId);
        if (!user) { res.writeHead(404, json); res.end(JSON.stringify({ error: 'User not found' })); return; }
        if (!verifyPassword(currentPassword, user.password)) { res.writeHead(401, json); res.end(JSON.stringify({ error: 'Current password incorrect' })); return; }
        if (!newPassword || newPassword.length < 8) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'New password must be at least 8 characters' })); return; }
        user.password = hashPassword(newPassword);
        saveConfig();
        for (const [t, s] of sessions) { if (s.userId === session.userId) sessions.delete(t); }
        const newToken = createSession(user);
        res.writeHead(200, json); res.end(JSON.stringify({ token: newToken }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  // ── User management (admin only) ──
  if (pathname === '/api/users' && req.method === 'GET') {
    if (session.role !== 'admin') { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Admin required' })); return; }
    res.writeHead(200, json);
    res.end(JSON.stringify(config.users.map(u => ({ id: u.id, username: u.username, role: u.role, createdAt: u.createdAt }))));
    return;
  }

  if (pathname === '/api/users' && req.method === 'POST') {
    if (session.role !== 'admin') { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Admin required' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { username, password, role } = JSON.parse(body);
        if (!username || username.trim().length < 3) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Username must be at least 3 characters' })); return; }
        if (!password || password.length < 8) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Password must be at least 8 characters' })); return; }
        if (!['admin', 'readonly'].includes(role)) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Role must be admin or readonly' })); return; }
        const uname = username.trim().toLowerCase();
        if (config.users.find(u => u.username === uname)) { res.writeHead(409, json); res.end(JSON.stringify({ error: 'Username already exists' })); return; }
        const user = { id: crypto.randomUUID(), username: uname, password: hashPassword(password), role, createdAt: new Date().toISOString() };
        config.users.push(user);
        saveConfig();
        res.writeHead(201, json); res.end(JSON.stringify({ id: user.id, username: user.username, role: user.role, createdAt: user.createdAt }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/users' && req.method === 'DELETE') {
    if (session.role !== 'admin') { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Admin required' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { username } = JSON.parse(body);
        if (username === session.username) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Cannot delete your own account' })); return; }
        const idx = config.users.findIndex(u => u.username === username);
        if (idx === -1) { res.writeHead(404, json); res.end(JSON.stringify({ error: 'User not found' })); return; }
        const deleted = config.users.splice(idx, 1)[0];
        for (const [t, s] of sessions) { if (s.userId === deleted.id) sessions.delete(t); }
        saveConfig();
        res.writeHead(200, json); res.end(JSON.stringify({ ok: true }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/users' && req.method === 'PATCH') {
    if (session.role !== 'admin') { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Admin required' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { username, role } = JSON.parse(body);
        if (username === session.username) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Cannot change your own role' })); return; }
        if (!['admin', 'readonly'].includes(role)) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'Role must be admin or readonly' })); return; }
        const user = config.users.find(u => u.username === username);
        if (!user) { res.writeHead(404, json); res.end(JSON.stringify({ error: 'User not found' })); return; }
        user.role = role;
        for (const [, s] of sessions) { if (s.userId === user.id) s.role = role; }
        saveConfig();
        res.writeHead(200, json); res.end(JSON.stringify({ ok: true, username: user.username, role: user.role }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/services' && req.method === 'GET') {
    res.writeHead(200, json);
    res.end(JSON.stringify(config.services.map(s => ({ name: s.name, url: s.url, sslHost: s.sslHost || null, public: !!s.public }))));
    return;
  }

  if (pathname === '/api/services' && req.method === 'POST') {
    if (session.role !== 'admin') { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Admin required' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', async () => {
      try {
        const { name, url: serviceUrl, sslHost } = JSON.parse(body);
        if (!name || !serviceUrl) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'name and url are required' })); return; }
        new URL(serviceUrl);
        if (config.services.find(s => s.url === serviceUrl)) { res.writeHead(409, json); res.end(JSON.stringify({ error: 'Service with this URL already exists' })); return; }
        const service = { name, url: serviceUrl };
        if (sslHost) service.sslHost = sslHost;
        config.services.push(service);
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
        const result = await scanService(service);
        cache[service.url] = result;
        res.writeHead(201, json); res.end(JSON.stringify(result));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/services' && req.method === 'DELETE') {
    if (session.role !== 'admin') { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Admin required' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { url: serviceUrl } = JSON.parse(body);
        const idx = config.services.findIndex(s => s.url === serviceUrl);
        if (idx === -1) { res.writeHead(404, json); res.end(JSON.stringify({ error: 'Service not found' })); return; }
        config.services.splice(idx, 1);
        delete cache[serviceUrl];
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
        res.writeHead(200, json); res.end(JSON.stringify({ ok: true }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/services' && req.method === 'PATCH') {
    if (session.role !== 'admin') { res.writeHead(403, json); res.end(JSON.stringify({ error: 'Admin required' })); return; }
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try {
        const { url: serviceUrl, public: isPublic } = JSON.parse(body);
        const svc = config.services.find(s => s.url === serviceUrl);
        if (!svc) { res.writeHead(404, json); res.end(JSON.stringify({ error: 'Service not found' })); return; }
        svc.public = !!isPublic;
        saveConfig();
        res.writeHead(200, json); res.end(JSON.stringify({ ok: true, public: svc.public }));
      } catch (e) { res.writeHead(400, json); res.end(JSON.stringify({ error: e.message })); }
    });
    return;
  }

  if (pathname === '/api/scan/all') {
    res.writeHead(200, json);
    const results = await Promise.all(config.services.map(s => {
      cache[s.url] = null;
      return scanService(s).then(r => { cache[s.url] = r; return r; });
    }));
    res.end(JSON.stringify(results));
    return;
  }

  if (pathname === '/api/scan') {
    const target = parsed.query.url;
    const service = config.services.find(s => s.url === target);
    if (!service) { res.writeHead(404, json); res.end(JSON.stringify({ error: 'Service not found' })); return; }
    res.writeHead(200, json);
    const result = await scanService(service);
    cache[service.url] = result;
    res.end(JSON.stringify(result));
    return;
  }

  if (pathname === '/api/dkim') {
    const domain = parsed.query.domain;
    const selector = parsed.query.selector;
    if (!domain || !selector) { res.writeHead(400, json); res.end(JSON.stringify({ error: 'domain and selector are required' })); return; }
    if (!/^[a-zA-Z0-9._-]+$/.test(selector) || !/^[a-zA-Z0-9._-]+$/.test(domain)) {
      res.writeHead(400, json); res.end(JSON.stringify({ error: 'Invalid domain or selector' })); return;
    }
    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      const record = records.flat().join('');
      res.writeHead(200, json);
      res.end(JSON.stringify({ found: true, selector, domain, record }));
    } catch {
      res.writeHead(200, json);
      res.end(JSON.stringify({ found: false, selector, domain, record: null }));
    }
    return;
  }

  if (pathname === '/api/results') {
    res.writeHead(200, json);
    res.end(JSON.stringify(Object.values(cache).filter(Boolean)));
    return;
  }

  if (pathname === '/api/history') {
    res.writeHead(200, json);
    res.end(JSON.stringify(history));
    return;
  }

  res.writeHead(404, json);
  res.end(JSON.stringify({ error: 'Not found' }));
});

const PORT = config.port || 3002;
server.listen(PORT, () => {
  console.log(`SecureScout running on http://localhost:${PORT}`);
  console.log('Running initial scan...');
  Promise.all(config.services.map(s => scanService(s).then(r => { cache[s.url] = r; })))
    .then(() => console.log('Initial scan complete.'));
});

if (config.scanIntervalMinutes > 0) {
  setInterval(() => {
    config.services.forEach(s => scanService(s).then(r => { cache[s.url] = r; }));
  }, config.scanIntervalMinutes * 60 * 1000);
}
