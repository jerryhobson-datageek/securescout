# SecureScout

A self-hosted security dashboard for monitoring your web services. Checks SSL certificates, security headers, WAF detection, server info, and browser support — all from a single page.

![SecureScout Dashboard](https://img.shields.io/badge/Node.js-20+-green) ![License](https://img.shields.io/badge/license-MIT-blue) ![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

## Features

- **SSL Certificate** — expiry countdown, issuer, cipher suite, protocol, self-signed detection
- **Security Headers** — grades A–F across 8 headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection, Cache-Control)
- **WAF Detection** — fingerprints Cloudflare, AWS WAF, Sucuri, Imperva, Akamai, F5 BIG-IP, Barracuda, Fastly; fires a live XSS + SQLi probe to test blocking
- **Server Info** — software, IP address, HTTP status, response time, X-Powered-By
- **Browser Support** — TLS 1.2/1.3 and HTTP/2 probed directly, with human-readable compatibility notes

## Tech Stack

- Node.js 20+ (stdlib only — zero npm dependencies)
- Vanilla JS frontend, no frameworks
- Single page: `server.js` + `index.html` + `config.json`

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/jerryhobson-datageek/securescout.git
cd securescout
```

### 2. Configure your services

Edit `config.json`:

```json
{
  "port": 3002,
  "scanIntervalMinutes": 60,
  "services": [
    {
      "name": "My Site",
      "host": "example.com",
      "url": "https://example.com"
    }
  ]
}
```

| Field | Description |
|---|---|
| `port` | Port the dashboard listens on |
| `scanIntervalMinutes` | How often to auto-rescan (0 = disabled) |
| `services` | List of services to monitor |

### 3. Run

```bash
node server.js
```

Open `http://localhost:3002` in your browser.

## Deployment (systemd)

```bash
# Copy files
cp server.js index.html /opt/securescout/
# config.json — copy only on first deploy, do not overwrite

# Create service
cat > /etc/systemd/system/securescout.service << EOF
[Unit]
Description=SecureScout Security Dashboard
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/securescout
ExecStart=/usr/bin/node /opt/securescout/server.js
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now securescout
```

## Running Behind a Reverse Proxy (Nginx Proxy Manager)

If NPM runs in Docker, use the Docker bridge gateway IP instead of `localhost` as the forward host:

```
Forward Host: 172.17.0.1
Forward Port: 3002
```

Enable SSL, force HTTPS, and turn on HTTP/2 in the NPM proxy host settings.

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard UI |
| `GET /api/services` | List configured services |
| `GET /api/scan/all` | Trigger a full scan of all services |
| `GET /api/scan?url=<url>` | Scan a single service |
| `GET /api/results` | Return cached scan results |

## WAF Detection Method

SecureScout uses two techniques:

1. **Header fingerprinting** — checks response headers for known WAF signatures (e.g. `CF-Ray` for Cloudflare, `X-Sucuri-ID` for Sucuri)
2. **Probe request** — sends a request with a URL-encoded XSS + SQLi payload and checks if the response is blocked (HTTP 403/406/429/444)

## License

MIT
