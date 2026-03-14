![Banner](https://www.upload.ee/image/18524137/k9shield-banner.jpeg)

# K9Shield

Express middleware for DDoS protection, rate limiting, and web application security. Requests are evaluated by a priority-based policy engine of configurable rules.

## Installation

```bash
bun add k9shield
# or
npm install k9shield
```

## Quick Start

```javascript
const express = require('express');
const K9Shield = require('k9shield');

const app = express();
const shield = new K9Shield({
  security: { trustProxy: false, allowPrivateIPs: true },
  rateLimiting: {
    enabled: true,
    default: {
      maxRequests: 100,
      timeWindow: 60000,
      banDuration: 300000,
      retryAfter: 60,
      throttleDuration: 30000,
      throttleDelay: 1000
    }
  },
  logging: { enable: true, level: 'info', maxLogSize: 5000, archiveLimit: 5, archives: [] }
});

app.use(shield.protect());
app.get('/', (req, res) => res.json({ status: 'ok' }));
app.listen(3000);
```

## Policy Engine

Each request is evaluated against rules in priority order. The first matching rule returns the decision; no match yields allow.

| Rule | Priority | Decision |
|------|----------|----------|
| WhitelistRule | 200 | ALLOW_BYPASS |
| BlacklistRule | 100 | BLOCK |
| DdosRule | 90 | BLOCK |
| BypassRouteRule | 85 | ALLOW_BYPASS |
| SecurityPolicyRule | 80 | BLOCK |
| CsrfRule | 75 | BLOCK (optional) |
| RateLimitRule | 50 | THROTTLE / BLOCK |

Bypass routes are evaluated after blacklist and DDoS; a blocked IP cannot use a bypass path.

## Configuration

Constructor accepts a single options object. Main sections:

- **security** — `trustProxy`, `trustedProxies`, `allowPrivateIPs`, `maxBodySize`, `allowedMethods`, `requestHeaderWhitelist`, `securityHeaders`, `csp`, `permissions`, `corsOrigin`, `csrfProtection` (optional)
- **rateLimiting** — `enabled`, `default` (maxRequests, timeWindow, banDuration, retryAfter, throttleDuration, throttleDelay), `routes`, `routePatterns`
- **ddosProtection** — `enabled`, `config` (timeWindow, blockDuration, requestThreshold, burstThreshold, slowRequestThreshold, rateLimitByPath)
- **logging** — `enable`, `level`, `maxLogSize`, `archiveLimit`, `archives`
- **errorHandling** — `customHandlers`, `defaultResponses` (per reason code)
- **bypassRoutes** — array of path strings or RegExp
- **onSecurityEvent** — optional `(event, payload) => {}` callback
- **updateCheck** — set `false` to disable npm version check on startup

Behind a reverse proxy, set `security.trustProxy: true` and `security.trustedProxies` to proxy CIDRs or IPs. Client IP is taken from the first non-trusted hop in `X-Forwarded-For` (right to left).

```javascript
security: {
  trustProxy: true,
  trustedProxies: ['10.0.0.0/8', '172.16.0.0/12', '192.168.1.1']
}
```

### Full reference

Complete config shape and available options:

```javascript
const shield = new K9Shield({
  security: {
    trustProxy: false,
    trustedProxies: [],
    allowPrivateIPs: false,
    maxBodySize: 1048576,
    checkStringMaxLength: 32768,
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    requestHeaderWhitelist: [],
    userAgentBlacklist: [],
    refererBlacklist: [],
    securityHeaders: {},
    csp: {},
    permissions: {},
    corsOrigin: undefined,
    csrfProtection: {
      enabled: false,
      originWhitelist: [],
      requireOriginOrReferer: false
    }
  },

  rateLimiting: {
    enabled: true,
    default: {
      maxRequests: 10,
      timeWindow: 60000,
      banDuration: 3600000,
      retryAfter: 60,
      throttleDuration: 60000,
      throttleDelay: 1000
    },
    routes: {},
    routePatterns: []
  },

  ddosProtection: {
    enabled: true,
    config: {
      maxConnections: 100,
      timeWindow: 60000,
      blockDuration: 3600000,
      requestThreshold: 100,
      burstThreshold: 20,
      slowRequestThreshold: 5,
      rateLimitByPath: {}
    }
  },

  logging: {
    enable: true,
    level: 'info',
    maxLogSize: 5000,
    archiveLimit: 5,
    archives: []
  },

  errorHandling: {
    includeErrorDetails: false,
    customHandlers: {},
    defaultResponses: {
      methodNotAllowed:   { status: 405, message: 'Method not allowed' },
      accessDenied:       { status: 403, message: 'Access denied' },
      payloadTooLarge:    { status: 413, message: 'Payload too large' },
      invalidIP:          { status: 400, message: 'Invalid IP address' },
      suspiciousRequest:  { status: 403, message: 'Suspicious request pattern detected' },
      rateLimitExceeded:  { status: 429, message: 'Too many requests' },
      permanentlyBlocked: { status: 403, message: 'Permanently blocked' },
      ddosAttack:         { status: 429, message: 'DDoS attack detected' },
      internalError:      { status: 500, message: 'Internal server error' },
      csrfOriginMismatch: { status: 403, message: 'Invalid or missing Origin' },
      csrfRefererMismatch: { status: 403, message: 'Invalid Referer' },
      csrfMissingOriginOrReferer: { status: 403, message: 'Origin or Referer required' }
    }
  },

  bypassRoutes: [],
  onSecurityEvent: null,
  updateCheck: true
});
```

- **security** — Proxy and IP: `trustProxy`, `trustedProxies`, `allowPrivateIPs`. Limits: `maxBodySize`, `checkStringMaxLength`, `allowedMethods`, `requestHeaderWhitelist`. Lists: `userAgentBlacklist`, `refererBlacklist`. Headers: `securityHeaders`, `csp`, `permissions`, `corsOrigin`. Optional: `csrfProtection` (`enabled`, `originWhitelist`, `requireOriginOrReferer`).
- **rateLimiting.default** — `maxRequests`, `timeWindow` (ms), `banDuration`, `retryAfter` (s), `throttleDuration`, `throttleDelay`. **routes** — path → method → same shape. **routePatterns** — `[{ pattern: string|RegExp, config: { [method]: {...}, default: {...} } }]`.
- **ddosProtection.config** — `timeWindow`, `blockDuration`, `requestThreshold`, `burstThreshold`, `slowRequestThreshold`, `rateLimitByPath` (path pattern → max req/min).
- **errorHandling.customHandlers** — reason code → `(res, data) => {}`. **defaultResponses** — reason code → `{ status, message }`.
- **onSecurityEvent** — `(event, payload) => {}` for `blocked`, `throttled`, `allowed_bypass`.

## API

| Method | Description |
|--------|-------------|
| `shield.protect()` | Express middleware. Mount with `app.use(shield.protect())`. |
| `shield.blockIP(ip)` / `shield.unblockIP(ip)` | Add or remove IP (or CIDR) from blacklist. |
| `shield.whitelistIP(ip)` / `shield.unwhitelistIP(ip)` | Add or remove IP (or CIDR) from whitelist. |
| `shield.addSuspiciousPattern(regex)` | Register a pattern for request scanning. |
| `shield.setConfig(config)` | Update config (merged and validated). |
| `shield.getLogs()` / `shield.getArchivedLogs()` | In-memory and archived logs. |
| `shield.scanForSensitiveData(data)` | Returns `{ hasSensitiveData, detectedData }`. |
| `shield.maskSensitiveData(data)` | Returns data with sensitive fields masked. |
| `shield.encryptSensitiveData(data)` / `shield.decryptSensitiveData(encrypted)` | Async encrypt/decrypt (requires configured DLP key for persistence). |
| `shield.addCustomSensitivePattern(type, regex)` | Add custom DLP pattern. |
| `shield.reset()` | Clear blocks, rate-limit state, logs, and metrics. |
| `shield.getMetrics()` | Returns `{ requestsAllowed, requestsBlocked, requestsThrottled, blocksByReason, lastReset }`. |

## Data Loss Prevention

DLP supports scan, mask, and encrypt/decrypt. Built-in patterns: `creditCard`, `email`, `ssn`, `phoneNumber`, `iban`, `passport`.

```javascript
const result = shield.scanForSensitiveData(req.body);
if (result.hasSensitiveData) {
  const safe = shield.maskSensitiveData(req.body);
}
```

For persistent encryption across restarts, set a 64‑character hex key via `config.dlp.encryptionKey` or `K9SHIELD_DLP_KEY`. Without it, an ephemeral key is used and encrypted data is not recoverable after restart.

## Custom Rules

```javascript
const Rule = require('k9shield/src/policy-engine/Rule');

const rule = new Rule({
  name: 'BlockTorExitNodes',
  priority: 95,
  condition: async ({ ip }) => torExitNodeSet.has(ip),
  action: () => ({ decision: 'BLOCK', reason: 'accessDenied' })
});
shield.policyEngine.addRule(rule);
```

Decisions: `BLOCK`, `ALLOW_BYPASS`. Return `null` from `condition` to fall through to the next rule.

## Security Coverage

| Category | Coverage |
|----------|----------|
| DDoS | Requests/sec and /min, burst, slow-body |
| Anomaly | Payload/header/URL size, pattern uniformity, timing |
| SQLi / XSS | Common patterns and encoded variants |
| Path traversal | `../` and encoded forms |
| Command injection | Shell metacharacters, known interpreter paths |
| LFI / RFI | PHP wrappers, zip/phar, gopher, data URIs |
| Deserialization | PHP/Java-style object and XML entity patterns |
| Encoding evasion | High %-encoding, Unicode, special-character anomalies |

Block state uses per-IP expiry; repeated offences increase block duration (capped at 24h). Rate limiter uses a per-IP sliding window; repeated violations can lead to permanent blacklist entry.

## HTTP Responses

| Code | When |
|------|------|
| 200 | Allowed |
| 400 | Invalid or unspoofable client IP |
| 403 | Blacklisted or suspicious request |
| 405 | Method not in allowed list |
| 413 | Body exceeds maxBodySize |
| 429 | Rate limit or DDoS block |
| 500 | Internal error |

---

**License:** MIT — [LICENSE](./LICENSE)  
**Contact:** hi@k9crypt.xyz
