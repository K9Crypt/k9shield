![Banner](https://www.upload.ee/image/18524137/k9shield-banner.jpeg)

# K9Shield

Production-grade Express.js middleware for DDoS protection, rate limiting, and web application security. Built around a priority-based policy engine that evaluates every request through layered, independent security rules.

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
  security: {
    trustProxy: false,
    allowPrivateIPs: true
  },
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
  logging: {
    enable: true,
    level: 'info',
    maxLogSize: 5000,
    archiveLimit: 5,
    archives: []
  }
});

app.use(shield.protect());

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);
```

---

## Policy Engine

Every request passes through a chain of prioritized rules. The first rule that matches short-circuits evaluation and returns its decision.

| Rule | Priority | Decision |
|---|---|---|
| `WhitelistRule` | 200 | `ALLOW_BYPASS` — trusted IPs skip all further checks |
| `BlacklistRule` | 100 | `BLOCK` — permanently or temporarily banned IPs |
| `DdosRule` | 90 | `BLOCK` — anomaly-score based DDoS detection |
| `BypassRouteRule` | 85 | `ALLOW_BYPASS` — health/metrics routes, post security gates |
| `SecurityPolicyRule` | 80 | `BLOCK` — method, payload, and pattern validation |
| `CsrfRule` | 75 | `BLOCK` — Origin/Referer validation for state-changing methods (optional) |
| `RateLimitRule` | 50 | `THROTTLE` or `BLOCK` — per-IP / per-route throttling (429 when limit exceeded) |

> **Security note:** `BypassRouteRule` runs *after* blacklist and DDoS checks. A banned IP cannot escape via a bypass route.

---

## Configuration

### Full reference

```javascript
const shield = new K9Shield({
  security: {
    trustProxy: false,          // only enable when behind a trusted reverse proxy
    trustedProxies: [],         // CIDRs/IPs of trusted proxies, e.g. ['10.0.0.1', '172.16.0.0/12']
    allowPrivateIPs: false,     // set true in development
    maxBodySize: 1048576,       // bytes — default 1 MB
    checkStringMaxLength: 32768, // max length for request pattern scan (default 32 KB)
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    requestHeaderWhitelist: [], // headers excluded from pattern scanning
    userAgentBlacklist: [],
    refererBlacklist: [],
    securityHeaders: {},        // override individual security headers
    csp: {},                    // merge into Content-Security-Policy directives
    permissions: {},           // merge into Permissions-Policy directives
    corsOrigin: '*',            // '*' or string[] of allowed origins
    csrfProtection: {           // optional CSRF for state-changing methods
      enabled: false,
      originWhitelist: [],      // e.g. ['https://app.example.com']
      requireOriginOrReferer: false
    }
  },

  rateLimiting: {
    enabled: true,
    default: {
      maxRequests: 100,
      timeWindow: 60000,        // ms
      banDuration: 300000,      // ms — permanent-ban accumulation window
      retryAfter: 60,           // seconds sent in Retry-After header
      throttleDuration: 30000,  // ms — how long throttle window lasts
      throttleDelay: 1000       // ms — delay between throttled requests
    },
    routes: {
      '/api/auth/login': {
        POST: {
          maxRequests: 5,
          timeWindow: 60000,
          banDuration: 1800000,
          retryAfter: 60,
          throttleDuration: 60000,
          throttleDelay: 2000
        }
      }
    },
    routePatterns: []           // optional: [{ pattern: '/api/*'|RegExp, config: { GET: {...}, default: {...} } }]
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
      rateLimitByPath: {
        '/api/*': 100,  // max 100 req/min to any /api/* path
        '/auth/*': 20
      }
    }
  },

  logging: {
    enable: true,
    level: 'info',    // debug | info | warning | blocked | attack | ratelimit | banned | manual
    maxLogSize: 5000,
    archiveLimit: 5,
    archives: []
  },

  errorHandling: {
    includeErrorDetails: false,
    customHandlers: {
      rateLimitExceeded: (res, data) => {
        res.status(429).json({ error: 'Too many requests', retryAfter: data.retryAfter });
      },
      ddosAttack: (res) => {
        res.status(429).json({ error: 'Blocked' });
      }
    },
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

  bypassRoutes: ['/health', '/metrics'],  // strings or RegExp instances

  onSecurityEvent: null,  // optional (event, payload) => {} for blocked/throttled/allowed_bypass

  updateCheck: true   // set false to disable startup npm registry check
});
```

### Proxy setup

`trustProxy` is `false` by default. Client IP is taken from the socket's direct peer. To honour `X-Forwarded-For`, explicitly list your proxy CIDRs:

```javascript
security: {
  trustProxy: true,
  trustedProxies: ['10.0.0.0/8', '172.16.0.0/12', '192.168.1.1']
}
```

K9Shield walks the `X-Forwarded-For` chain right-to-left and returns the first hop that is not in `trustedProxies`, preventing IP spoofing via header injection.

---

## API

```javascript
// Middleware
app.use(shield.protect());

// IP management
shield.blockIP('1.2.3.4');
shield.unblockIP('1.2.3.4');
shield.whitelistIP('10.0.0.1');
shield.unwhitelistIP('10.0.0.1');

// CIDR notation is supported
shield.blockIP('192.168.1.0/24');
shield.whitelistIP('10.0.0.0/8');

// Pattern detection
shield.addSuspiciousPattern(/malicious-payload/i);

// Runtime config update (validated before applying)
shield.setConfig({ rateLimiting: { enabled: false } });

// Logs
const active   = shield.getLogs();
const archived = shield.getArchivedLogs();

// Data Loss Prevention (optional utility)
const scan      = shield.scanForSensitiveData(payload);    // { hasSensitiveData, detectedData }
const masked    = shield.maskSensitiveData(payload);
const encrypted = await shield.encryptSensitiveData(payload);
const decrypted = await shield.decryptSensitiveData(encrypted);
shield.addCustomSensitivePattern('apiKey', /sk-[a-z0-9]{32}/i);

// Reset all runtime state (blocked IPs, rate limit counters, logs, metrics)
shield.reset();

// Metrics (requests allowed/blocked/throttled, blocks by reason)
const metrics = shield.getMetrics();
// { requestsAllowed, requestsBlocked, requestsThrottled, blocksByReason, lastReset }
```

---

## Data Loss Prevention

K9Shield includes a DLP module that scans, masks, and encrypts sensitive data in request/response payloads.

Built-in pattern types: `creditCard`, `email`, `ssn`, `phoneNumber`, `iban`, `passport`.

```javascript
// Scan a payload for sensitive data before logging or storing it
const result = shield.scanForSensitiveData(req.body);
if (result.hasSensitiveData) {
  const safe = shield.maskSensitiveData(req.body);
  // log or store `safe` instead of raw body
}
```

To persist encrypted data across restarts, provide a stable 32-byte key:

```bash
# .env
K9SHIELD_DLP_KEY=your64hexcharacterkey...
```

```javascript
// or via config
const shield = new K9Shield({
  dlp: {
    encryptionKey: process.env.K9SHIELD_DLP_KEY
  }
});
```

> Without a configured key an ephemeral key is generated on startup with a console warning. Encrypted data will be unrecoverable after restart.

---

## Custom Rules

```javascript
const Rule = require('k9shield/src/policy-engine/Rule');

const myRule = new Rule({
  name: 'BlockTorExitNodes',
  priority: 95,   // runs before DdosRule
  condition: async ({ ip }) => {
    return torExitNodeSet.has(ip);
  },
  action: () => ({
    decision: 'BLOCK',
    reason: 'accessDenied'
  })
});

shield.policyEngine.addRule(myRule);
```

Decisions: `BLOCK`, `ALLOW_BYPASS`. Returning `null` from `condition` passes the request to the next rule.

---

## Security Model

### What K9Shield detects and blocks

| Category | Signals |
|---|---|
| **DDoS** | Requests/sec, requests/min, burst spikes, slow-body attacks |
| **Anomaly scoring** | Payload size, header size, URL length, request pattern uniformity, inter-request timing |
| **SQLi** | UNION SELECT, time-based blind, error-based, stacked queries, encoded variants |
| **XSS** | Inline scripts, event handlers, javascript: URIs, DOM sinks, encoding evasion |
| **Path traversal** | `../`, URL-encoded, double-encoded, Unicode-encoded variants |
| **Command injection** | Shell metacharacters, backtick execution, subshell patterns, known interpreter paths |
| **LFI / RFI** | PHP wrappers, zip/phar streams, gopher, data URIs |
| **Deserialization** | PHP object notation, XML entity declarations, Java class references |
| **Encoding evasion** | High URL-encoding density, Unicode confusables, special character anomalies |

### IP blocking behaviour

- Blocks are stored as expiry timestamps (`Map<ip, expiryTs>`). Repeated blocks extend the expiry, never reset it.
- Block duration escalates exponentially per IP with each offence (`blockDuration × 2^n`, capped at 24 h).
- Temporary blocks from pattern detection and permanent blocks from rate-limit accumulation are tracked independently.

### Rate limiter

- Per-IP sliding window with per-route override support.
- Three-strike accumulation triggers a permanent ban entry on the blacklist.
- Throttle state is checked before rate-limit counters — an active throttle window is enforced immediately.

---

## Production deployment

### Dependencies (3)

Before deploying, run a dependency audit and fix any reported issues:

```bash
bun audit
# or with npm (requires package-lock.json): npm audit
```

Resolve critical/high vulnerabilities in dependencies before production use.

### Multi-instance / distributed (4)

Rate limit and DDoS block state are **in-memory per process**. With multiple app instances behind a load balancer, each instance has its own counters and block list, so limits are effectively multiplied by the number of instances.

For shared rate limiting across instances, provide a `rateLimitStore` that implements:

- **`increment(key, windowMs)`** — returns a Promise resolving to `{ count: number, ttl?: number }`. `key` is e.g. `ratelimit:{ip}:{path}`; `windowMs` is the window in milliseconds. Increment the counter for `key`, expire after `windowMs`, and return the current count and optional TTL in ms.

Example with a Redis-backed store:

```javascript
const shield = new K9Shield({
  rateLimiting: {
    enabled: true,
    default: { maxRequests: 100, timeWindow: 60000, ... }
  }
});
shield.rateLimiter.rateLimitStore = {
  async increment(key, windowMs) {
    const count = await redis.incr(key);
    if (count === 1) await redis.pexpire(key, windowMs);
    const ttl = await redis.pttl(key);
    return { count, ttl: ttl > 0 ? ttl : windowMs };
  }
};
```

DDoS block list and security blacklist/whitelist remain per-instance unless you sync them externally (e.g. shared Redis or admin API).

### DLP key (5)

If you use `encryptSensitiveData` / `decryptSensitiveData`, set a **stable 32-byte (64 hex) key** so encrypted data survives restarts:

```bash
# .env or environment
K9SHIELD_DLP_KEY=your64characterhexkey...
```

Or via config:

```javascript
const shield = new K9Shield({
  dlp: { encryptionKey: process.env.K9SHIELD_DLP_KEY }
});
```

Without a configured key, an ephemeral key is used and encrypted data cannot be decrypted after restart.

---

## HTTP Response Codes

| Code | Reason |
|---|---|
| `200` | Request allowed |
| `400` | Invalid or unspoofable IP address |
| `403` | Blacklisted IP or suspicious pattern |
| `405` | HTTP method not in `allowedMethods` |
| `413` | Body exceeds `maxBodySize` |
| `429` | Rate limit exceeded or DDoS detected |
| `500` | Unexpected internal error |

---

## License

MIT — see [LICENSE](./LICENSE).

---

For enterprise integrations or support: `hi@k9crypt.xyz`
