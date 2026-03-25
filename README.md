![Banner](https://www.upload.ee/image/18524137/k9shield-banner.jpeg)

# K9Shield

K9Shield is an Express middleware security layer for Node.js applications. It combines request filtering, rate limiting, DDoS heuristics, CSRF protection, webhook signature verification, streaming body protection, route-aware security profiles, DLP helpers, shadow mode, and signed security event export in a single policy engine.

The library is designed to be mounted early in the middleware chain so it can stop hostile traffic before it reaches application handlers.

## What It Solves

K9Shield is useful when you want one middleware stack to handle:

- request allow/block decisions
- IP and CIDR blacklists / whitelists
- burst and path-aware DDoS heuristics
- rate limiting with tenant or identity aware keys
- CSRF origin checks and double-submit token validation
- webhook signature verification with replay detection
- suspicious payload / URL / header inspection
- slow body and oversized upload detection
- route-aware security profiles like `api`, `html`, `webhook`, `upload`, `admin`
- shadow mode rollouts
- security event export and observability
- DLP scanning, masking, and encryption helpers

## Installation

```bash
bun add k9shield
# or
npm install k9shield
```

## Quick Start

```js
const express = require('express');
const K9Shield = require('k9shield');

const app = express();
const shield = new K9Shield({
  security: {
    trustProxy: false,
    allowPrivateIPs: true,
    maxBodySize: 1024 * 1024,
    csrfProtection: {
      enabled: true,
      originWhitelist: ['https://app.example.com'],
      requireOriginOrReferer: true,
      tokenMode: 'double-submit'
    }
  },
  rateLimiting: {
    enabled: true,
    keyStrategy: 'identity',
    includeTenantInKey: true,
    default: {
      maxRequests: 100,
      timeWindow: 60000,
      banDuration: 300000,
      retryAfter: 60,
      throttleDuration: 30000
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
app.use(express.json({ limit: '1mb', verify: shield.rawBodySaver() }));
app.use(shield.inspectBody());
app.use(shield.payloadTooLargeHandler());

app.get('/', (req, res) => {
  res.json({
    ok: true,
    profile: req.k9shieldProfile?.name || 'default'
  });
});

app.listen(3000);
```

## Middleware Order

K9Shield works best when mounted in this order:

```js
app.use(shield.protect());
app.use(express.json({ verify: shield.rawBodySaver() }));
app.use(shield.inspectBody());
app.use(shield.payloadTooLargeHandler());
```

Why this order matters:

1. `protect()` runs first so K9Shield can reject bad IPs, invalid methods, suspicious headers, DDoS bursts, and oversized requests as early as possible.
2. `rawBodySaver()` lets webhook verification use the original request body.
3. `inspectBody()` runs after the body parser, so malicious JSON or form payloads can still be scanned.
4. `payloadTooLargeHandler()` converts parser-level `413` errors into your configured JSON response instead of the default HTML error page.

## Request Lifecycle

Every request goes through a priority-based policy engine. Rules run in order, and the first rule that returns a decision wins.

| Rule | Priority | Typical Decision |
|------|----------|------------------|
| `WhitelistRule` | 200 | `ALLOW_BYPASS` |
| `BlacklistRule` | 100 | `BLOCK` |
| `DdosRule` | 90 | `BLOCK` |
| `BypassRouteRule` | 85 | `ALLOW_BYPASS` |
| `ReputationRule` | 82 | `BLOCK` / `THROTTLE` |
| `SecurityPolicyRule` | 80 | `BLOCK` |
| `BotProtectionRule` | 79 | `BLOCK` / `THROTTLE` |
| `WebhookRule` | 78 | `BLOCK` |
| `CsrfRule` | 75 | `BLOCK` |
| `RateLimitRule` | 50 | `THROTTLE` / `BLOCK` |

If no rule matches, the request is allowed.

## Core Features

### 1. Route Profiles

K9Shield can classify requests into profiles such as `default`, `api`, `html`, `admin`, `webhook`, and `upload`.

Profiles affect:

- whether deep inspection should run
- whether CSP nonces are generated
- cache policy behavior
- whether CSRF should be skipped
- whether User-Agent checks should be skipped
- whether a route should operate in shadow mode

Default route profile matching:

```js
security: {
  routeProfiles: [
    { pattern: '/api/*', profile: 'api' },
    { pattern: '/admin/*', profile: 'admin' },
    { pattern: '/webhooks/*', profile: 'webhook' },
    { pattern: '/upload/*', profile: 'upload' }
  ]
}
```

You can override or add your own:

```js
security: {
  routeProfiles: [
    {
      pattern: /^\/partner\/v\d+\//,
      profile: 'api',
      overrides: {
        shadowMode: true
      }
    }
  ]
}
```

### 2. Fast Path and Deep Path Inspection

K9Shield now avoids paying the full regex scan cost on every request. It first performs cheaper checks and only moves to deep inspection when the route profile, method, content type, or prefilter tokens suggest higher risk.

This improves:

- latency on normal traffic
- CPU usage under load
- false-positive control for routes like uploads and webhooks

### 3. Streaming Body Protection

`protect()` attaches a streaming guard before downstream body parsers read the request.

It can stop requests for:

- oversized body streams
- suspiciously slow uploads
- excessive chunk counts

Configuration:

```js
security: {
  streamingProtection: {
    enabled: true,
    maxBodySize: 1024 * 1024,
    maxChunkCount: 2048,
    minBytesPerSecond: 128,
    gracePeriodMs: 1500,
    checkIntervalMs: 500,
    applyToMethods: ['POST', 'PUT', 'PATCH']
  }
}
```

### 4. Parsed Body Inspection

If your request body is parsed by `express.json()` or similar middleware, `shield.inspectBody()` can scan the parsed payload for malicious content after parsing.

This is especially useful for:

- JSON APIs
- form submissions
- admin panels
- route-specific payload inspection

### 5. CSRF Protection

K9Shield supports:

- explicit origin whitelist validation
- referer fallback validation
- optional `requireOriginOrReferer`
- optional double-submit token mode

Example:

```js
const shield = new K9Shield({
  security: {
    csrfProtection: {
      enabled: true,
      originWhitelist: ['https://app.example.com'],
      requireOriginOrReferer: true,
      tokenMode: 'double-submit'
    }
  }
});

const csrfToken = shield.generateCsrfToken('anonymous');
```

To validate double-submit tokens, the request must include:

- a cookie named `k9shield_csrf` by default
- a header named `x-csrf-token` by default
- the same signed token value in both places

You can customize `cookieName`, `headerName`, and `tokenMaxAgeMs`.

If you do not provide `security.csrfProtection.secret`, K9Shield generates a secure runtime secret automatically so double-submit mode works out of the box.

### 6. Webhook Protection

K9Shield can verify webhook signatures and detect replay attacks.

Supported providers:

- `generic`
- `github`
- `stripe`
- `slack`

Example:

```js
const shield = new K9Shield({
  security: {
    webhookProtection: {
      enabled: true,
      requireRawBody: true,
      replayWindowMs: 300000,
      routes: [
        {
          path: '/webhooks/github',
          provider: 'github',
          secret: 'github-webhook-secret'
        },
        {
          path: '/webhooks/stripe',
          provider: 'stripe',
          secret: 'stripe-webhook-secret'
        }
      ]
    }
  }
});

app.use(express.json({ verify: shield.rawBodySaver() }));
```

Webhook protection can block:

- missing signatures
- invalid signatures
- timestamps outside the allowed tolerance
- replayed delivery IDs
- misconfigured webhook routes

### 7. Adaptive Bot Protection

K9Shield includes a lightweight bot scoring layer. It can raise a score when requests look like automated abuse, for example:

- known offensive User-Agents
- empty User-Agent values on state-changing requests
- automation-like header patterns

It can return either:

- `THROTTLE`
- `BLOCK`

Profile-aware skips are supported. For example, webhook routes skip User-Agent checks by default because many webhook senders are machine-to-machine clients.

### 8. Reputation Cache

You can plug in your own reputation resolver and cache the result inside K9Shield.

Example:

```js
const shield = new K9Shield({
  security: {
    reputation: {
      enabled: true,
      ttl: 300000,
      throttleThreshold: 50,
      blockThreshold: 80,
      resolver: async ({ ip, req }) => {
        if (ip === '203.0.113.10') {
          return { score: 90, action: 'block', reason: 'known-abuser' };
        }
        return { score: 0 };
      }
    }
  }
});
```

### 9. Shadow Mode

Shadow mode allows you to observe what K9Shield would have blocked without actually blocking the request.

This is useful when:

- rolling out stricter rules
- tuning false positives
- comparing behavior in staging and production

Example:

```js
const shield = new K9Shield({
  mode: {
    shadow: true,
    shadowRules: []
  }
});
```

When shadow mode is active, K9Shield:

- allows the request to continue
- records the decision trace
- emits a `shadowed` security event
- adds `X-K9Shield-Shadow-Decision`

### 10. Multi-Tenant and Identity-Aware Rate Limiting

Rate limits no longer have to be IP-only.

You can configure:

- `keyStrategy: 'ip'`
- `keyStrategy: 'identity'`
- `keyStrategy: 'tenant'`
- a custom `keyGenerator`
- tenant-aware keys with `includeTenantInKey`

Example:

```js
rateLimiting: {
  enabled: true,
  keyStrategy: 'tenant',
  tenantHeader: 'x-tenant-id',
  includeTenantInKey: true,
  default: {
    maxRequests: 100,
    timeWindow: 60000,
    banDuration: 300000,
    retryAfter: 60,
    throttleDuration: 30000
  }
}
```

### 11. Signed Security Events and Observability

K9Shield can store decision traces and export signed event envelopes.

Example:

```js
const shield = new K9Shield({
  eventExport: {
    enabled: true,
    signingKey: 'k9shield-event-signing-key',
    includeDecisionTrace: true
  }
});

shield.setSecurityEventExporters([
  async (event) => {
    console.log('Security event', event);
  }
]);
```

The metrics object now includes:

- request counters
- block reasons
- per-rule execution counts
- per-rule timing totals
- bounded decision history
- bounded security event history

```js
const metrics = shield.getMetrics();
```

### 12. Rule Simulation and Replay

K9Shield includes dry-run tooling for config validation and attack replay exercises.

```js
const singleResult = await shield.simulateRequest({
  method: 'POST',
  path: '/admin/login',
  headers: {
    'user-agent': 'sqlmap/1.8'
  }
});

const replayResults = await shield.replayRequests([
  { path: '/' },
  { path: '/admin/login', headers: { 'user-agent': 'sqlmap/1.8' } }
]);
```

This is useful for:

- staging validation
- regression checks
- support debugging
- demoing rule behavior

## Presets

Built-in presets:

- `strict-api`
- `public-form`
- `admin-panel`
- `webhook-ingress`
- `file-upload`

Usage:

```js
const shield = new K9Shield({
  preset: 'admin-panel'
});
```

Presets are just config fragments. Your explicit config still overrides them.

## Configuration Overview

### `mode`

- `shadow`
- `shadowRules`

### `security`

- `trustProxy`
- `trustedProxies`
- `allowPrivateIPs`
- `maxBodySize`
- `checkStringMaxLength`
- `allowedMethods`
- `requestHeaderWhitelist`
- `userAgentBlacklist`
- `refererBlacklist`
- `securityHeaders`
- `csp`
- `permissions`
- `corsOrigin`
- `parsedBodyInspection`
- `fastInspection`
- `streamingProtection`
- `routeProfiles`
- `profiles`
- `botProtection`
- `reputation`
- `csrfProtection`
- `webhookProtection`

### `rateLimiting`

- `enabled`
- `keyStrategy`
- `keyGenerator`
- `identityHeaders`
- `tenantHeader`
- `includeTenantInKey`
- `default`
- `routes`
- `routePatterns`

### `ddosProtection`

- `enabled`
- `config.maxConnections`
- `config.timeWindow`
- `config.blockDuration`
- `config.requestThreshold`
- `config.burstThreshold`
- `config.slowRequestThreshold`
- `config.rateLimitByPath`

### `logging`

- `enable`
- `level`
- `maxLogSize`
- `archiveLimit`
- `archives`
- `sampling`

### `observability`

- `enabled`
- `maxDecisionHistory`
- `maxEventHistory`

### `eventExport`

- `enabled`
- `signingKey`
- `includeDecisionTrace`

## API

### Middleware

- `shield.protect()`
- `shield.inspectBody()`
- `shield.payloadTooLargeHandler()`
- `shield.rawBodySaver()`

### IP and rule management

- `shield.blockIP(ip)`
- `shield.unblockIP(ip)`
- `shield.whitelistIP(ip)`
- `shield.unwhitelistIP(ip)`
- `shield.addSuspiciousPattern(regex)`
- `shield.setConfig(config)`
- `shield.reset()`

### Security helpers

- `shield.generateCsrfToken(subject)`
- `shield.scanForSensitiveData(data)`
- `shield.maskSensitiveData(data)`
- `shield.encryptSensitiveData(data)`
- `shield.decryptSensitiveData(encrypted)`
- `shield.addCustomSensitivePattern(type, regex)`

### Observability and testing

- `shield.getMetrics()`
- `shield.getLogs()`
- `shield.getArchivedLogs()`
- `shield.setSecurityEventExporters(exporters)`
- `shield.setRateLimitStore(store)`
- `shield.setReplayStore(store)`
- `shield.simulateRequest(requestLike)`
- `shield.replayRequests(requests)`

## Production Guidance

Use the following checklist before deploying:

1. Set `security.trustProxy` and `security.trustedProxies` correctly if you are behind a reverse proxy.
2. If you want fixed CSRF tokens across restarts, set `security.csrfProtection.secret`. Otherwise K9Shield creates a runtime secret automatically.
3. Set webhook secrets and mount a body parser with `verify: shield.rawBodySaver()` for signed webhooks.
4. If you want a fixed application-managed DLP key, set `config.dlp.encryptionKey`. Otherwise K9Shield creates a runtime key automatically.
5. Configure `security.corsOrigin` explicitly if your frontend is cross-origin. CORS is closed by default now.
6. Keep `protect()` before your body parser and `inspectBody()` after it.
7. If you run multiple app instances, inject shared stores through `setRateLimitStore()` and `setReplayStore()`. Default in-memory stores are safest for single-process deployments only.
8. Review shadow mode before enabling strict blocking rules.
9. Decide whether you want startup update checks. They are disabled automatically in production unless you explicitly set `updateCheck: true`.

## Example: Full Setup

```js
const express = require('express');
const K9Shield = require('k9shield');

const app = express();

const shield = new K9Shield({
  preset: 'webhook-ingress',
  security: {
    allowPrivateIPs: true,
    trustProxy: true,
    trustedProxies: ['10.0.0.0/8', '172.16.0.0/12'],
    corsOrigin: ['https://app.example.com'],
    csrfProtection: {
      enabled: true,
      originWhitelist: ['https://app.example.com'],
      requireOriginOrReferer: true,
      tokenMode: 'double-submit'
    },
    webhookProtection: {
      enabled: true,
      routes: [
        {
          path: '/webhooks/github',
          provider: 'github',
          secret: 'github-webhook-secret'
        }
      ]
    }
  },
  rateLimiting: {
    enabled: true,
    keyStrategy: 'identity',
    includeTenantInKey: true,
    default: {
      maxRequests: 100,
      timeWindow: 60000,
      banDuration: 300000,
      retryAfter: 60,
      throttleDuration: 30000
    }
  },
  eventExport: {
    enabled: true,
    signingKey: 'k9shield-event-signing-key',
    includeDecisionTrace: true
  }
});

shield.setSecurityEventExporters([
  async (event) => {
    console.log(JSON.stringify(event));
  }
]);

app.use(shield.protect());
app.use(express.json({ limit: '1mb', verify: shield.rawBodySaver() }));
app.use(shield.inspectBody());
app.use(shield.payloadTooLargeHandler());

app.post('/submit', (req, res) => {
  res.json({ ok: true });
});

app.post('/webhooks/github', (req, res) => {
  res.json({ received: true });
});

app.listen(3000);
```

## Security Notes

- Default CORS is closed unless you explicitly configure `security.corsOrigin`.
- Unsafe methods are forced to `no-store` cache behavior.
- Webhooks require raw body access for robust signature validation.
- Double-submit CSRF mode uses signed tokens and validates both cookie and header.
- Shadow mode is powerful, but it is still allow mode. Do not mistake it for enforcement mode.

## License

MIT
