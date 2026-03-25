const defaultConfig = {
  mode: {
    shadow: false,
    shadowRules: []
  },
  security: {
    trustProxy: false,
    trustedProxies: [],
    allowPrivateIPs: false,
    securityHeaders: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'"
    },
    allowedMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    maxBodySize: 1024 * 1024,
    requestHeaderWhitelist: [],
    userAgentBlacklist: [],
    refererBlacklist: [],
    checkStringMaxLength: 32 * 1024,
    permissions: {},
    csp: {},
    corsOrigin: undefined,
    parsedBodyInspection: {
      enabled: true,
      maxBodyScanSize: 64 * 1024
    },
    fastInspection: {
      enabled: true,
      deepInspectMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
      deepInspectContentTypes: [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain'
      ]
    },
    streamingProtection: {
      enabled: true,
      maxBodySize: null,
      maxChunkCount: 2048,
      minBytesPerSecond: 128,
      gracePeriodMs: 1500,
      checkIntervalMs: 500,
      applyToMethods: ['POST', 'PUT', 'PATCH']
    },
    routeProfiles: [
      { pattern: '/api/*', profile: 'api' },
      { pattern: '/admin/*', profile: 'admin' },
      { pattern: '/webhooks/*', profile: 'webhook' },
      { pattern: '/upload/*', profile: 'upload' }
    ],
    profiles: {
      default: {
        enableDeepInspection: true,
        htmlResponse: false,
        cspNonce: false,
        cacheStrategy: 'default',
        skipCsrf: false,
        skipUserAgentCheck: false,
        shadowMode: false
      },
      api: {
        enableDeepInspection: true,
        htmlResponse: false,
        cspNonce: false,
        cacheStrategy: 'no-store',
        skipCsrf: false,
        skipUserAgentCheck: false,
        shadowMode: false
      },
      html: {
        enableDeepInspection: true,
        htmlResponse: true,
        cspNonce: true,
        cacheStrategy: 'public',
        skipCsrf: false,
        skipUserAgentCheck: false,
        shadowMode: false
      },
      admin: {
        enableDeepInspection: true,
        htmlResponse: true,
        cspNonce: true,
        cacheStrategy: 'no-store',
        skipCsrf: false,
        skipUserAgentCheck: false,
        shadowMode: false
      },
      webhook: {
        enableDeepInspection: false,
        htmlResponse: false,
        cspNonce: false,
        cacheStrategy: 'no-store',
        skipCsrf: true,
        skipUserAgentCheck: true,
        shadowMode: false
      },
      upload: {
        enableDeepInspection: false,
        htmlResponse: false,
        cspNonce: false,
        cacheStrategy: 'no-store',
        skipCsrf: false,
        skipUserAgentCheck: false,
        shadowMode: false
      }
    },
    botProtection: {
      enabled: true,
      knownBadUserAgents: [
        'sqlmap',
        'nikto',
        'masscan',
        'nmap',
        'python-requests',
        'go-http-client',
        'curl/',
        'wget'
      ],
      allowListedUserAgents: ['googlebot', 'bingbot'],
      emptyUserAgentScore: 2,
      automationHeaderScore: 1,
      blockThreshold: 5,
      throttleThreshold: 3
    },
    reputation: {
      enabled: false,
      ttl: 5 * 60 * 1000,
      throttleThreshold: 50,
      blockThreshold: 80,
      resolver: null
    },
    csrfProtection: {
      enabled: false,
      originWhitelist: [],
      requireOriginOrReferer: false,
      tokenMode: 'off',
      secret: null,
      cookieName: 'k9shield_csrf',
      headerName: 'x-csrf-token',
      tokenMaxAgeMs: 2 * 60 * 60 * 1000
    },
    webhookProtection: {
      enabled: false,
      requireRawBody: true,
      defaultSecret: null,
      toleranceSeconds: 300,
      replayWindowMs: 5 * 60 * 1000,
      routes: []
    }
  },
  rateLimiting: {
    enabled: true,
    keyStrategy: 'ip',
    keyGenerator: null,
    identityHeaders: ['x-api-key', 'authorization'],
    tenantHeader: 'x-tenant-id',
    includeTenantInKey: false,
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
    archives: [],
    sampling: {
      enabled: true,
      windowMs: 10000,
      maxEntriesPerInterval: 250
    }
  },
  observability: {
    enabled: true,
    maxDecisionHistory: 200,
    maxEventHistory: 200
  },
  eventExport: {
    enabled: false,
    signingKey: null,
    includeDecisionTrace: true
  },
  errorHandling: {
    includeErrorDetails: false,
    customHandlers: {},
    defaultResponses: {
      methodNotAllowed: { status: 405, message: 'Method not allowed' },
      accessDenied: {
        status: 403,
        message: 'Access denied - IP is blacklisted'
      },
      payloadTooLarge: { status: 413, message: 'Payload too large' },
      invalidIP: { status: 400, message: 'Invalid IP address' },
      suspiciousRequest: {
        status: 403,
        message: 'Suspicious request pattern detected'
      },
      rateLimitExceeded: { status: 429, message: 'Too many requests' },
      permanentlyBlocked: {
        status: 403,
        message: 'Temporarily blocked due to repeated rate limit violations'
      },
      ddosAttack: {
        status: 429,
        message: 'DDoS attack detected - Access temporarily blocked'
      },
      slowRequest: {
        status: 408,
        message: 'Request body upload was too slow'
      },
      internalError: {
        status: 500,
        message: 'An internal server error occurred'
      },
      csrfOriginMismatch: { status: 403, message: 'Invalid or missing Origin' },
      csrfRefererMismatch: { status: 403, message: 'Invalid Referer' },
      csrfInvalidReferer: { status: 403, message: 'Invalid Referer header' },
      csrfMissingOriginOrReferer: { status: 403, message: 'Origin or Referer required' },
      csrfMissingToken: { status: 403, message: 'CSRF token required' },
      csrfTokenMismatch: { status: 403, message: 'CSRF token mismatch' },
      csrfInvalidToken: { status: 403, message: 'Invalid CSRF token' },
      userAgentBlocked: { status: 403, message: 'User-Agent not allowed' },
      refererBlocked: { status: 403, message: 'Referer not allowed' },
      botDetected: { status: 403, message: 'Automated abuse pattern detected' },
      reputationBlocked: { status: 403, message: 'Request blocked by reputation policy' },
      reputationThrottled: { status: 429, message: 'Request throttled by reputation policy' },
      webhookMisconfigured: { status: 500, message: 'Webhook route is misconfigured' },
      webhookMissingRawBody: { status: 400, message: 'Webhook raw body is required for verification' },
      webhookMissingSignature: { status: 401, message: 'Webhook signature required' },
      webhookInvalidSignature: { status: 401, message: 'Webhook signature verification failed' },
      webhookReplayDetected: { status: 409, message: 'Webhook replay detected' },
      webhookTimestampExpired: { status: 401, message: 'Webhook timestamp outside allowed tolerance' }
    }
  },
  bypassRoutes: [],
  onSecurityEvent: null,
  updateCheck: undefined
};

module.exports = defaultConfig;
