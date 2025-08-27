const defaultConfig = {
  security: {
    trustProxy: true,
    securityHeaders: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'Content-Security-Policy': "default-src 'self'"
    },
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    maxBodySize: 1024 * 1024,
    requestHeaderWhitelist: [],
    userAgentBlacklist: [],
    refererBlacklist: []
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
    routes: {}
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
        message: 'Permanently blocked due to multiple violations'
      },
      ddosAttack: {
        status: 429,
        message: 'DDoS attack detected - Access temporarily blocked'
      },
      internalError: {
        status: 500,
        message: 'An internal server error occurred'
      }
    }
  },
  bypassRoutes: []
};

module.exports = defaultConfig;
