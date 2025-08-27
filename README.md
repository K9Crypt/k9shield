![Banner](https://www.upload.ee/image/18524137/k9shield-banner.jpeg)

# K9Shield

Robust and flexible Node.js middleware designed to protect your web applications from a wide range of threats, including DDoS attacks, brute-force attempts, and malicious traffic. With its advanced policy engine, customizable security rules, and comprehensive logging capabilities, K9Shield empowers developers to implement enterprise-grade security measures with ease.

## 🚀 Quick Start

```javascript
const express = require('express');
const K9Shield = require('k9shield');

const app = express();

// Initialize K9Shield with basic configuration
const shield = new K9Shield({
  security: {
    allowPrivateIPs: true // Allow localhost for development
  },
  rateLimiting: {
    enabled: true,
    default: {
      maxRequests: 100,
      timeWindow: 60000 // 1 minute
    }
  },
  logging: {
    enable: true,
    level: 'info'
  }
});

// Apply K9Shield protection to all routes
app.use(shield.protect());

// Your application routes
app.get('/', (req, res) => {
  res.json({ message: 'Protected by K9Shield', ip: req.ip });
});

app.listen(3000, () => {
  console.log('Server running with K9Shield protection on port 3000');
});
```

## 📋 Table of Contents

- [Installation](#installation)
- [Policy Engine Architecture](#policy-engine-architecture)
- [Configuration Guide](#configuration-guide)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Custom Rules](#custom-rules)
- [Testing](#testing)
- [Best Practices](#best-practices)
- [License](#license)

## 📦 Installation

```bash
npm install k9shield
```

## 🧠 Policy Engine Architecture

K9Shield v2.0 introduces a revolutionary **Security Policy Engine** that acts as the central brain of your application's security. This engine evaluates every incoming request through a series of prioritized security rules.

### How It Works

1. **Rule-Based System**: Each security check (blacklist, whitelist, DDoS, rate limiting) is implemented as an independent rule
2. **Priority-Based Execution**: Rules are executed in order of priority (200 = highest, 0 = lowest)
3. **Centralized Decision Making**: All security decisions are made through a single, coherent engine
4. **Modular Architecture**: Easy to add new security rules without modifying core logic

### Built-in Security Rules

| Rule Name              | Priority | Purpose                                         |
| ---------------------- | -------- | ----------------------------------------------- |
| **WhitelistRule**      | 200      | Allow trusted IPs to bypass all other checks    |
| **BypassRouteRule**    | 190      | Allow specific routes to bypass security checks |
| **BlacklistRule**      | 100      | Block malicious IPs immediately                 |
| **DdosRule**           | 90       | Detect and prevent DDoS attacks                 |
| **SecurityPolicyRule** | 80       | Validate requests (method, payload, patterns)   |
| **RateLimitRule**      | 50       | Control request frequency per IP                |

### Policy Engine Flow

```javascript
// Request comes in → Policy Engine evaluates rules by priority
// 1. WhitelistRule: Is IP whitelisted? → ALLOW_BYPASS
// 2. BypassRouteRule: Is route bypassed? → ALLOW_BYPASS
// 3. BlacklistRule: Is IP blacklisted? → BLOCK
// 4. DdosRule: Is this a DDoS attack? → BLOCK
// 5. SecurityPolicyRule: Is request suspicious? → BLOCK
// 6. RateLimitRule: Is rate limit exceeded? → BLOCK
// 7. Default: No rules triggered → ALLOW
```

## ⚙️ Configuration Guide

### Basic Configuration

```javascript
const shield = new K9Shield({
  // Security settings
  security: {
    allowPrivateIPs: true, // Allow private IPs (localhost, 192.168.x.x)
    maxBodySize: 1024 * 1024, // 1MB request limit
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
    userAgentBlacklist: ['bot', 'crawler']
  },

  // Rate limiting
  rateLimiting: {
    enabled: true,
    default: {
      maxRequests: 100, // 100 requests per window
      timeWindow: 60000, // 1 minute window
      banDuration: 300000 // 5 minute ban
    }
  },

  // DDoS protection
  ddosProtection: {
    enabled: true,
    config: {
      maxConnections: 50, // Max concurrent connections
      blockDuration: 300000, // 5 minute block
      requestThreshold: 100 // Max requests in burst
    }
  },

  // Logging
  logging: {
    enable: true,
    level: 'info' // 'debug', 'info', 'warning', 'error'
  }
});
```

### Advanced Configuration

```javascript
const shield = new K9Shield({
  security: {
    trustProxy: true,
    allowPrivateIPs: false,
    maxBodySize: 1024 * 500, // 500KB limit

    // Security headers
    securityHeaders: {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Strict-Transport-Security': 'max-age=31536000'
    },

    // Content Security Policy
    csp: {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:']
    },

    // Permissions Policy
    permissions: {
      geolocation: '()',
      camera: '()',
      microphone: '()'
    }
  },

  rateLimiting: {
    enabled: true,
    default: {
      maxRequests: 60,
      timeWindow: 60000,
      banDuration: 600000, // 10 minute ban
      throttleDuration: 30000, // Throttle for 30 seconds
      throttleDelay: 2000 // 2 second delay between requests
    },

    // Route-specific limits
    routes: {
      '/api/auth/login': {
        POST: {
          maxRequests: 5, // Only 5 login attempts per minute
          timeWindow: 60000,
          banDuration: 1800000 // 30 minute ban for failed attempts
        }
      },
      '/api/upload': {
        POST: {
          maxRequests: 3, // Limited upload requests
          timeWindow: 300000 // 5 minute window
        }
      }
    }
  },

  ddosProtection: {
    enabled: true,
    config: {
      maxConnections: 200,
      timeWindow: 60000,
      blockDuration: 1800000, // 30 minute block
      requestThreshold: 500,
      burstThreshold: 50,
      slowRequestThreshold: 10,

      // Path-based rate limits
      rateLimitByPath: {
        '/api/*': 100, // API endpoints: 100 req/min
        '/auth/*': 20, // Auth endpoints: 20 req/min
        '/upload/*': 5, // Upload endpoints: 5 req/min
        '*': 500 // All other routes: 500 req/min
      }
    }
  },

  // Bypass routes (won't be processed by security rules)
  bypassRoutes: ['/health', '/metrics', '/status'],

  // Error handling
  errorHandling: {
    includeErrorDetails: true,
    customHandlers: {
      rateLimitExceeded: (res, data) => {
        res.status(429).json({
          error: 'Rate limit exceeded',
          retryAfter: data.retryAfter,
          limit: data.limit
        });
      },
      ddosAttack: (res) => {
        res.status(403).json({
          error: 'Access denied',
          reason: 'Suspicious traffic detected'
        });
      },
      suspiciousRequest: (res) => {
        res.status(403).json({
          error: 'Request blocked',
          reason: 'Suspicious patterns detected'
        });
      }
    }
  }
});
```

## 🛡️ Security Features

### 1. IP Management

```javascript
// Block specific IPs
shield.blockIP('192.168.1.100');
shield.blockIP('10.0.0.50');

// Whitelist trusted IPs (bypass all security checks)
shield.whitelistIP('203.0.113.10');
shield.whitelistIP('198.51.100.0/24'); // CIDR notation

// Remove from lists
shield.unblockIP('192.168.1.100');
shield.unwhitelistIP('203.0.113.10');

// Check IP status
const isBlocked = shield.security.isBlacklisted(req, res, ip);
const isWhitelisted = shield.security.isWhitelisted(ip);
```

### 2. Custom Security Patterns

```javascript
// Add custom suspicious patterns
shield.addSuspiciousPattern(/eval\s*\(/i); // Code injection
shield.addSuspiciousPattern(/<script[^>]*>.*?<\/script>/i); // XSS attempts
shield.addSuspiciousPattern(/UNION\s+SELECT/i); // SQL injection
shield.addSuspiciousPattern(/\.\.\/|\.\.\\/); // Path traversal

// The patterns will be checked against:
// - Request URL
// - Query parameters
// - POST body (JSON)
// - Headers (User-Agent, Referer)
```

### 3. Route-Specific Protection

```javascript
const shield = new K9Shield({
  rateLimiting: {
    routes: {
      // Strict limits for authentication
      '/api/auth/*': {
        POST: { maxRequests: 3, timeWindow: 60000, banDuration: 900000 }
      },

      // API endpoints
      '/api/v1/*': {
        GET: { maxRequests: 1000, timeWindow: 60000 },
        POST: { maxRequests: 100, timeWindow: 60000 },
        PUT: { maxRequests: 50, timeWindow: 60000 },
        DELETE: { maxRequests: 10, timeWindow: 60000 }
      },

      // File upload restrictions
      '/upload': {
        POST: { maxRequests: 5, timeWindow: 300000 } // 5 uploads per 5 minutes
      }
    }
  }
});
```

## 💡 Usage Examples

### Development Environment

```javascript
const shield = new K9Shield({
  security: {
    allowPrivateIPs: true, // Allow localhost
    maxBodySize: 1024 * 1024 * 10 // 10MB for development
  },
  rateLimiting: {
    enabled: false // Disable rate limiting in dev
  },
  ddosProtection: {
    enabled: false // Disable DDoS protection in dev
  },
  logging: {
    level: 'debug' // Verbose logging
  }
});
```

### Production Environment

```javascript
const shield = new K9Shield({
  security: {
    allowPrivateIPs: false, // Block private IPs
    trustProxy: true, // Trust reverse proxy
    maxBodySize: 1024 * 100, // 100KB limit
    allowedMethods: ['GET', 'POST', 'PUT', 'DELETE']
  },
  rateLimiting: {
    enabled: true,
    default: {
      maxRequests: 60, // Conservative limit
      timeWindow: 60000,
      banDuration: 1800000 // 30 minute ban
    }
  },
  ddosProtection: {
    enabled: true,
    config: {
      maxConnections: 100, // Conservative connection limit
      blockDuration: 3600000 // 1 hour block
    }
  },
  logging: {
    level: 'warning' // Only important events
  }
});
```

### E-commerce Application

```javascript
const shield = new K9Shield({
  rateLimiting: {
    routes: {
      '/api/auth/login': {
        POST: { maxRequests: 5, timeWindow: 300000, banDuration: 1800000 }
      },
      '/api/cart/checkout': {
        POST: { maxRequests: 3, timeWindow: 60000 }
      },
      '/api/products/search': {
        GET: { maxRequests: 100, timeWindow: 60000 }
      },
      '/api/user/profile': {
        PUT: { maxRequests: 5, timeWindow: 300000 }
      }
    }
  },
  security: {
    userAgentBlacklist: ['bot', 'crawler', 'scraper'],
    maxBodySize: 1024 * 500 // 500KB for product images
  }
});
```

### API Gateway

```javascript
const shield = new K9Shield({
  rateLimiting: {
    routes: {
      '/api/public/*': {
        GET: { maxRequests: 1000, timeWindow: 60000 }
      },
      '/api/authenticated/*': {
        GET: { maxRequests: 500, timeWindow: 60000 },
        POST: { maxRequests: 100, timeWindow: 60000 }
      },
      '/api/admin/*': {
        GET: { maxRequests: 100, timeWindow: 60000 },
        POST: { maxRequests: 20, timeWindow: 60000 }
      }
    }
  },
  bypassRoutes: ['/health', '/metrics', '/api/status']
});
```

## 🔌 API Reference

### Core Methods

```javascript
// Initialize K9Shield
const shield = new K9Shield(config);

// Apply middleware
app.use(shield.protect());

// IP Management
shield.blockIP('192.168.1.100');
shield.unblockIP('192.168.1.100');
shield.whitelistIP('10.0.0.1');
shield.unwhitelistIP('10.0.0.1');

// Pattern Management
shield.addSuspiciousPattern(/malicious-pattern/i);

// Configuration
shield.setConfig(newConfig);

// Logging
const logs = shield.getLogs();
const archivedLogs = shield.getArchivedLogs();

// Reset (clear all data and statistics)
shield.reset();
```

### Configuration Options

```javascript
{
  // Security settings
  security: {
    trustProxy: boolean,              // Trust X-Forwarded-For header
    allowPrivateIPs: boolean,         // Allow private IP addresses
    maxBodySize: number,              // Max request body size in bytes
    allowedMethods: string[],         // Allowed HTTP methods
    userAgentBlacklist: string[],     // Blocked user agents
    refererBlacklist: string[],       // Blocked referers
    securityHeaders: object,          // Custom security headers
    csp: object,                      // Content Security Policy
    permissions: object               // Permissions Policy
  },

  // Rate limiting
  rateLimiting: {
    enabled: boolean,
    default: {
      maxRequests: number,            // Max requests per window
      timeWindow: number,             // Time window in milliseconds
      banDuration: number,            // Ban duration in milliseconds
      throttleDuration: number,       // Throttle duration
      throttleDelay: number           // Delay between throttled requests
    },
    routes: object                    // Route-specific limits
  },

  // DDoS protection
  ddosProtection: {
    enabled: boolean,
    config: {
      maxConnections: number,         // Max concurrent connections
      timeWindow: number,             // Analysis time window
      blockDuration: number,          // Block duration
      requestThreshold: number,       // Request threshold
      burstThreshold: number,         // Burst threshold
      slowRequestThreshold: number,   // Slow request threshold
      rateLimitByPath: object         // Path-based limits
    }
  },

  // Bypass routes
  bypassRoutes: string[],

  // Error handling
  errorHandling: {
    includeErrorDetails: boolean,
    customHandlers: object
  },

  // Logging
  logging: {
    enable: boolean,
    level: string,                    // 'debug', 'info', 'warning', 'error'
    maxLogSize: number,
    archiveLimit: number
  }
}
```

## 🔧 Custom Rules

You can extend K9Shield with custom security rules:

```javascript
const Rule = require('k9shield/src/policy-engine/Rule');

// Create a custom rule
const customRule = new Rule({
  name: 'CustomSecurityRule',
  priority: 75, // Between SecurityPolicyRule (80) and RateLimitRule (50)

  condition: async (context) => {
    const { req, ip } = context;

    // Example: Block requests with suspicious headers
    if (req.headers['x-malicious-header']) {
      return true;
    }

    // Example: Block requests from specific countries (you'd need GeoIP)
    // if (isFromBlockedCountry(ip)) {
    //   return true;
    // }

    return false;
  },

  action: (context) => {
    return {
      decision: 'BLOCK',
      reason: 'customSecurity',
      message: 'Request blocked by custom rule'
    };
  }
});

// Add the rule to the policy engine
shield.policyEngine.addRule(customRule);
```

### Custom Rule Examples

#### Geographic Blocking Rule

```javascript
const geoBlockRule = new Rule({
  name: 'GeoBlockRule',
  priority: 85,
  condition: async (context) => {
    const { ip } = context;
    const country = await getCountryFromIP(ip); // Your GeoIP implementation
    const blockedCountries = ['CN', 'RU', 'KP']; // ISO country codes
    return blockedCountries.includes(country);
  },
  action: (context) => ({
    decision: 'BLOCK',
    reason: 'geoBlocked',
    message: 'Access denied from your location'
  })
});
```

#### Business Hours Rule

```javascript
const businessHoursRule = new Rule({
  name: 'BusinessHoursRule',
  priority: 60,
  condition: async (context) => {
    const now = new Date();
    const hour = now.getHours();
    const isBusinessHours = hour >= 9 && hour <= 17;
    const isWeekend = now.getDay() === 0 || now.getDay() === 6;

    // Block admin routes outside business hours
    return (
      context.req.path.startsWith('/admin') && (!isBusinessHours || isWeekend)
    );
  },
  action: (context) => ({
    decision: 'BLOCK',
    reason: 'outsideBusinessHours',
    message: 'Admin access only allowed during business hours'
  })
});
```

## 🧪 Testing

### Basic Test Setup

```javascript
// test.js
const express = require('express');
const K9Shield = require('k9shield');

const app = express();
const shield = new K9Shield({
  security: { allowPrivateIPs: true },
  logging: { enable: true, level: 'info' },
  errorHandling: { includeErrorDetails: true }
});

// Block a test IP
shield.blockIP('192.168.1.100');

// Apply middleware
app.use(shield.protect());

app.get('/', (req, res) => {
  res.json({ message: 'Protected endpoint', ip: req.ip });
});

app.listen(3000, () => {
  console.log('Test server running on port 3000');
});
```

### Expected Responses

- **200**: Request allowed
- **403**: Access denied (blacklist, suspicious patterns, DDoS)
- **405**: Method not allowed
- **413**: Payload too large
- **429**: Rate limit exceeded

## 📋 Best Practices

### 1. Configuration

```javascript
// ✅ Good: Environment-specific configuration
const isProduction = process.env.NODE_ENV === 'production';

const shield = new K9Shield({
  security: {
    allowPrivateIPs: !isProduction,
    maxBodySize: isProduction ? 1024 * 100 : 1024 * 1024 * 10
  },
  rateLimiting: {
    enabled: isProduction,
    default: {
      maxRequests: isProduction ? 60 : 1000
    }
  }
});

// ❌ Bad: Hardcoded production values in development
const shield = new K9Shield({
  security: { allowPrivateIPs: false }, // Blocks localhost in development
  rateLimiting: {
    default: { maxRequests: 10 } // Too restrictive for development
  }
});
```

### 2. Rate Limiting

```javascript
// ✅ Good: Route-specific limits based on criticality
rateLimiting: {
  routes: {
    '/api/auth/login': { POST: { maxRequests: 5, banDuration: 1800000 } },
    '/api/data/export': { GET: { maxRequests: 2, timeWindow: 3600000 } },
    '/api/search': { GET: { maxRequests: 100, timeWindow: 60000 } }
  }
}

// ❌ Bad: Same limits for all routes
rateLimiting: {
  default: { maxRequests: 10 } // Too restrictive for read operations
}
```

### 3. Error Handling

```javascript
// ✅ Good: Custom error responses
errorHandling: {
  customHandlers: {
    rateLimitExceeded: (res, data) => {
      res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: data.retryAfter
      });
    };
  }
}

// ❌ Bad: Generic error responses (reveals no information to users)
```

### 4. Monitoring

```javascript
// ✅ Good: Regular log monitoring
setInterval(() => {
  const logs = shield.getLogs();
  const recentBlocks = logs.filter(
    (log) =>
      log.level === 'warning' &&
      Date.now() - new Date(log.timestamp).getTime() < 300000 // Last 5 minutes
  );

  if (recentBlocks.length > 50) {
    console.warn('High number of blocks detected:', recentBlocks.length);
    // Send alert to monitoring system
  }
}, 60000); // Check every minute
```

### 5. Performance

```javascript
// ✅ Good: Reasonable limits based on your server capacity
const shield = new K9Shield({
  ddosProtection: {
    config: {
      maxConnections: 200, // Based on your server's capacity
      requestThreshold: 500 // Reasonable for legitimate traffic
    }
  }
});

// ❌ Bad: Overly restrictive limits
const shield = new K9Shield({
  ddosProtection: {
    config: {
      maxConnections: 10, // Too low, will block legitimate users
      requestThreshold: 20 // Too restrictive
    }
  }
});
```

## 🔒 Security Considerations

1. **Keep K9Shield Updated**: Regularly update to get the latest security patches
2. **Monitor Logs**: Set up log monitoring and alerting for security events
3. **Test Configuration**: Always test your configuration in a staging environment
4. **Rate Limiting**: Set appropriate limits based on your application's usage patterns
5. **IP Management**: Regularly review and update your IP blacklists and whitelists
6. **Custom Rules**: Validate custom rules thoroughly before deploying to production

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

With K9Shield, you can build a military-grade firewall infrastructure and protect your application professionally against the latest and most advanced web threats. For enterprise integrations, technical support, or custom solutions, please contact us at `support@k9crypt.xyz`.
