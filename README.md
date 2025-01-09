![Banner](https://www.upload.ee/image/17590030/k9shield.png)

# K9Shield

K9Shield is a comprehensive security middleware for Node.js applications, providing robust protection against various web security threats. It offers advanced features like DDoS protection, rate limiting, IP management, and security headers management.

## Updates

### Data Protection Enhancements (January 2025)
- Added advanced data loss prevention module
- Implemented sensitive data detection and masking
- Integrated k9crypt for secure data encryption
- Added custom pattern support for sensitive data
- Enhanced data protection with regex-based detection
- Implemented async encryption and decryption methods
- Added comprehensive data masking techniques for various sensitive information types

#### Usage Example

```javascript
const shield = new K9Shield();

// Optional: Scan for sensitive data
const sensitiveDataResult = shield.scanForSensitiveData('Credit Card: 4111-1111-1111-1111');
console.log(sensitiveDataResult);
// Output: { hasSensitiveData: true, detectedData: { creditCard: ['4111-1111-1111-1111'] } }

// Optional: Mask sensitive data
const maskedData = shield.maskSensitiveData('Email: john.doe@example.com');
console.log(maskedData);
// Output: 'Email: jo****@example.com'

// Optional: Encrypt sensitive data
const encryptedData = await shield.encryptSensitiveData('Secret Information');
const decryptedData = await shield.decryptSensitiveData(encryptedData);

// Optional: Add custom sensitive pattern
shield.addCustomSensitivePattern('customId', /\bCUST-\d{6}\b/);
```

#### Module Status
- **Completely Optional**: The data loss prevention module is not mandatory
- **Can be Disabled**: No impact on core security features
- **Modular Design**: Use only the features you need
- **Performance Overhead**: Minimal additional processing
- **Recommended for**: Applications handling sensitive personal or financial data

*Note: While optional, this module provides an additional layer of data protection for applications requiring advanced data handling.*

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Core Components](#core-components)
- [Configuration](#configuration)
- [Security Features](#security-features)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Features

### Core Security Features
- **DDoS Protection**
  - Progressive penalty system
  - Connection tracking
  - Burst detection
  - Path-based rate limiting
  - Configurable thresholds and block durations

- **Rate Limiting**
  - Route-specific limits
  - Flexible time windows
  - Throttling support
  - Ban duration management
  - Distributed system support

- **IP Management**
  - CIDR notation support
  - IPv6 support with IPv4 mapping
  - Private IP detection
  - Whitelist/Blacklist functionality
  - Proxy support

- **Request Validation**
  - Method validation
  - Payload size limits
  - Header validation
  - Pattern detection (SQL Injection, XSS, Path Traversal)
  - User Agent and Referer filtering

### Advanced Security
- **Security Headers**
  - Content Security Policy (CSP)
  - Permissions Policy
  - HSTS support
  - XSS protection
  - Frame options
  - Content type options

- **Pattern Detection**
  - SQL Injection patterns
  - XSS patterns
  - Path traversal attempts
  - Custom pattern support
  - Regular expression based detection

### Monitoring & Logging
- **Logging System**
  - Multiple log levels
  - Automatic rotation
  - Archive management
  - Performance metrics
  - Security event tracking

- **Request Tracking**
  - IP tracking
  - Request duration
  - Path monitoring
  - Error logging
  - Detailed request information

## Installation

```bash
npm install k9shield
```

## Quick Start

### Basic Express Integration

```javascript
const express = require('express');
const K9Shield = require('k9shield');

const app = express();
const shield = new K9Shield();

// Protect all routes
app.use(shield.protect());

app.get('/', (req, res) => {
    res.json({ message: 'A secure endpoint' });
});

app.listen(3000, () => {
    console.log('Server running securely');
});
```

### Detailed Security Configuration

```javascript
const shield = new K9Shield({
    rateLimiting: {
        enabled: true,
        default: {
            maxRequests: 10,     // 10 requests per minute
            timeWindow: 60000,   // 1 minute
            banDuration: 300000  // 5 minutes ban
        },
        routes: {
            '/api/sensitive-endpoint': {
                'POST': { 
                    maxRequests: 3,      // Stricter control for sensitive endpoint
                    timeWindow: 60000,   // 1 minute
                    banDuration: 600000  // 10 minutes ban
                }
            }
        }
    },
    security: {
        maxBodySize: 1024 * 100,  // 100KB payload limit
        allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
        userAgentBlacklist: ['bad-bot', 'malicious-crawler']
    },
    ddosProtection: {
        enabled: true,
        config: {
            maxConnections: 50,
            blockDuration: 300,
            requestThreshold: 30,
            rateLimitByPath: {
                '/api/*': 20,    // Special limit for API routes
                '*': 50           // General limit for all routes
            }
        }
    }
});
```

### IP Management Examples

```javascript
// Block a specific IP
shield.blockIP('192.168.1.100');

// Whitelist an IP
shield.whitelistIP('10.0.0.1');

// Unblock a previously blocked IP
shield.unblockIP('192.168.1.100');

// Remove an IP from whitelist
shield.unwhitelistIP('10.0.0.1');
```

### Adding Custom Security Patterns

```javascript
// Custom patterns for SQL Injection and XSS
shield.addSuspiciousPattern(/SELECT.*FROM/i);
shield.addSuspiciousPattern(/<script>|javascript:/i);
```

### Advanced Error Handling

```javascript
const shield = new K9Shield({
    errorHandling: {
        includeErrorDetails: true,
        customHandlers: {
            // Custom response for rate limit exceeded
            'rateLimitExceeded': (res, data) => {
                res.status(429).json({
                    message: 'Too many requests',
                    retryAfter: data.retryAfter,
                    limit: data.limit
                });
            },
            // Custom response for DDoS attack
            'ddosAttack': (res) => {
                res.status(403).json({
                    message: 'Suspicious traffic detected',
                    action: 'Access denied'
                });
            }
        }
    }
});
```

### Logging and Monitoring

```javascript
// Get all log records
const logs = shield.getLogs();

// Get archived log records
const archivedLogs = shield.getArchivedLogs();

// Reset all settings and statistics
shield.reset();
```

### Test Environment Configuration

```javascript
// More flexible settings for development environment
process.env.NODE_ENV = 'development';

const shield = new K9Shield({
    rateLimiting: { enabled: false },  // Rate limit disabled in development
    ddosProtection: { enabled: false } // DDoS protection disabled
});
```

### Production Environment Configuration

```javascript
// Strict security settings for production
process.env.NODE_ENV = 'production';

const shield = new K9Shield({
    rateLimiting: {
        enabled: true,
        default: { maxRequests: 100, timeWindow: 60000 }
    },
    security: {
        maxBodySize: 1024 * 1024,  // 1MB
        allowPrivateIPs: false
    },
    ddosProtection: {
        enabled: true,
        config: {
            maxConnections: 200,
            blockDuration: 1800000  // 30 minutes block
        }
    },
    logging: {
        level: 'warning',  // Log only critical warnings
        maxLogSize: 10000  // More log storage
    }
});
```

## Core Components

### 1. K9Shield Class (`src/k9shield.js`)
The main class that orchestrates all security features:

```javascript
const shield = new K9Shield({
    security: {
        trustProxy: true,
        allowPrivateIPs: false,
        maxBodySize: 1024 * 1024 // 1MB
    }
});
```

### 2. IP Utils (`src/utils/ip.js`)
Handles IP address management and validation:

```javascript
// IP management examples
shield.blockIP('192.168.1.100');
shield.whitelistIP('10.0.0.1');
shield.unblockIP('192.168.1.100');
shield.unwhitelistIP('10.0.0.1');
```

### 3. Security Module (`src/core/security.js`)
Manages security patterns and request validation:

```javascript
// Add custom security patterns
shield.addSuspiciousPattern(/eval\(/i);
shield.addSuspiciousPattern(/(document|window)\./i);
```

### 4. Rate Limiter (`src/core/rateLimiter.js`)
Controls request rates and implements throttling:

```javascript
const config = {
    rateLimiting: {
        enabled: true,
        default: {
            maxRequests: 100,
            timeWindow: 60000, // 1 minute
            banDuration: 3600000 // 1 hour
        },
        routes: {
            '/api/data': {
                'POST': { maxRequests: 5, timeWindow: 30000 }
            }
        }
    }
};
```

### 5. DDoS Protection (`src/core/ddos.js`)
Provides DDoS attack prevention:

```javascript
const config = {
    ddosProtection: {
        enabled: true,
        config: {
            maxConnections: 200,
            timeWindow: 60000,
            blockDuration: 1800000,
            requestThreshold: 500,
            burstThreshold: 50
        }
    }
};
```

## Configuration

### Complete Configuration Example

```javascript
const shield = new K9Shield({
    security: {
        trustProxy: true,
        allowPrivateIPs: false,
        maxBodySize: 1024 * 1024,
        allowedMethods: ['GET', 'POST', 'PUT', 'DELETE'],
        userAgentBlacklist: ['bad-bot', 'malicious-crawler'],
        refererBlacklist: ['malicious.com'],
        securityHeaders: {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        },
        csp: {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", 'data:', 'https:']
        },
        permissions: {
            'geolocation': '()',
            'camera': '()',
            'microphone': '()'
        }
    },
    rateLimiting: {
        enabled: true,
        default: {
            maxRequests: 100,
            timeWindow: 60000,
            banDuration: 3600000,
            throttleDuration: 60000,
            throttleDelay: 1000
        },
        routes: {
            '/api/data': {
                'POST': { maxRequests: 5, timeWindow: 30000 }
            }
        }
    },
    ddosProtection: {
        enabled: true,
        config: {
            maxConnections: 200,
            timeWindow: 60000,
            blockDuration: 1800000,
            requestThreshold: 500,
            burstThreshold: 50,
            slowRequestThreshold: 10,
            rateLimitByPath: {
                '/api/*': 100,
                '/auth/*': 20,
                '*': 500
            }
        }
    },
    logging: {
        enable: true,
        level: 'info',
        maxLogSize: 5000,
        archiveLimit: 5
    },
    errorHandling: {
        includeErrorDetails: true,
        customHandlers: {
            'rateLimitExceeded': (res, data) => {
                res.status(429).json({
                    message: 'Too many requests',
                    retryAfter: data.retryAfter,
                    limit: data.limit,
                    windowMs: data.windowMs
                });
            }
        }
    },
    bypassRoutes: ['/health', '/metrics']
});
```

## Security Features

### 1. Rate Limiting
- **Global Limits**: Set default limits for all routes
- **Route-Specific Limits**: Configure different limits for specific routes
- **Throttling**: Progressive slowdown of requests
- **Ban System**: Temporary IP bans for limit violations

### 2. DDoS Protection
- **Connection Tracking**: Monitor connection counts
- **Burst Detection**: Identify sudden request spikes
- **Progressive Penalties**: Increasing restrictions for violations
- **Path-Based Limits**: Different limits for different paths

### 3. Security Headers
- **CSP**: Content Security Policy configuration
- **HSTS**: HTTP Strict Transport Security
- **XSS Protection**: Cross-site scripting prevention
- **Frame Options**: Clickjacking prevention

### 4. Pattern Detection
- **SQL Injection**: Detect SQL injection attempts
- **XSS**: Cross-site scripting pattern detection
- **Path Traversal**: Directory traversal prevention
- **Custom Patterns**: Add your own detection patterns

## API Reference

### Shield Methods
```javascript
// IP Management
shield.blockIP(ip)
shield.unblockIP(ip)
shield.whitelistIP(ip)
shield.unwhitelistIP(ip)

// Pattern Management
shield.addSuspiciousPattern(pattern)

// Configuration
shield.setConfig(config)

// Logging
shield.getLogs()
shield.getArchivedLogs()

// Reset
shield.reset()
```

## Testing

Run the test server:

```bash
node test.js
```

### Test Commands

1. **Basic Request Test**
```bash
curl http://localhost:3000/
```

2. **Rate Limit Test**
```bash
for i in $(seq 1 10); do 
    curl http://localhost:3000/api/test
    echo ""
    sleep 1
done
```

3. **SQL Injection Test**
```bash
curl -X POST http://localhost:3000/search \
     -H "Content-Type: application/json" \
     -d '{"query": "1 UNION SELECT * FROM users"}'
```

4. **XSS Test**
```bash
curl -X POST http://localhost:3000/comment \
     -H "Content-Type: application/json" \
     -d '{"comment": "<script>alert(\"XSS\")</script>"}'
```

5. **IP Information**
```bash
curl http://localhost:3000/ip
```

6. **Bypass Routes Test**
```bash
curl http://localhost:3000/health
curl http://localhost:3000/metrics
```

7. **DDoS Test**
```bash
for i in $(seq 1 100); do 
    curl http://localhost:3000/ & 
done
```

8. **Large Payload Test**
```bash
curl -X POST http://localhost:3000/comment \
     -H "Content-Type: application/json" \
     -d '{"comment": "A...(100KB+)..."}'
```

## Error Handling

K9Shield provides detailed error responses:

- **403**: Access Denied / Suspicious Request
- **405**: Method Not Allowed
- **413**: Payload Too Large
- **429**: Too Many Requests
- **500**: Internal Server Error

Each error includes:
- Error message
- Error code
- Timestamp
- Additional details (when enabled)

## Best Practices

1. **Rate Limiting**
   - Set appropriate limits based on your application needs
   - Use route-specific limits for sensitive endpoints
   - Implement proper retry-after headers

2. **DDoS Protection**
   - Configure thresholds based on your server capacity
   - Monitor and adjust settings based on traffic patterns
   - Use bypass routes for critical endpoints

3. **Security Headers**
   - Implement strict CSP policies
   - Enable HSTS in production
   - Configure appropriate frame options

4. **Logging**
   - Set appropriate log levels
   - Implement log rotation
   - Monitor security events regularly

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.