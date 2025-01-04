const crypto = require('crypto');

class HeaderManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;

        this.defaultSecurityHeaders = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
            'X-DNS-Prefetch-Control': 'off',
            'X-Download-Options': 'noopen',
            'X-Powered-By': undefined,
            'Server': undefined,
            'Access-Control-Allow-Credentials': 'true',
            'Access-Control-Expose-Headers': 'Content-Length, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset',
            'Feature-Policy': this.generateFeaturePolicy(),
            'Expect-CT': 'max-age=86400, enforce'
        };

        this.unsafeContentDirectives = new Set([
            "'unsafe-inline'",
            "'unsafe-eval'",
            'data:',
            'blob:',
            'filesystem:',
            'ws:',
            'wss:'
        ]);

        this.trustedSources = new Set([
            "'self'",
            'https:',
            'http://localhost',
            'ws://localhost',
            'wss://localhost'
        ]);
    }

    applySecurityHeaders(res, req) {
        try {
            if (!res || res.headersSent) {
                return;
            }

            const headers = {
                ...this.defaultSecurityHeaders,
                ...this.config.security.securityHeaders
            };

            headers['Content-Security-Policy'] = this.generateCSP(req);
            headers['Permissions-Policy'] = this.generatePermissionsPolicy();

            if (req.headers.origin) {
                this.applyCORSHeaders(req, res, headers);
            }

            if (process.env.NODE_ENV === 'production') {
                headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
            }

            this.applyCacheHeaders(req, res, headers);

            Object.entries(headers).forEach(([header, value]) => {
                try {
                    if (value === undefined) {
                        res.removeHeader(header);
                    } else if (value && typeof value === 'string' && !res.get(header)) {
                        res.setHeader(header, value);
                    }
                } catch (headerError) {
                    this.logger.log('warning', `Failed to set header ${header}: ${headerError.message}`);
                }
            });

            this.validateSecurityHeaders(res.getHeaders());

        } catch (e) {
            this.logger.log('error', `Failed to apply security headers: ${e.message}`);
        }
    }

    generateCSP(req) {
        try {
            const defaultPolicy = {
                'default-src': ["'self'"],
                'script-src': ["'self'", "'strict-dynamic'"],
                'style-src': ["'self'"],
                'img-src': ["'self'", 'data:', 'https:'],
                'font-src': ["'self'"],
                'connect-src': ["'self'"],
                'media-src': ["'self'"],
                'object-src': ["'none'"],
                'frame-src': ["'none'"],
                'worker-src': ["'self'"],
                'frame-ancestors': ["'none'"],
                'form-action': ["'self'"],
                'base-uri': ["'self'"],
                'manifest-src': ["'self'"],
                'upgrade-insecure-requests': [],
                'block-all-mixed-content': [],
                'require-trusted-types-for': ["'script'"],
                'trusted-types': ['default', 'dompurify'],
                ...this.config.security.csp
            };

            const nonce = this.generateNonce();
            if (nonce) {
                defaultPolicy['script-src'].push(`'nonce-${nonce}'`);
                req.cspNonce = nonce;
            }

            Object.keys(defaultPolicy).forEach(key => {
                if (Array.isArray(defaultPolicy[key])) {
                    defaultPolicy[key] = defaultPolicy[key].filter(value => 
                        this.trustedSources.has(value) || 
                        value.startsWith("'nonce-") || 
                        value === "'strict-dynamic'" ||
                        (process.env.NODE_ENV === 'development' && this.unsafeContentDirectives.has(value))
                    );
                }
            });

            return Object.entries(defaultPolicy)
                .map(([key, values]) => {
                    if (values.length === 0) {
                        return key;
                    }
                    return `${key} ${values.join(' ')}`;
                })
                .join('; ');
        } catch (e) {
            this.logger.log('error', `Failed to generate CSP: ${e.message}`);
            return "default-src 'self'";
        }
    }

    generatePermissionsPolicy() {
        try {
            const defaultPolicy = {
                'geolocation': '()',
                'microphone': '()',
                'camera': '()',
                'payment': '()',
                'usb': '()',
                'fullscreen': '(self)',
                'accelerometer': '()',
                'autoplay': '(self)',
                'document-domain': '()',
                'encrypted-media': '(self)',
                'gyroscope': '()',
                'magnetometer': '()',
                'midi': '()',
                'sync-xhr': '(self)',
                'interest-cohort': '()',
                'screen-wake-lock': '()',
                'web-share': '(self)',
                'clipboard-read': '(self)',
                'clipboard-write': '(self)',
                'gamepad': '()',
                'speaker-selection': '()',
                ...this.config.security.permissions
            };

            return Object.entries(defaultPolicy)
                .map(([feature, value]) => `${feature}=${value}`)
                .join(', ');
        } catch (e) {
            this.logger.log('error', `Failed to generate Permissions Policy: ${e.message}`);
            return Object.entries(this.config.security.permissions || {})
                .map(([feature, value]) => `${feature}=${value}`)
                .join(', ');
        }
    }

    generateFeaturePolicy() {
        try {
            const features = {
                'accelerometer': "'none'",
                'ambient-light-sensor': "'none'",
                'autoplay': "'none'",
                'battery': "'none'",
                'camera': "'none'",
                'display-capture': "'none'",
                'document-domain': "'none'",
                'encrypted-media': "'none'",
                'execution-while-not-rendered': "'none'",
                'execution-while-out-of-viewport': "'none'",
                'gyroscope': "'none'",
                'magnetometer': "'none'",
                'microphone': "'none'",
                'midi': "'none'",
                'navigation-override': "'none'",
                'payment': "'none'",
                'picture-in-picture': "'none'",
                'publickey-credentials-get': "'none'",
                'sync-xhr': "'none'",
                'usb': "'none'",
                'wake-lock': "'none'",
                'xr-spatial-tracking': "'none'"
            };

            return Object.entries(features)
                .map(([feature, value]) => `${feature} ${value}`)
                .join('; ');
        } catch (e) {
            this.logger.log('error', `Failed to generate Feature Policy: ${e.message}`);
            return "";
        }
    }

    applyCORSHeaders(req, res, headers) {
        try {
            const origin = req.headers.origin;
            const allowedOrigins = this.config.security.corsOrigin || '*';

            if (allowedOrigins === '*') {
                headers['Access-Control-Allow-Origin'] = '*';
            } else if (Array.isArray(allowedOrigins) && allowedOrigins.includes(origin)) {
                headers['Access-Control-Allow-Origin'] = origin;
                headers['Vary'] = 'Origin';
            }

            if (req.method === 'OPTIONS') {
                headers['Access-Control-Allow-Methods'] = this.config.security.allowedMethods.join(', ');
                headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With';
                headers['Access-Control-Max-Age'] = '86400';
            }
        } catch (e) {
            this.logger.log('error', `Failed to apply CORS headers: ${e.message}`);
        }
    }

    applyCacheHeaders(req, res, headers) {
        try {
            const sensitiveRoutes = ['/api', '/auth', '/admin'];
            const isSensitiveRoute = sensitiveRoutes.some(route => req.path.startsWith(route));

            if (isSensitiveRoute) {
                headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
                headers['Pragma'] = 'no-cache';
                headers['Expires'] = '0';
            } else {
                headers['Cache-Control'] = 'public, max-age=3600';
            }
        } catch (e) {
            this.logger.log('error', `Failed to apply cache headers: ${e.message}`);
        }
    }

    validateSecurityHeaders(headers) {
        try {
            const requiredHeaders = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ];

            const missingHeaders = requiredHeaders.filter(header => !headers[header.toLowerCase()]);
            if (missingHeaders.length > 0) {
                this.logger.log('warning', `Missing required security headers: ${missingHeaders.join(', ')}`);
            }

            const csp = headers['content-security-policy'];
            if (csp && csp.includes("'unsafe-inline'") && process.env.NODE_ENV === 'production') {
                this.logger.log('warning', "CSP contains 'unsafe-inline' in production");
            }
        } catch (e) {
            this.logger.log('error', `Failed to validate security headers: ${e.message}`);
        }
    }

    generateNonce() {
        try {
            return crypto.randomBytes(16).toString('base64');
        } catch (error) {
            this.logger.log('error', `Failed to generate nonce: ${error.message}`);
            return null;
        }
    }
}

module.exports = HeaderManager; 