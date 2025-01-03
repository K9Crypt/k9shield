class HeaderManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
    }

    applySecurityHeaders(res, req) {
        try {
            if (!res || res.headersSent) {
                return;
            }

            const headers = {
                ...this.config.security.securityHeaders,
                'Content-Security-Policy': this.generateCSP(),
                'Access-Control-Allow-Origin': this.config.security.corsOrigin || '*',
                'Access-Control-Allow-Methods': this.config.security.allowedMethods.join(', '),
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'X-Permitted-Cross-Domain-Policies': 'none',
                'Referrer-Policy': 'strict-origin-when-cross-origin',
                'Permissions-Policy': this.generatePermissionsPolicy(),
                'Cross-Origin-Embedder-Policy': 'require-corp',
                'Cross-Origin-Opener-Policy': 'same-origin',
                'Cross-Origin-Resource-Policy': 'same-origin'
            };

            Object.entries(headers).forEach(([header, value]) => {
                try {
                    if (value && typeof value === 'string' && !res.get(header)) {
                        res.setHeader(header, value);
                    }
                } catch (headerError) {
                    this.logger.log('warning', `Failed to set header ${header}: ${headerError.message}`);
                }
            });

            if (this.config.security.forceHTTPS && !req.secure) {
                res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
            }
        } catch (e) {
            this.logger.log('error', `Failed to apply security headers: ${e.message}`);
        }
    }

    generateCSP() {
        const defaultPolicy = this.config.security.csp || {
            'default-src': ["'self'"],
            'script-src': ["'self'", "'unsafe-inline'"],
            'style-src': ["'self'", "'unsafe-inline'"],
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
            'manifest-src': ["'self'"]
        };

        return Object.entries(defaultPolicy)
            .map(([key, values]) => `${key} ${values.join(' ')}`)
            .join('; ');
    }

    generatePermissionsPolicy() {
        const defaultPolicy = this.config.security.permissions || {
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
            'sync-xhr': '(self)'
        };

        return Object.entries(defaultPolicy)
            .map(([feature, value]) => `${feature}=${value}`)
            .join(', ');
    }
}

module.exports = HeaderManager; 