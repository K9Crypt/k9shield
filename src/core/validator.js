const { LOG_LEVELS } = require('../utils/logger');

class ConfigValidator {
    constructor(logger) {
        this.logger = logger;
        this.LOG_LEVELS = LOG_LEVELS;
    }

    validateConfig(config) {
        if (!config || typeof config !== 'object') {
            throw new Error('Invalid configuration object');
        }

        if (config.security) {
            this.validateSecurityConfig(config.security);
        }

        if (config.logging) {
            this.validateLoggingConfig(config.logging);
        }

        if (config.rateLimiting) {
            this.validateRateLimitingConfig(config.rateLimiting);
        }

        if (config.ddosProtection) {
            this.validateDDoSConfig(config.ddosProtection);
        }

        if (config.errorHandling) {
            this.validateErrorHandlingConfig(config.errorHandling);
        }
    }

    validateSecurityConfig(security) {
        if (typeof security.trustProxy !== 'boolean') {
            throw new Error('security.trustProxy must be boolean');
        }

        if (security.securityHeaders && typeof security.securityHeaders !== 'object') {
            throw new Error('security.securityHeaders must be an object');
        }

        if (!Array.isArray(security.allowedMethods)) {
            throw new Error('security.allowedMethods must be an array');
        }

        if (typeof security.maxBodySize !== 'number' || security.maxBodySize <= 0) {
            throw new Error('security.maxBodySize must be a positive number');
        }

        if (!Array.isArray(security.requestHeaderWhitelist)) {
            throw new Error('security.requestHeaderWhitelist must be an array');
        }
    }

    validateLoggingConfig(logging) {
        if (typeof logging.enable !== 'boolean') {
            throw new Error('logging.enable must be boolean');
        }

        if (!this.LOG_LEVELS[logging.level]) {
            throw new Error(`Invalid log level: ${logging.level}`);
        }

        if (!Number.isInteger(logging.maxLogSize) || logging.maxLogSize <= 0) {
            throw new Error('logging.maxLogSize must be a positive integer');
        }

        if (!Number.isInteger(logging.archiveLimit) || logging.archiveLimit <= 0) {
            throw new Error('logging.archiveLimit must be a positive integer');
        }
    }

    validateRateLimitingConfig(rateLimiting) {
        if (typeof rateLimiting.enabled !== 'boolean') {
            throw new Error('rateLimiting.enabled must be boolean');
        }

        if (rateLimiting.default) {
            this.validateRateLimitConfig(rateLimiting.default);
        }

        if (rateLimiting.routes) {
            if (typeof rateLimiting.routes !== 'object') {
                throw new Error('rateLimiting.routes must be an object');
            }

            Object.values(rateLimiting.routes).forEach(route => {
                if (typeof route === 'object') {
                    Object.values(route).forEach(config => {
                        if (config) this.validateRateLimitConfig(config);
                    });
                }
            });
        }
    }

    validateDDoSConfig(ddosConfig) {
        const requiredFields = [
            'maxConnections',
            'timeWindow',
            'blockDuration',
            'requestThreshold',
            'burstThreshold',
            'slowRequestThreshold'
        ];

        requiredFields.forEach(field => {
            if (!Number.isInteger(ddosConfig.config[field]) || ddosConfig.config[field] <= 0) {
                throw new Error(`ddosProtection.config.${field} must be a positive integer`);
            }
        });

        if (typeof ddosConfig.config.rateLimitByPath !== 'object') {
            throw new Error('ddosProtection.config.rateLimitByPath must be an object');
        }
    }

    validateErrorHandlingConfig(errorHandling) {
        if (typeof errorHandling.customHandlers !== 'object') {
            throw new Error('errorHandling.customHandlers must be an object');
        }

        if (typeof errorHandling.defaultResponses !== 'object') {
            throw new Error('errorHandling.defaultResponses must be an object');
        }

        Object.values(errorHandling.defaultResponses).forEach(response => {
            if (!response.status || !response.message) {
                throw new Error('Each error response must have status and message properties');
            }
            if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
                throw new Error('Error response status must be a valid HTTP status code');
            }
        });
    }

    validateRateLimitConfig(config) {
        const requiredFields = ['maxRequests', 'timeWindow', 'banDuration', 'retryAfter', 'throttleDuration', 'throttleDelay'];
        requiredFields.forEach(field => {
            if (!Number.isInteger(config[field]) || config[field] <= 0) {
                throw new Error(`Rate limit ${field} must be a positive integer`);
            }
        });
    }
}

module.exports = ConfigValidator; 