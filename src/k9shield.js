const defaultConfig = require('./config/default');
const { Logger } = require('./utils/logger');
const IPUtils = require('./utils/ip');
const DDoSProtection = require('./core/ddos');
const RateLimiter = require('./core/rateLimiter');
const Security = require('./core/security');
const HeaderManager = require('./middleware/headers');
const ConfigValidator = require('./core/validator');
const semver = require('semver');
const https = require('https');
const packageJson = require('../package.json');
const PolicyEngine = require('./policy-engine/PolicyEngine');
const DataLossPreventionManager = require('./core/dataLossProtection');

class K9Shield {
  constructor(config = {}) {
    try {
      this.config = this.mergeConfig(defaultConfig, config);
      this.logger = new Logger(this.config);
      this.validator = new ConfigValidator(this.logger);
      this.validator.validateConfig(this.config);
      this.ipUtils = new IPUtils(this.config, this.logger);
      this.security = new Security(this.config, this.logger, this.ipUtils);
      this.ddosProtection = new DDoSProtection(this.config, this.logger);
      this.rateLimiter = new RateLimiter(this.config, this.logger);
      this.headerManager = new HeaderManager(this.config, this.logger);
      this.dataLossPreventionManager = new DataLossPreventionManager(
        this.config,
        this.logger
      );

      this.policyEngine = new PolicyEngine(this);

      this.metrics = {
        requestsAllowed: 0,
        requestsBlocked: 0,
        requestsThrottled: 0,
        blocksByReason: {},
        lastReset: Date.now()
      };

      this.currentVersion = packageJson.version;
      if (this.config.updateCheck !== false) {
        this.checkForUpdates();
      }

      this.logger.log('info', 'K9Shield initialized successfully');
    } catch (error) {
      console.error('K9Shield initialization failed:', error.message);
      throw error;
    }
  }

  checkForUpdates() {
    try {
      const MAX_RESPONSE_BYTES = 64 * 1024;
      const req = https.get('https://registry.npmjs.org/k9shield/latest', (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return;
        }

        let data = '';
        let bytesRead = 0;

        res.on('data', (chunk) => {
          bytesRead += chunk.length;
          if (bytesRead > MAX_RESPONSE_BYTES) {
            res.destroy();
            return;
          }
          data += chunk;
        });

        res.on('end', () => {
          try {
            const npmData = JSON.parse(data);
            const latestVersion = npmData.version;
            if (latestVersion && semver.gt(latestVersion, this.currentVersion)) {
              this.logger.log('warning', `K9Shield update available: ${latestVersion}`);
              console.warn(
                `[K9Shield] Update available: ${this.currentVersion} → ${latestVersion}. Run: bun add k9shield@latest`
              );
            }
          } catch (parseError) {
            this.logger.log('error', `Error parsing NPM registry data: ${parseError.message}`);
          }
        });
      });

      // Abort if registry takes too long so init does not hang.
      req.setTimeout(3000, () => req.destroy());

      req.on('error', (err) => {
        this.logger.log('error', `Error checking for updates: ${err.message}`);
      });
    } catch (error) {
      this.logger.log('error', `Unexpected error in update check: ${error.message}`);
    }
  }

  mergeConfig(defaultConfig, userConfig) {
    const merged = { ...defaultConfig };

    for (const [key, value] of Object.entries(userConfig)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        merged[key] = this.mergeConfig(merged[key] || {}, value);
      } else {
        merged[key] = value;
      }
    }

    return merged;
  }

  protect() {
    return async (req, res, next) => {
      const startTime = Date.now();

      try {
        const clientIP = this.ipUtils.getClientIP(req);

        if (!clientIP) {
          this.logger.log('warning', 'Invalid IP address detected', {
            ip: req.ip
          });
          this.sendErrorResponse(res, 'invalidIP');
          return;
        }

        const context = { req, res, ip: clientIP, k9shield: this };
        const result = await this.policyEngine.evaluate(context);

        if (result.decision === 'ALLOW_BYPASS') {
          this.metrics.requestsAllowed++;
          this.emitSecurityEvent('allowed_bypass', { ip: clientIP, path: req.path });
          return next();
        }

        if (result.decision === 'BLOCK') {
          this.metrics.requestsBlocked++;
          const reason = result.reason || 'block';
          this.metrics.blocksByReason[reason] = (this.metrics.blocksByReason[reason] || 0) + 1;
          this.emitSecurityEvent('blocked', { ip: clientIP, reason, path: req.path, data: result.data });
          this.headerManager.applySecurityHeaders(res, req);
          this.sendErrorResponse(res, result.reason, result.data);
          return;
        }

        if (result.decision === 'THROTTLE') {
          this.metrics.requestsThrottled++;
          this.emitSecurityEvent('throttled', { ip: clientIP, reason: result.reason, path: req.path, data: result.data });
          this.headerManager.applySecurityHeaders(res, req);
          this.sendErrorResponse(res, result.reason, result.data);
          return;
        }

        this.metrics.requestsAllowed++;
        this.headerManager.applySecurityHeaders(res, req);

        const endTime = Date.now();
        this.logger.log('debug', 'Request processed', {
          ip: clientIP,
          path: req.path,
          method: req.method,
          duration: endTime - startTime
        });

        next();
      } catch (error) {
        this.logger.log('error', 'Unexpected error in protect middleware', {
          error: error.message,
          stack: error.stack
        });
        this.sendErrorResponse(res, 'internalError', {
          message: 'An unexpected error occurred'
        });
      }
    };
  }

  shouldBypassRoute(path) {
    if (!path || !this.config.bypassRoutes) return false;

    return this.config.bypassRoutes.some((route) => {
      try {
        if (typeof route === 'string') {
          return path === route;
        } else if (route instanceof RegExp) {
          return route.test(path);
        }
        return false;
      } catch (error) {
        this.logger.log('error', 'Error in bypass route check', {
          error: error.message
        });
        return false;
      }
    });
  }

  sendErrorResponse(res, errorType, additionalData = {}) {
    try {
      const customHandler = this.config.errorHandling.customHandlers[errorType];
      if (customHandler && typeof customHandler === 'function') {
        return customHandler(res, additionalData);
      }

      const errorResponse =
        this.config.errorHandling.defaultResponses[errorType];
      if (!errorResponse) {
        this.logger.log('error', `Undefined error type: ${errorType}`);
        return res.status(500).json({
          error: 'Internal server error',
          message: 'An unexpected error occurred',
          code: 'internalError',
          timestamp: new Date().toISOString()
        });
      }

      const response = {
        error: errorResponse.message,
        code: errorType,
        timestamp: new Date().toISOString(),
        ...additionalData
      };

      if (
        this.config.errorHandling.includeErrorDetails &&
        errorResponse.details
      ) {
        response.details = errorResponse.details;
      }

      res.status(errorResponse.status).json(response);
    } catch (error) {
      this.logger.log('error', 'Error sending error response', {
        error: error.message
      });
      res.status(500).json({
        error: 'Internal server error',
        message:
          'An unexpected error occurred while processing the error response',
        code: 'internalError',
        timestamp: new Date().toISOString()
      });
    }
  }

  setConfig(config) {
    try {
      const newConfig = this.mergeConfig(this.config, config);
      this.validator.validateConfig(newConfig);
      this.config = newConfig;
      this.logger.log('info', 'Configuration updated successfully');
    } catch (error) {
      this.logger.log('error', 'Configuration update failed', {
        error: error.message
      });
      throw error;
    }
  }

  blockIP(ip) {
    try {
      this.security.blockIP(ip);
      this.logger.log('info', 'IP blocked successfully', { ip });
    } catch (error) {
      this.logger.log('error', 'Error blocking IP', {
        ip,
        error: error.message
      });
      throw error;
    }
  }

  unblockIP(ip) {
    try {
      this.security.unblockIP(ip);
      this.logger.log('info', 'IP unblocked successfully', { ip });
    } catch (error) {
      this.logger.log('error', 'Error unblocking IP', {
        ip,
        error: error.message
      });
      throw error;
    }
  }

  whitelistIP(ip) {
    try {
      this.security.whitelistIP(ip);
      this.logger.log('info', 'IP whitelisted successfully', { ip });
    } catch (error) {
      this.logger.log('error', 'Error whitelisting IP', {
        ip,
        error: error.message
      });
      throw error;
    }
  }

  unwhitelistIP(ip) {
    try {
      this.security.unwhitelistIP(ip);
      this.logger.log('info', 'IP removed from whitelist successfully', { ip });
    } catch (error) {
      this.logger.log('error', 'Error removing IP from whitelist', {
        ip,
        error: error.message
      });
      throw error;
    }
  }

  addSuspiciousPattern(pattern) {
    try {
      this.security.addSuspiciousPattern(pattern);
      this.logger.log('info', 'Suspicious pattern added successfully');
    } catch (error) {
      this.logger.log('error', 'Error adding suspicious pattern', {
        error: error.message
      });
      throw error;
    }
  }

  getLogs() {
    try {
      return this.logger.getLogs();
    } catch (error) {
      this.logger.log('error', 'Error getting logs', { error: error.message });
      throw error;
    }
  }

  getArchivedLogs() {
    try {
      return this.logger.getArchivedLogs();
    } catch (error) {
      this.logger.log('error', 'Error getting archived logs', {
        error: error.message
      });
      throw error;
    }
  }

  reset() {
    try {
      this.security.reset();
      this.rateLimiter.reset();
      this.ddosProtection.reset();
      this.logger.reset();
      this.metrics.requestsAllowed = 0;
      this.metrics.requestsBlocked = 0;
      this.metrics.requestsThrottled = 0;
      this.metrics.blocksByReason = {};
      this.metrics.lastReset = Date.now();
      this.logger.log('info', 'K9Shield reset successfully');
    } catch (error) {
      this.logger.log('error', 'Error resetting K9Shield', {
        error: error.message
      });
      throw error;
    }
  }

  emitSecurityEvent(event, payload) {
    const fn = this.config.onSecurityEvent;
    if (typeof fn === 'function') {
      setImmediate(() => {
        try {
          fn(event, payload);
        } catch (e) {
          this.logger.log('error', `onSecurityEvent error: ${e.message}`);
        }
      });
    }
  }

  getMetrics() {
    return { ...this.metrics };
  }

  scanForSensitiveData(data) {
    try {
      return this.dataLossPreventionManager.scanForSensitiveData(data);
    } catch (error) {
      this.logger.log('error', 'Sensitive data scan failed', {
        error: error.message
      });
      throw error;
    }
  }

  maskSensitiveData(data) {
    try {
      return this.dataLossPreventionManager.maskSensitiveData(data);
    } catch (error) {
      this.logger.log('error', 'Sensitive data masking failed', {
        error: error.message
      });
      throw error;
    }
  }

  encryptSensitiveData(data) {
    try {
      return this.dataLossPreventionManager.encryptSensitiveData(data);
    } catch (error) {
      this.logger.log('error', 'Sensitive data encryption failed', {
        error: error.message
      });
      throw error;
    }
  }

  decryptSensitiveData(encryptedData) {
    try {
      return this.dataLossPreventionManager.decryptSensitiveData(encryptedData);
    } catch (error) {
      this.logger.log('error', 'Sensitive data decryption failed', {
        error: error.message
      });
      throw error;
    }
  }

  addCustomSensitivePattern(type, pattern) {
    try {
      this.dataLossPreventionManager.addCustomSensitivePattern(type, pattern);
    } catch (error) {
      this.logger.log('error', 'Adding custom sensitive pattern failed', {
        error: error.message
      });
      throw error;
    }
  }
}

module.exports = K9Shield;
