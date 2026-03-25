const crypto = require('crypto');
const https = require('https');
const semver = require('semver');
const defaultConfig = require('./config/default');
const { Logger } = require('./utils/logger');
const IPUtils = require('./utils/ip');
const DDoSProtection = require('./core/ddos');
const RateLimiter = require('./core/rateLimiter');
const Security = require('./core/security');
const WebhookProtection = require('./core/webhookProtection');
const HeaderManager = require('./middleware/headers');
const ConfigValidator = require('./core/validator');
const PolicyEngine = require('./policy-engine/PolicyEngine');
const DataLossPreventionManager = require('./core/dataLossProtection');
const { describePattern, matchesRoutePattern } = require('./utils/routes');
const packageJson = require('../package.json');

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    !(value instanceof RegExp) &&
    !(value instanceof Date) &&
    !Buffer.isBuffer(value)
  );
}

class K9Shield {
  static getPresets() {
    // Presets are intentionally small config fragments so teams can start from
    // an opinionated baseline and still override every field explicitly.
    return {
      'strict-api': {
        security: {
          routeProfiles: [{ pattern: '/api/*', profile: 'api' }],
          csrfProtection: { enabled: false },
          fastInspection: {
            enabled: true,
            deepInspectMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
          }
        },
        rateLimiting: {
          keyStrategy: 'identity',
          includeTenantInKey: true
        }
      },
      'public-form': {
        security: {
          csrfProtection: {
            enabled: true,
            requireOriginOrReferer: true,
            tokenMode: 'double-submit'
          }
        }
      },
      'admin-panel': {
        security: {
          routeProfiles: [{ pattern: '/admin/*', profile: 'admin' }],
          csrfProtection: {
            enabled: true,
            requireOriginOrReferer: true,
            tokenMode: 'double-submit'
          },
          botProtection: {
            enabled: true,
            blockThreshold: 4,
            throttleThreshold: 2
          }
        },
        rateLimiting: {
          keyStrategy: 'identity'
        }
      },
      'webhook-ingress': {
        security: {
          routeProfiles: [{ pattern: '/webhooks/*', profile: 'webhook' }],
          webhookProtection: {
            enabled: true
          }
        }
      },
      'file-upload': {
        security: {
          routeProfiles: [{ pattern: '/upload/*', profile: 'upload' }],
          streamingProtection: {
            enabled: true,
            maxChunkCount: 1024
          }
        }
      }
    };
  }

  constructor(config = {}) {
    try {
      const configWithPreset = this.applyPresetConfig(config);
      const mergedConfig = this.mergeConfig(defaultConfig, configWithPreset);
      this.config = mergedConfig;
      this.logger = new Logger(mergedConfig);
      this.validator = new ConfigValidator(this.logger);
      this.validator.validateConfig(mergedConfig);
      this.ipUtils = new IPUtils(mergedConfig, this.logger);
      this.security = new Security(mergedConfig, this.logger, this.ipUtils);
      this.ddosProtection = new DDoSProtection(mergedConfig, this.logger);
      this.rateLimiter = new RateLimiter(mergedConfig, this.logger);
      this.headerManager = new HeaderManager(mergedConfig, this.logger);
      this.webhookProtection = new WebhookProtection(mergedConfig, this.logger);
      this.dataLossPreventionManager = new DataLossPreventionManager(
        mergedConfig,
        this.logger
      );
      this.securityEventExporters = [];
      this.applyConfig(mergedConfig);

      this.policyEngine = new PolicyEngine(this);

      this.metrics = {
        requestsAllowed: 0,
        requestsBlocked: 0,
        requestsThrottled: 0,
        requestsShadowed: 0,
        blocksByReason: {},
        rules: {},
        decisionHistory: [],
        securityEvents: [],
        lastReset: Date.now()
      };

      this.currentVersion = packageJson.version;
      if (this.shouldCheckForUpdates()) {
        this.checkForUpdates();
      }

      this.logger.log('info', 'K9Shield initialized successfully');
    } catch (error) {
      console.error('K9Shield initialization failed:', error.message);
      throw error;
    }
  }

  shouldCheckForUpdates() {
    if (this.config.updateCheck === false) return false;
    if (this.config.updateCheck === true) return true;
    return process.env.NODE_ENV !== 'production';
  }

  applyPresetConfig(userConfig) {
    if (!userConfig || !userConfig.preset) return userConfig;
    const presets = K9Shield.getPresets();
    const preset = presets[userConfig.preset];
    if (!preset) return userConfig;

    const { preset: presetName, ...rest } = userConfig;
    return this.mergeConfig(preset, rest);
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
                `[K9Shield] Update available: ${this.currentVersion} -> ${latestVersion}. Run: bun add k9shield@latest`
              );
            }
          } catch (parseError) {
            this.logger.log('error', `Error parsing NPM registry data: ${parseError.message}`);
          }
        });
      });

      req.setTimeout(3000, () => req.destroy());
      req.on('error', (error) => {
        this.logger.log('error', `Error checking for updates: ${error.message}`);
      });
    } catch (error) {
      this.logger.log('error', `Unexpected error in update check: ${error.message}`);
    }
  }

  mergeConfig(baseConfig, userConfig) {
    if (!isPlainObject(baseConfig)) {
      return userConfig === undefined ? baseConfig : userConfig;
    }

    const merged = { ...baseConfig };
    if (!isPlainObject(userConfig)) {
      return merged;
    }

    for (const [key, value] of Object.entries(userConfig)) {
      if (isPlainObject(value) && isPlainObject(merged[key])) {
        merged[key] = this.mergeConfig(merged[key], value);
      } else {
        merged[key] = value;
      }
    }

    return merged;
  }

  applyConfig(newConfig) {
    const previousKey = this.dataLossPreventionManager?.configuredEncryptionKey;

    this.config = newConfig;
    if (this.logger) this.logger.config = newConfig;
    if (this.ipUtils) this.ipUtils.config = newConfig;
    if (this.security) this.security.config = newConfig;
    if (this.ddosProtection) this.ddosProtection.config = newConfig;
    if (this.rateLimiter) this.rateLimiter.config = newConfig;
    if (this.headerManager) this.headerManager.config = newConfig;
    if (this.webhookProtection) this.webhookProtection.config = newConfig;

    if (this.dataLossPreventionManager) {
      const nextKey = this.dataLossPreventionManager.getConfiguredEncryptionKey(newConfig);
      if (previousKey !== nextKey) {
        this.dataLossPreventionManager = new DataLossPreventionManager(
          newConfig,
          this.logger
        );
      } else {
        this.dataLossPreventionManager.config = newConfig;
      }
    }
  }

  resolveRouteProfile(req) {
    // Profiles let us pay the expensive security cost only where it adds value.
    // This keeps hot API paths cheaper while still allowing strict HTML/admin rules.
    const securityConfig = this.config.security || {};
    const profiles = securityConfig.profiles || {};
    const defaultProfile = profiles.default || {};
    const routeProfiles = Array.isArray(securityConfig.routeProfiles)
      ? securityConfig.routeProfiles
      : [];

    for (const entry of routeProfiles) {
      if (matchesRoutePattern(req.path, entry.pattern)) {
        const profile = profiles[entry.profile] || {};
        return {
          name: entry.profile,
          matcher: describePattern(entry.pattern),
          ...defaultProfile,
          ...profile,
          ...(entry.overrides || {})
        };
      }
    }

    const accept = String(req.headers.accept || '').toLowerCase();
    if (accept.includes('text/html')) {
      return {
        name: 'html',
        ...defaultProfile,
        ...(profiles.html || {})
      };
    }

    return {
      name: 'default',
      ...defaultProfile
    };
  }

  shouldShadowDecision(result, req, context) {
    const mode = this.config.mode || {};
    const profileShadow = req?.k9shieldProfile?.shadowMode === true;
    const shadowRules = Array.isArray(mode.shadowRules) ? mode.shadowRules : [];
    const matchedRule = context?.decisionTrace?.find((entry) => entry.matched)?.rule;
    return mode.shadow === true || profileShadow || shadowRules.includes(matchedRule);
  }

  recordDecision(req, ip, result, context, durationMs) {
    const trace = Array.isArray(context?.decisionTrace) ? context.decisionTrace : [];

    if (!this.config.observability?.enabled) return;

    // Keep histories bounded so observability stays useful without becoming a memory leak.
    trace.forEach((entry) => {
      const rule = this.metrics.rules[entry.rule] || {
        matched: 0,
        executed: 0,
        totalDurationNs: 0
      };
      rule.executed += 1;
      if (entry.matched) rule.matched += 1;
      rule.totalDurationNs += entry.durationNs;
      this.metrics.rules[entry.rule] = rule;
    });

    const maxHistory = this.config.observability.maxDecisionHistory || 200;
    this.metrics.decisionHistory.push({
      timestamp: new Date().toISOString(),
      ip,
      path: req.path,
      method: req.method,
      decision: result.decision,
      reason: result.reason || null,
      durationMs,
      profile: req.k9shieldProfile?.name || 'default',
      trace
    });
    if (this.metrics.decisionHistory.length > maxHistory) {
      this.metrics.decisionHistory.splice(0, this.metrics.decisionHistory.length - maxHistory);
    }
  }

  createEventEnvelope(event, payload = {}, context = {}) {
    const base = {
      timestamp: new Date().toISOString(),
      event,
      payload,
      trace:
        this.config.eventExport?.includeDecisionTrace === true
          ? context.decisionTrace || []
          : undefined
    };

    // Sign exported events so downstream systems can verify they came from this process
    // and were not modified in transit.
    const signingKey = this.config.eventExport?.signingKey;
    if (signingKey) {
      base.signature = crypto
        .createHmac('sha256', signingKey)
        .update(JSON.stringify({ event: base.event, payload: base.payload, timestamp: base.timestamp }))
        .digest('hex');
    }

    return base;
  }

  emitSecurityEvent(event, payload, context = {}) {
    const envelope = this.createEventEnvelope(event, payload, context);
    const fn = this.config.onSecurityEvent;
    const maxHistory = this.config.observability?.maxEventHistory || 200;

    this.metrics.securityEvents.push(envelope);
    if (this.metrics.securityEvents.length > maxHistory) {
      this.metrics.securityEvents.splice(0, this.metrics.securityEvents.length - maxHistory);
    }

    if (typeof fn === 'function') {
      setImmediate(() => {
        try {
          fn(event, envelope);
        } catch (error) {
          this.logger.log('error', `onSecurityEvent error: ${error.message}`);
        }
      });
    }

    // Event exporters run out-of-band so request latency is not coupled to integrations.
    if (this.config.eventExport?.enabled === true && this.securityEventExporters.length > 0) {
      for (const exporter of this.securityEventExporters) {
        Promise.resolve()
          .then(() => exporter(envelope))
          .catch((error) => {
            this.logger.log('error', `Security event exporter failed: ${error.message}`);
          });
      }
    }
  }

  setSecurityEventExporters(exporters) {
    this.securityEventExporters = Array.isArray(exporters) ? exporters.filter(Boolean) : [];
  }

  setRateLimitStore(store) {
    this.rateLimiter.setStore(store);
  }

  setReplayStore(store) {
    this.webhookProtection.setReplayStore(store);
  }

  rawBodySaver() {
    return (req, res, buffer) => {
      if (buffer && buffer.length) {
        req.rawBody = Buffer.from(buffer);
      }
    };
  }

  inspectBody() {
    return (req, res, next) => {
      try {
        const parsedBodyConfig = this.config.security?.parsedBodyInspection;
        if (!parsedBodyConfig || parsedBodyConfig.enabled !== true) {
          return next();
        }

        const clientIP = this.ipUtils.getClientIP(req);
        if (!clientIP) {
          this.headerManager.applySecurityHeaders(res, req);
          this.sendErrorResponse(res, 'invalidIP');
          return;
        }

        // Body inspection runs after parsing so JSON and form payloads can still be scanned.
        if (this.security.inspectParsedBody(req.body, clientIP)) {
          this.metrics.requestsBlocked += 1;
          this.metrics.blocksByReason.suspiciousRequest =
            (this.metrics.blocksByReason.suspiciousRequest || 0) + 1;
          this.headerManager.applySecurityHeaders(res, req);
          this.sendErrorResponse(res, 'suspiciousRequest');
          return;
        }

        next();
      } catch (error) {
        this.logger.log('error', 'Unexpected error in inspectBody middleware', {
          error: error.message
        });
        this.sendErrorResponse(res, 'internalError', {
          message: 'An unexpected error occurred'
        });
      }
    };
  }

  protect() {
    return async (req, res, next) => {
      const startTime = Date.now();

      try {
        const clientIP = this.ipUtils.getClientIP(req);
        if (!clientIP) {
          this.logger.log('warning', 'Invalid IP address detected', { ip: req.ip });
          this.sendErrorResponse(res, 'invalidIP');
          return;
        }

        // Resolve the route profile once and reuse it across headers, CSRF, and scanning.
        req.k9shieldProfile = this.resolveRouteProfile(req);
        this.security.attachStreamingProtection(req, res, clientIP, (reason, data) => {
          if (!res.headersSent) {
            this.metrics.requestsBlocked += 1;
            this.metrics.blocksByReason[reason] = (this.metrics.blocksByReason[reason] || 0) + 1;
            this.headerManager.applySecurityHeaders(res, req);
            this.emitSecurityEvent('blocked', { ip: clientIP, reason, path: req.path, data });
            this.sendErrorResponse(res, reason, data);
          }
        });

        const context = {
          req,
          res,
          ip: clientIP,
          profile: req.k9shieldProfile,
          k9shield: this
        };

        // The policy engine returns the first terminal decision in priority order.
        const result = await this.policyEngine.evaluate(context);

        if (result.decision === 'ALLOW_BYPASS') {
          this.metrics.requestsAllowed += 1;
          this.recordDecision(req, clientIP, result, context, Date.now() - startTime);
          this.emitSecurityEvent('allowed_bypass', { ip: clientIP, path: req.path }, context);
          return next();
        }

        if (
          (result.decision === 'BLOCK' || result.decision === 'THROTTLE') &&
          this.shouldShadowDecision(result, req, context)
        ) {
          // Shadow mode preserves full decision visibility without enforcing the block.
          this.metrics.requestsShadowed += 1;
          res.setHeader('X-K9Shield-Shadow-Decision', `${result.decision}:${result.reason}`);
          this.recordDecision(
            req,
            clientIP,
            { decision: 'ALLOW', reason: `shadow:${result.reason}` },
            context,
            Date.now() - startTime
          );
          this.emitSecurityEvent(
            'shadowed',
            { ip: clientIP, reason: result.reason, path: req.path, originalDecision: result.decision },
            context
          );
          this.headerManager.applySecurityHeaders(res, req);
          return next();
        }

        if (result.decision === 'BLOCK') {
          this.metrics.requestsBlocked += 1;
          const reason = result.reason || 'block';
          this.metrics.blocksByReason[reason] = (this.metrics.blocksByReason[reason] || 0) + 1;
          this.recordDecision(req, clientIP, result, context, Date.now() - startTime);
          this.emitSecurityEvent(
            'blocked',
            { ip: clientIP, reason, path: req.path, data: result.data },
            context
          );
          this.headerManager.applySecurityHeaders(res, req);
          this.sendErrorResponse(res, result.reason, result.data);
          return;
        }

        if (result.decision === 'THROTTLE') {
          this.metrics.requestsThrottled += 1;
          this.recordDecision(req, clientIP, result, context, Date.now() - startTime);
          this.emitSecurityEvent(
            'throttled',
            { ip: clientIP, reason: result.reason, path: req.path, data: result.data },
            context
          );
          this.headerManager.applySecurityHeaders(res, req);
          this.sendErrorResponse(res, result.reason, result.data);
          return;
        }

        this.metrics.requestsAllowed += 1;
        this.recordDecision(req, clientIP, result, context, Date.now() - startTime);
        this.headerManager.applySecurityHeaders(res, req);

        this.logger.log('debug', 'Request processed', {
          ip: clientIP,
          path: req.path,
          method: req.method,
          duration: Date.now() - startTime
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
        return matchesRoutePattern(path, route);
      } catch (error) {
        this.logger.log('error', 'Error in bypass route check', {
          error: error.message
        });
        return false;
      }
    });
  }

  payloadTooLargeHandler() {
    return (err, req, res, next) => {
      const isPayloadTooLarge =
        (err && err.type === 'entity.too.large') || (err && err.status === 413);
      if (isPayloadTooLarge) {
        req.k9shieldProfile = req.k9shieldProfile || this.resolveRouteProfile(req);
        this.headerManager.applySecurityHeaders(res, req);
        this.sendErrorResponse(res, 'payloadTooLarge');
        return;
      }
      next(err);
    };
  }

  sendErrorResponse(res, errorType, additionalData = {}) {
    try {
      const customHandler = this.config.errorHandling.customHandlers[errorType];
      if (customHandler && typeof customHandler === 'function') {
        return customHandler(res, additionalData);
      }

      const errorResponse = this.config.errorHandling.defaultResponses[errorType];
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
        message: 'An unexpected error occurred while processing the error response',
        code: 'internalError',
        timestamp: new Date().toISOString()
      });
    }
  }

  setConfig(config) {
    try {
      const configWithPreset = this.applyPresetConfig(config);
      const newConfig = this.mergeConfig(this.config, configWithPreset);
      this.validator.validateConfig(newConfig);
      this.applyConfig(newConfig);
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
      this.logger.log('error', 'Error blocking IP', { ip, error: error.message });
      throw error;
    }
  }

  unblockIP(ip) {
    try {
      this.security.unblockIP(ip);
      this.logger.log('info', 'IP unblocked successfully', { ip });
    } catch (error) {
      this.logger.log('error', 'Error unblocking IP', { ip, error: error.message });
      throw error;
    }
  }

  whitelistIP(ip) {
    try {
      this.security.whitelistIP(ip);
      this.logger.log('info', 'IP whitelisted successfully', { ip });
    } catch (error) {
      this.logger.log('error', 'Error whitelisting IP', { ip, error: error.message });
      throw error;
    }
  }

  unwhitelistIP(ip) {
    try {
      this.security.unwhitelistIP(ip);
      this.logger.log('info', 'IP removed from whitelist successfully', { ip });
    } catch (error) {
      this.logger.log('error', 'Error removing IP from whitelist', { ip, error: error.message });
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
    return this.logger.getLogs();
  }

  getArchivedLogs() {
    return this.logger.getArchivedLogs();
  }

  generateCsrfToken(subject) {
    return this.security.generateCsrfToken(subject);
  }

  async simulateRequest(requestLike) {
    // Simulation uses an isolated instance so replay tooling never mutates live counters.
    const shadowShield = new K9Shield({
      ...this.config,
      updateCheck: false,
      logging: {
        ...this.config.logging,
        enable: false
      }
    });

    const middleware = shadowShield.protect();
    const req = {
      method: requestLike.method || 'GET',
      path: requestLike.path || '/',
      url: requestLike.url || requestLike.path || '/',
      headers: requestLike.headers || {},
      query: requestLike.query || {},
      params: requestLike.params || {},
      body: requestLike.body || '',
      socket: {
        remoteAddress: requestLike.ip || '8.8.8.8',
        bytesRead: requestLike.bytesRead || 0
      },
      connection: {
        remoteAddress: requestLike.ip || '8.8.8.8'
      },
      ip: requestLike.ip || '8.8.8.8',
      on() {},
      off() {}
    };
    const res = {
      headers: {},
      statusCode: 200,
      body: null,
      headersSent: false,
      setHeader(name, value) {
        this.headers[name] = value;
      },
      get(name) {
        return this.headers[name];
      },
      getHeaders() {
        return this.headers;
      },
      removeHeader(name) {
        delete this.headers[name];
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        this.headersSent = true;
        return this;
      },
      on() {},
      off() {}
    };

    let allowed = false;
    await middleware(req, res, () => {
      allowed = true;
    });

    return {
      allowed,
      statusCode: res.statusCode,
      response: res.body,
      headers: res.headers,
      metrics: shadowShield.getMetrics()
    };
  }

  async replayRequests(requests = []) {
    const results = [];
    for (const requestLike of requests) {
      results.push(await this.simulateRequest(requestLike));
    }
    return results;
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
      this.metrics.requestsShadowed = 0;
      this.metrics.blocksByReason = {};
      this.metrics.rules = {};
      this.metrics.decisionHistory = [];
      this.metrics.securityEvents = [];
      this.metrics.lastReset = Date.now();
      this.logger.log('info', 'K9Shield reset successfully');
    } catch (error) {
      this.logger.log('error', 'Error resetting K9Shield', {
        error: error.message
      });
      throw error;
    }
  }

  getMetrics() {
    return {
      ...this.metrics,
      rules: { ...this.metrics.rules },
      decisionHistory: this.metrics.decisionHistory.slice(),
      securityEvents: this.metrics.securityEvents.slice()
    };
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
