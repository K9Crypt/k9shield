const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warning: 2,
  blocked: 3,
  attack: 4,
  ratelimit: 5,
  banned: 6,
  manual: 7,
  throttled: 8,
  userAgentBlocked: 9,
  refererBlocked: 10
};

class ConfigValidator {
  constructor(logger) {
    this.logger = logger;
    this.LOG_LEVELS = LOG_LEVELS;
  }

  validateConfig(config) {
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
      throw new Error('Invalid configuration object');
    }

    if (config.mode) this.validateModeConfig(config.mode);
    if (config.security) this.validateSecurityConfig(config.security);
    if (config.logging) this.validateLoggingConfig(config.logging);
    if (config.rateLimiting) this.validateRateLimitingConfig(config.rateLimiting);
    if (config.ddosProtection) this.validateDDoSConfig(config.ddosProtection);
    if (config.errorHandling) this.validateErrorHandlingConfig(config.errorHandling);
    if (config.observability) this.validateObservabilityConfig(config.observability);
    if (config.eventExport) this.validateEventExportConfig(config.eventExport);
  }

  validateModeConfig(mode) {
    if (typeof mode.shadow !== 'boolean') {
      throw new Error('mode.shadow must be boolean');
    }

    if (mode.shadowRules !== undefined && !Array.isArray(mode.shadowRules)) {
      throw new Error('mode.shadowRules must be an array');
    }
  }

  validateSecurityConfig(security) {
    if (typeof security.trustProxy !== 'boolean') {
      throw new Error('security.trustProxy must be boolean');
    }

    if (
      security.securityHeaders &&
      (typeof security.securityHeaders !== 'object' || Array.isArray(security.securityHeaders))
    ) {
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

    for (const key of [
      'trustedProxies',
      'userAgentBlacklist',
      'refererBlacklist',
      'routeProfiles'
    ]) {
      if (security[key] !== undefined && !Array.isArray(security[key])) {
        throw new Error(`security.${key} must be an array`);
      }
    }

    if (
      security.checkStringMaxLength !== undefined &&
      (!Number.isInteger(security.checkStringMaxLength) || security.checkStringMaxLength <= 0)
    ) {
      throw new Error('security.checkStringMaxLength must be a positive integer');
    }

    this.validateProfilesConfig(security);
    this.validateFastInspectionConfig(security.fastInspection);
    this.validateStreamingProtectionConfig(security.streamingProtection);
    this.validateBotProtectionConfig(security.botProtection);
    this.validateReputationConfig(security.reputation);
    this.validateParsedBodyInspectionConfig(security.parsedBodyInspection);
    this.validateWebhookProtectionConfig(security.webhookProtection);
    this.validateCsrfConfig(security.csrfProtection);
  }

  validateProfilesConfig(security) {
    if (
      security.profiles !== undefined &&
      (typeof security.profiles !== 'object' || Array.isArray(security.profiles))
    ) {
      throw new Error('security.profiles must be an object');
    }

    if (!Array.isArray(security.routeProfiles)) return;

    for (const profile of security.routeProfiles) {
      if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
        throw new Error('security.routeProfiles entries must be objects');
      }
      if (!profile.profile || typeof profile.profile !== 'string') {
        throw new Error('security.routeProfiles.profile must be a string');
      }
      if (
        profile.pattern === undefined ||
        !(
          typeof profile.pattern === 'string' ||
          profile.pattern instanceof RegExp ||
          typeof profile.pattern === 'function'
        )
      ) {
        throw new Error('security.routeProfiles.pattern must be a string, RegExp, or function');
      }
    }
  }

  validateFastInspectionConfig(config) {
    if (!config) return;
    if (typeof config.enabled !== 'boolean') {
      throw new Error('security.fastInspection.enabled must be boolean');
    }

    for (const key of ['deepInspectMethods', 'deepInspectContentTypes']) {
      if (config[key] !== undefined && !Array.isArray(config[key])) {
        throw new Error(`security.fastInspection.${key} must be an array`);
      }
    }
  }

  validateStreamingProtectionConfig(config) {
    if (!config) return;
    if (typeof config.enabled !== 'boolean') {
      throw new Error('security.streamingProtection.enabled must be boolean');
    }

    for (const key of ['maxChunkCount', 'minBytesPerSecond', 'gracePeriodMs', 'checkIntervalMs']) {
      if (
        config[key] !== undefined &&
        config[key] !== null &&
        (!Number.isInteger(config[key]) || config[key] <= 0)
      ) {
        throw new Error(`security.streamingProtection.${key} must be a positive integer`);
      }
    }

    if (config.maxBodySize !== undefined && config.maxBodySize !== null) {
      if (!Number.isInteger(config.maxBodySize) || config.maxBodySize <= 0) {
        throw new Error('security.streamingProtection.maxBodySize must be a positive integer');
      }
    }

    if (config.applyToMethods !== undefined && !Array.isArray(config.applyToMethods)) {
      throw new Error('security.streamingProtection.applyToMethods must be an array');
    }
  }

  validateBotProtectionConfig(config) {
    if (!config) return;
    if (typeof config.enabled !== 'boolean') {
      throw new Error('security.botProtection.enabled must be boolean');
    }

    for (const key of ['knownBadUserAgents', 'allowListedUserAgents']) {
      if (config[key] !== undefined && !Array.isArray(config[key])) {
        throw new Error(`security.botProtection.${key} must be an array`);
      }
    }

    for (const key of ['emptyUserAgentScore', 'automationHeaderScore', 'blockThreshold', 'throttleThreshold']) {
      if (config[key] !== undefined && (!Number.isInteger(config[key]) || config[key] < 0)) {
        throw new Error(`security.botProtection.${key} must be a non-negative integer`);
      }
    }
  }

  validateReputationConfig(config) {
    if (!config) return;
    if (typeof config.enabled !== 'boolean') {
      throw new Error('security.reputation.enabled must be boolean');
    }

    for (const key of ['ttl', 'throttleThreshold', 'blockThreshold']) {
      if (config[key] !== undefined && (!Number.isInteger(config[key]) || config[key] <= 0)) {
        throw new Error(`security.reputation.${key} must be a positive integer`);
      }
    }

    if (config.resolver !== undefined && config.resolver !== null && typeof config.resolver !== 'function') {
      throw new Error('security.reputation.resolver must be a function');
    }
  }

  validateParsedBodyInspectionConfig(config) {
    if (!config) return;
    if (typeof config.enabled !== 'boolean') {
      throw new Error('security.parsedBodyInspection.enabled must be boolean');
    }

    if (
      config.maxBodyScanSize !== undefined &&
      (!Number.isInteger(config.maxBodyScanSize) || config.maxBodyScanSize <= 0)
    ) {
      throw new Error('security.parsedBodyInspection.maxBodyScanSize must be a positive integer');
    }
  }

  validateWebhookProtectionConfig(config) {
    if (!config) return;
    if (typeof config.enabled !== 'boolean') {
      throw new Error('security.webhookProtection.enabled must be boolean');
    }

    if (typeof config.requireRawBody !== 'boolean') {
      throw new Error('security.webhookProtection.requireRawBody must be boolean');
    }

    for (const key of ['toleranceSeconds', 'replayWindowMs']) {
      if (config[key] !== undefined && (!Number.isInteger(config[key]) || config[key] <= 0)) {
        throw new Error(`security.webhookProtection.${key} must be a positive integer`);
      }
    }

    if (config.routes !== undefined && !Array.isArray(config.routes)) {
      throw new Error('security.webhookProtection.routes must be an array');
    }

    if (!Array.isArray(config.routes)) return;

    for (const route of config.routes) {
      if (!route || typeof route !== 'object' || Array.isArray(route)) {
        throw new Error('security.webhookProtection.routes entries must be objects');
      }

      if (
        route.path === undefined &&
        route.pattern === undefined
      ) {
        throw new Error('security.webhookProtection.routes entries must define path or pattern');
      }

      if (route.provider !== undefined && typeof route.provider !== 'string') {
        throw new Error('security.webhookProtection.routes.provider must be a string');
      }

      if (route.secret !== undefined && typeof route.secret !== 'string') {
        throw new Error('security.webhookProtection.routes.secret must be a string');
      }
    }
  }

  validateCsrfConfig(csrf) {
    if (csrf === undefined) return;
    if (typeof csrf !== 'object' || Array.isArray(csrf)) {
      throw new Error('security.csrfProtection must be an object');
    }

    if (csrf.originWhitelist !== undefined) {
      if (!Array.isArray(csrf.originWhitelist)) {
        throw new Error('security.csrfProtection.originWhitelist must be an array');
      }
      csrf.originWhitelist.forEach((origin) => {
        try {
          const parsed = new URL(origin);
          if (!parsed.protocol || !parsed.host) {
            throw new Error('invalid');
          }
        } catch (error) {
          throw new Error(`Invalid CSRF origin whitelist entry: ${origin}`);
        }
      });
    }

    if (
      csrf.tokenMode !== undefined &&
      !['off', 'double-submit'].includes(csrf.tokenMode)
    ) {
      throw new Error('security.csrfProtection.tokenMode must be "off" or "double-submit"');
    }

    if (csrf.secret !== undefined && csrf.secret !== null && typeof csrf.secret !== 'string') {
      throw new Error('security.csrfProtection.secret must be a string');
    }

    for (const key of ['cookieName', 'headerName']) {
      if (csrf[key] !== undefined && typeof csrf[key] !== 'string') {
        throw new Error(`security.csrfProtection.${key} must be a string`);
      }
    }

    if (
      csrf.tokenMaxAgeMs !== undefined &&
      (!Number.isInteger(csrf.tokenMaxAgeMs) || csrf.tokenMaxAgeMs <= 0)
    ) {
      throw new Error('security.csrfProtection.tokenMaxAgeMs must be a positive integer');
    }
  }

  validateLoggingConfig(logging) {
    if (typeof logging.enable !== 'boolean') {
      throw new Error('logging.enable must be boolean');
    }

    if (!(logging.level in this.LOG_LEVELS)) {
      throw new Error(`Invalid log level: ${logging.level}`);
    }

    if (!Number.isInteger(logging.maxLogSize) || logging.maxLogSize <= 0) {
      throw new Error('logging.maxLogSize must be a positive integer');
    }

    if (!Number.isInteger(logging.archiveLimit) || logging.archiveLimit <= 0) {
      throw new Error('logging.archiveLimit must be a positive integer');
    }

    if (logging.sampling !== undefined) {
      if (typeof logging.sampling !== 'object' || Array.isArray(logging.sampling)) {
        throw new Error('logging.sampling must be an object');
      }
      if (typeof logging.sampling.enabled !== 'boolean') {
        throw new Error('logging.sampling.enabled must be boolean');
      }
      for (const key of ['windowMs', 'maxEntriesPerInterval']) {
        if (
          logging.sampling[key] !== undefined &&
          (!Number.isInteger(logging.sampling[key]) || logging.sampling[key] <= 0)
        ) {
          throw new Error(`logging.sampling.${key} must be a positive integer`);
        }
      }
    }
  }

  validateRateLimitingConfig(rateLimiting) {
    if (typeof rateLimiting.enabled !== 'boolean') {
      throw new Error('rateLimiting.enabled must be boolean');
    }

    if (
      rateLimiting.keyStrategy !== undefined &&
      !['ip', 'identity', 'tenant'].includes(rateLimiting.keyStrategy)
    ) {
      throw new Error('rateLimiting.keyStrategy must be "ip", "identity", or "tenant"');
    }

    if (
      rateLimiting.keyGenerator !== undefined &&
      rateLimiting.keyGenerator !== null &&
      typeof rateLimiting.keyGenerator !== 'function'
    ) {
      throw new Error('rateLimiting.keyGenerator must be a function');
    }

    for (const key of ['identityHeaders']) {
      if (rateLimiting[key] !== undefined && !Array.isArray(rateLimiting[key])) {
        throw new Error(`rateLimiting.${key} must be an array`);
      }
    }

    if (rateLimiting.tenantHeader !== undefined && typeof rateLimiting.tenantHeader !== 'string') {
      throw new Error('rateLimiting.tenantHeader must be a string');
    }

    if (
      rateLimiting.includeTenantInKey !== undefined &&
      typeof rateLimiting.includeTenantInKey !== 'boolean'
    ) {
      throw new Error('rateLimiting.includeTenantInKey must be boolean');
    }

    if (rateLimiting.default) {
      this.validateRateLimitConfig(rateLimiting.default);
    }

    if (rateLimiting.routes) {
      if (typeof rateLimiting.routes !== 'object' || Array.isArray(rateLimiting.routes)) {
        throw new Error('rateLimiting.routes must be an object');
      }

      Object.values(rateLimiting.routes).forEach((route) => {
        if (route && typeof route === 'object') {
          Object.values(route).forEach((config) => {
            if (config) this.validateRateLimitConfig(config);
          });
        }
      });
    }

    if (rateLimiting.routePatterns !== undefined && !Array.isArray(rateLimiting.routePatterns)) {
      throw new Error('rateLimiting.routePatterns must be an array');
    }
  }

  validateDDoSConfig(ddosConfig) {
    if (typeof ddosConfig.enabled !== 'boolean') {
      throw new Error('ddosProtection.enabled must be boolean');
    }

    if (typeof ddosConfig.config !== 'object' || Array.isArray(ddosConfig.config)) {
      throw new Error('ddosProtection.config must be an object');
    }

    const requiredFields = [
      'maxConnections',
      'timeWindow',
      'blockDuration',
      'requestThreshold',
      'burstThreshold',
      'slowRequestThreshold'
    ];

    requiredFields.forEach((field) => {
      if (
        !Number.isInteger(ddosConfig.config[field]) ||
        ddosConfig.config[field] <= 0
      ) {
        throw new Error(
          `ddosProtection.config.${field} must be a positive integer`
        );
      }
    });

    if (
      typeof ddosConfig.config.rateLimitByPath !== 'object' ||
      Array.isArray(ddosConfig.config.rateLimitByPath)
    ) {
      throw new Error(
        'ddosProtection.config.rateLimitByPath must be an object'
      );
    }
  }

  validateErrorHandlingConfig(errorHandling) {
    if (typeof errorHandling.customHandlers !== 'object' || Array.isArray(errorHandling.customHandlers)) {
      throw new Error('errorHandling.customHandlers must be an object');
    }

    if (
      typeof errorHandling.defaultResponses !== 'object' ||
      Array.isArray(errorHandling.defaultResponses)
    ) {
      throw new Error('errorHandling.defaultResponses must be an object');
    }

    Object.values(errorHandling.defaultResponses).forEach((response) => {
      if (!response.status || !response.message) {
        throw new Error(
          'Each error response must have status and message properties'
        );
      }
      if (
        !Number.isInteger(response.status) ||
        response.status < 100 ||
        response.status > 599
      ) {
        throw new Error(
          'Error response status must be a valid HTTP status code'
        );
      }
    });
  }

  validateObservabilityConfig(observability) {
    if (typeof observability.enabled !== 'boolean') {
      throw new Error('observability.enabled must be boolean');
    }

    for (const key of ['maxDecisionHistory', 'maxEventHistory']) {
      if (
        observability[key] !== undefined &&
        (!Number.isInteger(observability[key]) || observability[key] <= 0)
      ) {
        throw new Error(`observability.${key} must be a positive integer`);
      }
    }
  }

  validateEventExportConfig(eventExport) {
    if (typeof eventExport.enabled !== 'boolean') {
      throw new Error('eventExport.enabled must be boolean');
    }

    if (
      eventExport.signingKey !== undefined &&
      eventExport.signingKey !== null &&
      typeof eventExport.signingKey !== 'string'
    ) {
      throw new Error('eventExport.signingKey must be a string');
    }

    if (
      eventExport.includeDecisionTrace !== undefined &&
      typeof eventExport.includeDecisionTrace !== 'boolean'
    ) {
      throw new Error('eventExport.includeDecisionTrace must be boolean');
    }
  }

  validateRateLimitConfig(config) {
    const requiredFields = ['maxRequests', 'timeWindow', 'retryAfter', 'throttleDuration'];
    requiredFields.forEach((field) => {
      if (!Number.isInteger(config[field]) || config[field] <= 0) {
        throw new Error(`Rate limit ${field} must be a positive integer`);
      }
    });

    if (
      config.banDuration !== undefined &&
      (!Number.isInteger(config.banDuration) || config.banDuration <= 0)
    ) {
      throw new Error('Rate limit banDuration must be a positive integer');
    }

    if (
      config.throttleDelay !== undefined &&
      (!Number.isInteger(config.throttleDelay) || config.throttleDelay <= 0)
    ) {
      throw new Error('Rate limit throttleDelay must be a positive integer');
    }
  }
}

module.exports = ConfigValidator;
