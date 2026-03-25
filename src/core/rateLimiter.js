const CLEANUP_INTERVAL_MS = 10000;
const { describePattern, matchesRoutePattern } = require('../utils/routes');

class RateLimiter {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.requestLimits = new Map();
    this.throttledBuckets = new Map();
    this.bannedIPs = new Map();
    this.rateLimitStore = null;
    this._lastCleanup = Date.now();
  }

  setStore(store) {
    this.rateLimitStore = store;
  }

  async handleRateLimiting(req, res, ip) {
    const now = Date.now();

    const subjectKey = this.getSubjectKey(req, ip);
    const ban = this.bannedIPs.get(subjectKey);
    if (ban && now < ban.blockedUntil) {
      const retryAfter = Math.ceil((ban.blockedUntil - now) / 1000);
      this.setRateLimitHeaders(res, { retryAfter });
      return { error: 'permanentlyBlocked', data: { retryAfter } };
    }
    if (ban) this.bannedIPs.delete(subjectKey);

    const resolved = this.resolveRateLimit(req.path, req.method);
    const rateLimitConfig = resolved.config || this.config.rateLimiting.default;
    const bucketId = resolved.bucketId || '__default__';
    const policyKey = this.createPolicyKey(subjectKey, req.method, bucketId);

    const throttle = this.throttledBuckets.get(policyKey);
    if (throttle && now < throttle.endTime) {
      const retryAfter = Math.ceil((throttle.endTime - now) / 1000);
      this.setRateLimitHeaders(res, { retryAfter });
      return { error: 'rateLimitExceeded', data: { retryAfter } };
    }
    if (throttle) this.throttledBuckets.delete(policyKey);

    if (now - this._lastCleanup > CLEANUP_INTERVAL_MS) {
      this.cleanupOldEntries();
      this._lastCleanup = now;
    }

    if (!this.config.rateLimiting.enabled) {
      return { error: null };
    }

    if (!rateLimitConfig) {
      this.logger.log('warning', 'Rate limit configuration missing', req);
      return { error: null };
    }

    try {
      if (this.rateLimitStore) {
        return await this.handleDistributedRateLimit(
          req,
          res,
          policyKey,
          rateLimitConfig
        );
      }

      return this.handleLocalRateLimit(req, res, subjectKey, policyKey, rateLimitConfig);
    } catch (error) {
      this.logger.log('error', `Rate limiting error: ${error.message}`, req);
      return { error: 'internalError', data: { message: error.message } };
    }
  }

  getSubjectKey(req, ip) {
    const config = this.config.rateLimiting || {};
    if (typeof config.keyGenerator === 'function') {
      const generated = config.keyGenerator({ req, ip });
      if (generated) return String(generated);
    }

    // The limiter can key by IP, identity, tenant, or a fully custom resolver.
    // This makes it usable for B2B APIs where per-IP limits are too blunt.
    const tenantHeader = config.tenantHeader || 'x-tenant-id';
    const tenant = req.headers[tenantHeader];
    const identityHeaders = Array.isArray(config.identityHeaders)
      ? config.identityHeaders
      : ['x-api-key', 'authorization'];
    const identity = identityHeaders
      .map((header) => req.headers[header])
      .find((value) => typeof value === 'string' && value.trim() !== '');

    let base = ip;
    if (config.keyStrategy === 'identity' && identity) {
      base = `identity:${identity}`;
    } else if (config.keyStrategy === 'tenant' && tenant) {
      base = `tenant:${tenant}`;
    }

    if (config.includeTenantInKey && tenant) {
      return `${tenant}:${base}`;
    }

    return base;
  }

  createPolicyKey(subjectKey, method, bucketId) {
    return `${subjectKey}:${method}:${bucketId}`;
  }

  resolveRateLimit(path, method) {
    // Pattern-based rules are checked before literal route rules so teams can define
    // a broad policy once and still keep exact-route overrides for special cases.
    const routePatterns = this.config.rateLimiting.routePatterns;
    if (Array.isArray(routePatterns) && routePatterns.length > 0) {
      for (const route of routePatterns) {
        const pattern = route.pattern;
        const config = route.config || route;
        const methodConfig = config[method] || config.default;
        if (!methodConfig) continue;
        if (matchesRoutePattern(path, pattern)) {
          return {
            config: methodConfig,
            bucketId: `pattern:${describePattern(pattern)}`
          };
        }
      }
    }

    const routeConfig = this.config.rateLimiting.routes || {};
    for (const route of Object.keys(routeConfig)) {
      if (matchesRoutePattern(path, route)) {
        const config = routeConfig[route];
        return {
          config: (config && (config[method] || config.default)) || null,
          bucketId: `route:${route}`
        };
      }
    }

    return {
      config: this.config.rateLimiting.default,
      bucketId: '__default__'
    };
  }

  async handleDistributedRateLimit(req, res, policyKey, rateLimitConfig) {
    try {
      const key = `ratelimit:${policyKey}`;
      const result = await this.rateLimitStore.increment(
        key,
        rateLimitConfig.timeWindow
      );

      if (result.count > rateLimitConfig.maxRequests) {
        const retryAfter = Math.ceil(
          (result.ttl || rateLimitConfig.timeWindow) / 1000
        );

        this.logger.log(
          'ratelimit',
          `Rate limit exceeded for bucket ${policyKey}`,
          req
        );

        this.setRateLimitHeaders(res, {
          limit: rateLimitConfig.maxRequests,
          remaining: 0,
          reset: Math.ceil(Date.now() / 1000) + retryAfter,
          retryAfter
        });

        return {
          error: 'rateLimitExceeded',
          data: {
            retryAfter,
            limit: rateLimitConfig.maxRequests,
            windowMs: rateLimitConfig.timeWindow
          }
        };
      }

      this.setRateLimitHeaders(res, {
        limit: rateLimitConfig.maxRequests,
        remaining: rateLimitConfig.maxRequests - result.count,
        reset:
          Math.ceil(Date.now() / 1000) +
          Math.ceil((result.ttl || rateLimitConfig.timeWindow) / 1000)
      });

      return { error: null };
    } catch (error) {
      this.logger.log(
        'error',
        `Distributed rate limiting error: ${error.message}`,
        req
      );
      return this.handleLocalRateLimit(
        req,
        res,
        policyKey.split(':').slice(0, -2).join(':'),
        policyKey,
        rateLimitConfig
      );
    }
  }

  handleLocalRateLimit(req, res, subjectKey, policyKey, rateLimitConfig) {
    let requestData = this.requestLimits.get(policyKey);
    if (!requestData) {
      requestData = {
        count: 1,
        firstRequest: Date.now(),
        warnings: 0,
        timeWindow: rateLimitConfig.timeWindow,
        lastSeen: Date.now()
      };
      this.requestLimits.set(policyKey, requestData);
      this.setRateLimitHeaders(res, {
        limit: rateLimitConfig.maxRequests,
        remaining: rateLimitConfig.maxRequests - 1,
        reset: Math.ceil((Date.now() + rateLimitConfig.timeWindow) / 1000)
      });
      return { error: null };
    }

    // We store the effective window on each bucket so cleanup cannot accidentally
    // evict long-window policies using only the global default.
    const now = Date.now();
    const timePassed = now - requestData.firstRequest;
    requestData.timeWindow = rateLimitConfig.timeWindow;
    requestData.lastSeen = now;

    if (timePassed > rateLimitConfig.timeWindow) {
      requestData.count = 1;
      requestData.firstRequest = now;
      requestData.lastSeen = now;
      this.requestLimits.set(policyKey, requestData);
      this.setRateLimitHeaders(res, {
        limit: rateLimitConfig.maxRequests,
        remaining: rateLimitConfig.maxRequests - 1,
        reset: Math.ceil((now + rateLimitConfig.timeWindow) / 1000)
      });
      return { error: null };
    }

    requestData.count += 1;

    if (requestData.count > rateLimitConfig.maxRequests) {
      requestData.warnings += 1;
      const retryAfter = Math.ceil(
        (rateLimitConfig.timeWindow - timePassed) / 1000
      );

      if (requestData.warnings >= 3) {
        const banDuration =
          rateLimitConfig.banDuration || this.config.rateLimiting.default.banDuration;
        this.bannedIPs.set(subjectKey, {
          blockedUntil: now + banDuration,
          lastSeen: now
        });
        this.logger.log(
          'banned',
          `Subject ${subjectKey} temporarily banned after multiple violations`,
          req
        );
        return {
          error: 'permanentlyBlocked',
          data: { retryAfter: Math.ceil(banDuration / 1000) }
        };
      }

      this.throttledBuckets.set(policyKey, {
        endTime: now + rateLimitConfig.throttleDuration,
        lastSeen: now
      });

      this.setRateLimitHeaders(res, {
        limit: rateLimitConfig.maxRequests,
        remaining: 0,
        reset: Math.ceil((requestData.firstRequest + rateLimitConfig.timeWindow) / 1000),
        retryAfter
      });

      this.logger.log(
        'ratelimit',
        `Rate limit exceeded for ${subjectKey}, throttling for ${rateLimitConfig.throttleDuration}ms`,
        req
      );
      return {
        error: 'rateLimitExceeded',
        data: { retryAfter }
      };
    }

    this.requestLimits.set(policyKey, requestData);
    this.setRateLimitHeaders(res, {
      limit: rateLimitConfig.maxRequests,
      remaining: Math.max(0, rateLimitConfig.maxRequests - requestData.count),
      reset: Math.ceil((requestData.firstRequest + rateLimitConfig.timeWindow) / 1000)
    });
    return { error: null };
  }

  setRateLimitHeaders(res, options) {
    if (options.limit) {
      res.setHeader('X-RateLimit-Limit', options.limit);
    }
    if (options.remaining !== undefined) {
      res.setHeader('X-RateLimit-Remaining', options.remaining);
    }
    if (options.reset) {
      res.setHeader('X-RateLimit-Reset', options.reset);
    }
    if (options.retryAfter) {
      res.setHeader('Retry-After', options.retryAfter);
    }
  }

  cleanupOldEntries() {
    const now = Date.now();
    for (const [policyKey, data] of this.requestLimits) {
      const timeWindow = data.timeWindow || this.config.rateLimiting.default.timeWindow;
      // Buckets live long enough to preserve route-specific windows correctly.
      if (now - data.firstRequest > timeWindow * 2) {
        this.requestLimits.delete(policyKey);
      }
    }

    for (const [policyKey, data] of this.throttledBuckets) {
      if (now > data.endTime) {
        this.throttledBuckets.delete(policyKey);
      }
    }

    for (const [subjectKey, data] of this.bannedIPs) {
      if (now > data.blockedUntil) {
        this.bannedIPs.delete(subjectKey);
      }
    }
  }

  reset() {
    this.requestLimits.clear();
    this.throttledBuckets.clear();
    this.bannedIPs.clear();
  }
}

module.exports = RateLimiter;
