class RateLimiter {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.requestLimits = new Map();
    this.throttledIPs = new Map();
    this.rateLimitStore = null;
  }

  async handleRateLimiting(req, res, ip) {
    this.cleanupOldEntries();
    if (!this.config.rateLimiting.enabled) {
      return { error: null };
    }

    const routeRateLimit = this.getRouteRateLimit(req.path, req.method);
    const rateLimitConfig = routeRateLimit || this.config.rateLimiting.default;

    if (!rateLimitConfig) {
      this.logger.log('warning', 'Rate limit configuration missing', req);
      return { error: null };
    }

    try {
      if (this.rateLimitStore) {
        return await this.handleDistributedRateLimit(
          req,
          res,
          ip,
          rateLimitConfig
        );
      } else {
        return this.handleLocalRateLimit(req, res, ip, rateLimitConfig);
      }
    } catch (error) {
      this.logger.log('error', `Rate limiting error: ${error.message}`, req);
      return { error: 'internalError', data: { message: error.message } };
    }
  }

  async handleDistributedRateLimit(req, res, ip, rateLimitConfig) {
    try {
      const key = `ratelimit:${ip}:${req.path}`;
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
          `Rate limit exceeded for IP ${ip} on path ${req.path}`,
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
      return this.handleLocalRateLimit(req, res, ip, rateLimitConfig);
    }
  }

  handleLocalRateLimit(req, res, ip, rateLimitConfig) {
    if (!this.requestLimits.has(ip)) {
      this.requestLimits.set(ip, {
        count: 1,
        firstRequest: Date.now(),
        warnings: 0
      });
      return { error: null };
    }

    const requestData = this.requestLimits.get(ip);
    const timePassed = Date.now() - requestData.firstRequest;

    if (timePassed > rateLimitConfig.timeWindow) {
      requestData.count = 1;
      requestData.firstRequest = Date.now();
      this.requestLimits.set(ip, requestData);
      return { error: null };
    }

    requestData.count++;

    if (requestData.count > rateLimitConfig.maxRequests) {
      requestData.warnings++;
      const retryAfter = Math.ceil(
        (rateLimitConfig.timeWindow - timePassed) / 1000
      );

      if (requestData.warnings >= 3) {
        this.logger.log(
          'banned',
          `IP ${ip} permanently banned after multiple violations`,
          req
        );
        return {
          error: 'permanentlyBlocked'
        };
      }

      this.throttledIPs.set(ip, {
        endTime: Date.now() + rateLimitConfig.throttleDuration
      });

      this.setRateLimitHeaders(res, {
        retryAfter
      });

      this.logger.log(
        'ratelimit',
        `Rate limit exceeded for IP ${ip}, throttling for ${rateLimitConfig.throttleDuration}ms`,
        req
      );
      return {
        error: 'rateLimitExceeded',
        data: { retryAfter }
      };
    }

    this.requestLimits.set(ip, requestData);
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

  getRouteRateLimit(path, method) {
    const routeConfig = this.config.rateLimiting.routes;
    for (const route in routeConfig) {
      if (typeof route === 'string' && path === route) {
        return routeConfig[route][method] || routeConfig[route]['default'];
      } else if (route instanceof RegExp && route.test(path)) {
        return routeConfig[route][method] || routeConfig[route]['default'];
      }
    }
    return null;
  }

  cleanupOldEntries() {
    const now = Date.now();
    for (const [ip, data] of this.requestLimits) {
      if (
        now - data.firstRequest >
        this.config.rateLimiting.default.timeWindow * 2
      ) {
        this.requestLimits.delete(ip);
      }
    }

    for (const [ip, data] of this.throttledIPs) {
      if (now > data.endTime) {
        this.throttledIPs.delete(ip);
      }
    }
  }

  reset() {
    this.requestLimits.clear();
    this.throttledIPs.clear();
  }
}

module.exports = RateLimiter;
