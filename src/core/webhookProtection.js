const crypto = require('crypto');
const { describePattern, matchesRoutePattern } = require('../utils/routes');
const { safeCompare, toBuffer } = require('../utils/http');

class WebhookProtection {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.replayStore = null;
    this.replayCache = new Map();
  }

  setReplayStore(store) {
    this.replayStore = store;
  }

  getConfig() {
    return this.config?.security?.webhookProtection || {};
  }

  resolveRoute(req) {
    const webhookConfig = this.getConfig();
    if (!webhookConfig.enabled) return null;

    // Webhook routes are configured explicitly so verification never "guesses"
    // which secret or provider format should apply to a request.
    const routes = Array.isArray(webhookConfig.routes) ? webhookConfig.routes : [];
    for (const route of routes) {
      if (matchesRoutePattern(req.path, route.pattern || route.path)) {
        return {
          ...route,
          profile: route.profile || 'webhook'
        };
      }
    }

    return null;
  }

  getRawPayload(req, routeConfig) {
    if (Buffer.isBuffer(req.rawBody)) return req.rawBody;
    if (typeof req.rawBody === 'string') return Buffer.from(req.rawBody);

    // Some teams may choose to verify against parsed content, but raw bytes remain
    // the safest default because most providers sign the exact original payload.
    const webhookConfig = this.getConfig();
    if (webhookConfig.requireRawBody !== false) {
      return null;
    }

    if (typeof req.body === 'string' || Buffer.isBuffer(req.body)) {
      return toBuffer(req.body);
    }

    return toBuffer(req.body || '');
  }

  parseStripeSignature(headerValue) {
    const parts = String(headerValue || '')
      .split(',')
      .map((segment) => segment.trim())
      .filter(Boolean);

    return parts.reduce((accumulator, segment) => {
      const [key, value] = segment.split('=');
      if (key && value) accumulator[key] = value;
      return accumulator;
    }, {});
  }

  createHmac(secret, value, algorithm = 'sha256') {
    return crypto.createHmac(algorithm, secret).update(value).digest('hex');
  }

  verifyGeneric(routeConfig, req, rawPayload) {
    const headerName = String(routeConfig.signatureHeader || 'x-k9shield-signature').toLowerCase();
    const signature = req.headers[headerName];
    if (!signature) {
      return { ok: false, reason: 'webhookMissingSignature' };
    }

    const expected = this.createHmac(routeConfig.secret, rawPayload, routeConfig.algorithm || 'sha256');
    const normalizedSignature = String(signature).replace(/^sha256=/i, '');
    if (!safeCompare(expected, normalizedSignature)) {
      return { ok: false, reason: 'webhookInvalidSignature' };
    }

    return { ok: true };
  }

  verifyGithub(routeConfig, req, rawPayload) {
    const signature = req.headers['x-hub-signature-256'];
    if (!signature) {
      return { ok: false, reason: 'webhookMissingSignature' };
    }

    const expected = `sha256=${this.createHmac(routeConfig.secret, rawPayload, 'sha256')}`;
    if (!safeCompare(expected, signature)) {
      return { ok: false, reason: 'webhookInvalidSignature' };
    }

    return { ok: true, replayKey: req.headers['x-github-delivery'] || signature };
  }

  verifyStripe(routeConfig, req, rawPayload) {
    const headerValue = req.headers['stripe-signature'];
    if (!headerValue) {
      return { ok: false, reason: 'webhookMissingSignature' };
    }

    const parsed = this.parseStripeSignature(headerValue);
    const timestamp = Number.parseInt(parsed.t, 10);
    const signature = parsed.v1;
    if (!Number.isFinite(timestamp) || !signature) {
      return { ok: false, reason: 'webhookInvalidSignature' };
    }

    const toleranceSeconds =
      routeConfig.toleranceSeconds || this.getConfig().toleranceSeconds || 300;
    if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > toleranceSeconds) {
      return { ok: false, reason: 'webhookTimestampExpired' };
    }

    const signedPayload = `${timestamp}.${rawPayload.toString('utf8')}`;
    const expected = this.createHmac(routeConfig.secret, signedPayload, 'sha256');
    if (!safeCompare(expected, signature)) {
      return { ok: false, reason: 'webhookInvalidSignature' };
    }

    return { ok: true, replayKey: `${timestamp}:${signature}` };
  }

  verifySlack(routeConfig, req, rawPayload) {
    const timestampHeader = req.headers['x-slack-request-timestamp'];
    const signature = req.headers['x-slack-signature'];
    const timestamp = Number.parseInt(timestampHeader, 10);
    if (!Number.isFinite(timestamp) || !signature) {
      return { ok: false, reason: 'webhookMissingSignature' };
    }

    const toleranceSeconds =
      routeConfig.toleranceSeconds || this.getConfig().toleranceSeconds || 300;
    if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > toleranceSeconds) {
      return { ok: false, reason: 'webhookTimestampExpired' };
    }

    const base = `v0:${timestamp}:${rawPayload.toString('utf8')}`;
    const expected = `v0=${this.createHmac(routeConfig.secret, base, 'sha256')}`;
    if (!safeCompare(expected, signature)) {
      return { ok: false, reason: 'webhookInvalidSignature' };
    }

    return { ok: true, replayKey: `${timestamp}:${signature}` };
  }

  async isReplay(routeConfig, replayKey) {
    if (!replayKey) return false;

    const replayWindowMs =
      routeConfig.replayWindowMs || this.getConfig().replayWindowMs || 5 * 60 * 1000;

    // Replay protection can use an injected shared store, but falls back to a bounded
    // in-memory cache for single-process deployments.
    if (this.replayStore) {
      const alreadySeen = await this.replayStore.has(replayKey);
      if (alreadySeen) return true;
      await this.replayStore.set(replayKey, replayWindowMs);
      return false;
    }

    const existingExpiry = this.replayCache.get(replayKey);
    const now = Date.now();
    if (existingExpiry && existingExpiry > now) {
      return true;
    }

    this.replayCache.set(replayKey, now + replayWindowMs);
    this.cleanupReplayCache(now);
    return false;
  }

  cleanupReplayCache(now = Date.now()) {
    for (const [key, expiry] of this.replayCache.entries()) {
      if (expiry <= now) this.replayCache.delete(key);
    }
  }

  async verifyRequest(req) {
    const routeConfig = this.resolveRoute(req);
    if (!routeConfig) return { ok: true, routeConfig: null };

    const secret = routeConfig.secret || this.getConfig().defaultSecret;
    if (!secret) {
      this.logger.log(
        'warning',
        `Webhook route ${describePattern(routeConfig.pattern || routeConfig.path)} missing secret`
      );
      return { ok: false, reason: 'webhookMisconfigured' };
    }

    const rawPayload = this.getRawPayload(req, routeConfig);
    if (!rawPayload || rawPayload.length === 0) {
      return { ok: false, reason: 'webhookMissingRawBody' };
    }

    // Verification is provider-aware so each signature format is handled exactly once.
    let result;
    switch ((routeConfig.provider || 'generic').toLowerCase()) {
      case 'github':
        result = this.verifyGithub({ ...routeConfig, secret }, req, rawPayload);
        break;
      case 'stripe':
        result = this.verifyStripe({ ...routeConfig, secret }, req, rawPayload);
        break;
      case 'slack':
        result = this.verifySlack({ ...routeConfig, secret }, req, rawPayload);
        break;
      default:
        result = this.verifyGeneric({ ...routeConfig, secret }, req, rawPayload);
        break;
    }

    if (!result.ok) return { ...result, routeConfig };

    if (await this.isReplay(routeConfig, result.replayKey)) {
      return {
        ok: false,
        reason: 'webhookReplayDetected',
        routeConfig
      };
    }

    return { ok: true, routeConfig };
  }
}

module.exports = WebhookProtection;
