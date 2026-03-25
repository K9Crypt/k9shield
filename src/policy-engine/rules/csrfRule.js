const Rule = require('../Rule');

const STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH'];

function normalizeOrigin(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.host}`.replace(/\/$/, '').toLowerCase();
  } catch (error) {
    return null;
  }
}

function createCsrfRule(k9shield) {
  return new Rule({
    name: 'CsrfRule',
    priority: 75,
    condition: async (context) => {
      const { req } = context;
      const profile = req.k9shieldProfile || {};
      const csrf = k9shield.config.security?.csrfProtection;
      if (!csrf || !csrf.enabled) return false;
      if (profile.skipCsrf === true) return false;
      if (!STATE_CHANGING_METHODS.includes(req.method)) return false;

      const origin = req.headers.origin;
      const referer = req.headers.referer;

      const whitelist = Array.isArray(csrf.originWhitelist) ? csrf.originWhitelist : [];
      const allowedOrigins = new Set(
        whitelist.map((entry) => normalizeOrigin(entry)).filter(Boolean)
      );
      let trustedSourcePresent = false;

      if (origin) {
        const normalizedOrigin = normalizeOrigin(origin);
        if (!normalizedOrigin || !allowedOrigins.has(normalizedOrigin)) {
          context.csrfDecision = { decision: 'BLOCK', reason: 'csrfOriginMismatch' };
          return true;
        }
        trustedSourcePresent = true;
      }

      if (!trustedSourcePresent && referer) {
        const normalizedReferer = normalizeOrigin(referer);
        if (!normalizedReferer) {
          context.csrfDecision = { decision: 'BLOCK', reason: 'csrfInvalidReferer' };
          return true;
        }
        if (!allowedOrigins.has(normalizedReferer)) {
          context.csrfDecision = { decision: 'BLOCK', reason: 'csrfRefererMismatch' };
          return true;
        }
        trustedSourcePresent = true;
      }

      if (csrf.tokenMode === 'double-submit') {
        const tokenDecision = k9shield.security.validateCsrfDoubleSubmit(req);
        if (tokenDecision) {
          context.csrfDecision = tokenDecision;
          return true;
        }
      }

      if (csrf.requireOriginOrReferer === true && !trustedSourcePresent) {
        context.csrfDecision = { decision: 'BLOCK', reason: 'csrfMissingOriginOrReferer' };
        return true;
      }

      return false;
    },
    action: (context) => context.csrfDecision
  });
}

module.exports = createCsrfRule;
