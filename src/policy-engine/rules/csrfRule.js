const Rule = require('../Rule');

const STATE_CHANGING_METHODS = ['POST', 'PUT', 'DELETE', 'PATCH'];

function createCsrfRule(k9shield) {
  return new Rule({
    name: 'CsrfRule',
    priority: 75,
    condition: async (context) => {
      const { req } = context;
      const csrf = k9shield.config.security?.csrfProtection;
      if (!csrf || !csrf.enabled) return false;
      if (!STATE_CHANGING_METHODS.includes(req.method)) return false;

      const origin = req.headers.origin;
      const referer = req.headers.referer;
      const host = req.headers.host || '';

      const whitelist = Array.isArray(csrf.originWhitelist) ? csrf.originWhitelist : [];
      const allowedOrigins = new Set(whitelist.map((o) => o.toLowerCase().replace(/\/$/, '')));

      const baseUrl = host ? `https://${host}` : '';
      if (baseUrl) allowedOrigins.add(baseUrl.toLowerCase());
      allowedOrigins.add(`http://${host}`.toLowerCase());

      if (origin) {
        const o = origin.toLowerCase().replace(/\/$/, '');
        if (!allowedOrigins.has(o)) {
          context.csrfDecision = { decision: 'BLOCK', reason: 'csrfOriginMismatch' };
          return true;
        }
        return false;
      }

      if (referer) {
        try {
          const refUrl = new URL(referer);
          const refOrigin = `${refUrl.protocol}//${refUrl.host}`.toLowerCase();
          if (!allowedOrigins.has(refOrigin)) {
            context.csrfDecision = { decision: 'BLOCK', reason: 'csrfRefererMismatch' };
            return true;
          }
        } catch (e) {
          context.csrfDecision = { decision: 'BLOCK', reason: 'csrfInvalidReferer' };
          return true;
        }
        return false;
      }

      if (csrf.requireOriginOrReferer === true) {
        context.csrfDecision = { decision: 'BLOCK', reason: 'csrfMissingOriginOrReferer' };
        return true;
      }

      return false;
    },
    action: (context) => context.csrfDecision
  });
}

module.exports = createCsrfRule;
