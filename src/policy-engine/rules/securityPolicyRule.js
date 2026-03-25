const Rule = require('../Rule');

function createSecurityPolicyRule(k9shield) {
  return new Rule({
    name: 'SecurityPolicyRule',
    priority: 80,
    condition: async (context) => {
      const { req, res, ip } = context;
      if (!k9shield.security.checkRequestMethod(req, res, ip)) {
        context.securityDecision = {
          decision: 'BLOCK',
          reason: 'methodNotAllowed'
        };
        return true;
      }

      if (!k9shield.security.checkUserAgent(req, res, ip)) {
        context.securityDecision = {
          decision: 'BLOCK',
          reason: 'userAgentBlocked'
        };
        return true;
      }

      if (!k9shield.security.checkReferer(req, ip)) {
        context.securityDecision = {
          decision: 'BLOCK',
          reason: 'refererBlocked'
        };
        return true;
      }

      if (!k9shield.security.checkPayloadSize(req, res, ip)) {
        context.securityDecision = {
          decision: 'BLOCK',
          reason: 'payloadTooLarge'
        };
        return true;
      }

      if (k9shield.security.hasSuspiciousPatterns(req, res, ip)) {
        context.securityDecision = {
          decision: 'BLOCK',
          reason: 'suspiciousRequest'
        };
        return true;
      }

      return false;
    },
    action: (context) => {
      return context.securityDecision;
    }
  });
}

module.exports = createSecurityPolicyRule;
