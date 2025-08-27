const Rule = require('../Rule');

function createRateLimitRule(k9shield) {
  return new Rule({
    name: 'RateLimitRule',
    priority: 50,
    condition: async (context) => {
      const { req, res, ip } = context;
      const result = await k9shield.rateLimiter.handleRateLimiting(
        req,
        res,
        ip
      );

      if (result && result.error) {
        context.rateLimitDecision = {
          decision: 'BLOCK',
          reason: result.error,
          data: result.data
        };
        return true;
      }

      return false;
    },
    action: (context) => {
      return context.rateLimitDecision;
    }
  });
}

module.exports = createRateLimitRule;
