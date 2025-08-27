const Rule = require('../Rule');

function createBlacklistRule(k9shield) {
  return new Rule({
    name: 'BlacklistRule',
    priority: 100,
    condition: async (context) => {
      return k9shield.security.isBlacklisted(
        context.req,
        context.res,
        context.ip
      );
    },
    action: (context) => {
      return { decision: 'BLOCK', reason: 'accessDenied' };
    }
  });
}

module.exports = createBlacklistRule;
