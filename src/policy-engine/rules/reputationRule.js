const Rule = require('../Rule');

function createReputationRule(k9shield) {
  return new Rule({
    name: 'ReputationRule',
    priority: 82,
    condition: async (context) => {
      const result = await k9shield.security.evaluateReputation(context.req, context.ip);
      if (result) {
        context.reputationDecision = result;
        return true;
      }
      return false;
    },
    action: (context) => context.reputationDecision
  });
}

module.exports = createReputationRule;
