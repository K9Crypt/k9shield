const Rule = require('../Rule');

function createBotProtectionRule(k9shield) {
  return new Rule({
    name: 'BotProtectionRule',
    priority: 79,
    condition: async (context) => {
      const result = k9shield.security.evaluateBotThreat(context.req, context.ip);
      if (result) {
        context.botDecision = result;
        return true;
      }
      return false;
    },
    action: (context) => context.botDecision
  });
}

module.exports = createBotProtectionRule;
