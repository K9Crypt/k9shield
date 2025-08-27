const Rule = require('../Rule');

function createDdosRule(k9shield) {
  return new Rule({
    name: 'DdosRule',
    priority: 90,
    condition: async (context) => {
      const { req, res, ip } = context;
      if (k9shield.ddosProtection.isBlocked(ip)) {
        context.ddosDecision = { decision: 'BLOCK', reason: 'ddosAttack' };
        return true;
      }
      const attackResult = k9shield.ddosProtection.checkAttack(req, res, ip);
      if (attackResult) {
        context.ddosDecision = { decision: 'BLOCK', reason: 'ddosAttack' };
        return true;
      }
      return false;
    },
    action: (context) => {
      return context.ddosDecision;
    }
  });
}

module.exports = createDdosRule;
