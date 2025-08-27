const Rule = require('../Rule');

function createWhitelistRule(k9shield) {
  return new Rule({
    name: 'WhitelistRule',
    priority: 200,
    condition: async (context) => {
      return k9shield.security.isWhitelisted(context.ip);
    },
    action: (context) => {
      k9shield.logger.log('debug', 'Whitelisted IP allowed', {
        ip: context.ip
      });
      return { decision: 'ALLOW_BYPASS' };
    }
  });
}

module.exports = createWhitelistRule;
