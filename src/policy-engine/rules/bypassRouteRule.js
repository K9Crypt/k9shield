const Rule = require('../Rule');

function createBypassRouteRule(k9shield) {
  return new Rule({
    name: 'BypassRouteRule',
    priority: 85,
    condition: async (context) => {
      return k9shield.shouldBypassRoute(context.req.path);
    },
    action: (context) => {
      k9shield.logger.log('debug', 'Route bypassed by rule', {
        path: context.req.path,
        ip: context.ip
      });
      return { decision: 'ALLOW_BYPASS' };
    }
  });
}

module.exports = createBypassRouteRule;
