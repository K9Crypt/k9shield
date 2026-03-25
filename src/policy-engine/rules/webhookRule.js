const Rule = require('../Rule');

function createWebhookRule(k9shield) {
  return new Rule({
    name: 'WebhookRule',
    priority: 78,
    condition: async (context) => {
      const result = await k9shield.webhookProtection.verifyRequest(context.req);
      if (!result.ok) {
        context.webhookDecision = {
          decision: 'BLOCK',
          reason: result.reason
        };
        return true;
      }

      if (result.routeConfig) {
        context.req.k9shieldWebhook = result.routeConfig;
      }

      return false;
    },
    action: (context) => context.webhookDecision
  });
}

module.exports = createWebhookRule;
