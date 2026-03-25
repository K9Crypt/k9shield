class PolicyEngine {
  constructor(k9shieldInstance) {
    this.k9shield = k9shieldInstance;
    this.logger = k9shieldInstance.logger;
    this.rules = [];
    this.loadRules();
  }

  loadRules() {
    const createBlacklistRule = require('./rules/blacklistRule');
    const createWhitelistRule = require('./rules/whitelistRule');
    const createDdosRule = require('./rules/ddosRule');
    const createBypassRouteRule = require('./rules/bypassRouteRule');
    const createReputationRule = require('./rules/reputationRule');
    const createSecurityPolicyRule = require('./rules/securityPolicyRule');
    const createBotProtectionRule = require('./rules/botProtectionRule');
    const createWebhookRule = require('./rules/webhookRule');
    const createCsrfRule = require('./rules/csrfRule');
    const createRateLimitRule = require('./rules/rateLimitRule');

    this.addRule(createWhitelistRule(this.k9shield));
    this.addRule(createBlacklistRule(this.k9shield));
    this.addRule(createDdosRule(this.k9shield));
    this.addRule(createBypassRouteRule(this.k9shield));
    this.addRule(createReputationRule(this.k9shield));
    this.addRule(createSecurityPolicyRule(this.k9shield));
    this.addRule(createBotProtectionRule(this.k9shield));
    this.addRule(createWebhookRule(this.k9shield));
    this.addRule(createCsrfRule(this.k9shield));
    this.addRule(createRateLimitRule(this.k9shield));

    this.logger.log(
      'info',
      `Policy Engine initialized with ${this.rules.length} rule(s).`
    );
  }

  addRule(rule) {
    this.rules.push(rule);
    this.rules.sort((a, b) => b.priority - a.priority);
  }

  async evaluate(context) {
    const trace = [];

    for (const rule of this.rules) {
      // Record per-rule timings so we can explain and measure why a decision happened.
      const startedAt = process.hrtime.bigint();
      const result = await rule.evaluate(context);
      const durationNs = Number(process.hrtime.bigint() - startedAt);
      trace.push({
        rule: rule.name,
        matched: !!result,
        decision: result?.decision || null,
        durationNs
      });

      if (result) {
        context.decisionTrace = trace;
        this.logger.log(
          'debug',
          `Policy Engine: Rule '${rule.name}' triggered. Decision: ${result.decision}`
        );
        return result;
      }
    }

    context.decisionTrace = trace;
    return { decision: 'ALLOW' };
  }
}

module.exports = PolicyEngine;
