const Rule = require('./Rule');

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
    const createBypassRouteRule = require('./rules/bypassRouteRule');
    const createDdosRule = require('./rules/ddosRule');
    const createSecurityPolicyRule = require('./rules/securityPolicyRule');
    const createRateLimitRule = require('./rules/rateLimitRule');

    this.addRule(createWhitelistRule(this.k9shield));
    this.addRule(createBypassRouteRule(this.k9shield));
    this.addRule(createBlacklistRule(this.k9shield));
    this.addRule(createDdosRule(this.k9shield));
    this.addRule(createSecurityPolicyRule(this.k9shield));
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
    for (const rule of this.rules) {
      const result = await rule.evaluate(context);
      if (result) {
        this.logger.log(
          'debug',
          `Policy Engine: Rule '${rule.name}' triggered. Decision: ${result.decision}`
        );
        return result;
      }
    }

    return { decision: 'ALLOW' };
  }
}

module.exports = PolicyEngine;
