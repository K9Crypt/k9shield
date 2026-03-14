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
    const createCsrfRule = require('./rules/csrfRule');

    this.addRule(createWhitelistRule(this.k9shield));    // priority 200 – whitelist first
    this.addRule(createBlacklistRule(this.k9shield));    // priority 100 – block known bad IPs before bypass
    this.addRule(createDdosRule(this.k9shield));         // priority 90  – DDoS check before bypass
    this.addRule(createBypassRouteRule(this.k9shield));  // priority 85  – bypass only after security gates
    this.addRule(createSecurityPolicyRule(this.k9shield)); // priority 80
    this.addRule(createCsrfRule(this.k9shield));         // priority 75  – CSRF for state-changing methods
    this.addRule(createRateLimitRule(this.k9shield));    // priority 50

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
