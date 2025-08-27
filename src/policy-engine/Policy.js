class Policy {
  constructor(name, rules = []) {
    this.name = name;
    this.rules = rules;
  }

  addRule(rule) {
    this.rules.push(rule);
  }
}

module.exports = Policy;
