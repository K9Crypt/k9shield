class Rule {
  constructor({ name, priority, condition, action }) {
    if (!name || !condition || !action) {
      throw new Error('Rule must have a name, condition, and action.');
    }
    this.name = name;
    this.priority = priority || 0;
    this.condition = condition;
    this.action = action;
  }

  async evaluate(context) {
    if (await this.condition(context)) {
      return this.action(context);
    }
    return null;
  }
}

module.exports = Rule;
