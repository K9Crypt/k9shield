function resetRegexState(pattern) {
  if (pattern && (pattern.global || pattern.sticky)) {
    pattern.lastIndex = 0;
  }
  return pattern;
}

function matchesRoutePattern(path, pattern) {
  if (!path || !pattern) return false;

  if (typeof pattern === 'string') {
    if (pattern === '*') return true;
    if (pattern.endsWith('/*')) {
      return path.startsWith(pattern.slice(0, -2));
    }
    return path === pattern;
  }

  if (pattern instanceof RegExp) {
    // Reset regex state so /g or /y patterns stay deterministic across requests.
    return resetRegexState(pattern).test(path);
  }

  if (typeof pattern === 'function') {
    return pattern(path) === true;
  }

  return false;
}

function describePattern(pattern) {
  if (typeof pattern === 'string') return pattern;
  if (pattern instanceof RegExp) return pattern.toString();
  return 'custom-pattern';
}

module.exports = {
  describePattern,
  matchesRoutePattern,
  resetRegexState
};
