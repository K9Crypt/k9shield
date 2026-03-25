const crypto = require('crypto');
const { parseCookies, safeCompare } = require('../utils/http');
const { resetRegexState } = require('../utils/routes');

const CHECK_STRING_MAX_LENGTH = 32 * 1024;
const PREFILTER_TOKENS = [
  '<script',
  'javascript:',
  'union select',
  '../',
  '..\\',
  'select ',
  'drop table',
  'insert into',
  'update ',
  'delete from',
  '$(',
  '${',
  'cmd.exe',
  '/bin/bash',
  'php://',
  'gopher://',
  '<?xml',
  '<!entity'
];

class Security {
  constructor(config, logger, ipUtils) {
    this.config = config;
    this.logger = logger;
    this.ipUtils = ipUtils;
    this.runtimeCsrfSecret = crypto.randomBytes(32).toString('hex');
    this.blacklist = new Set();
    this.whitelist = new Set();
    this.blacklistParsedCIDRs = [];
    this.whitelistParsedCIDRs = [];
    this.tempBlockList = new Map();
    this.blockHistory = new Map();
    this.lastAttackTimestamps = new Map();
    this.attackPatterns = new Map();
    this.attackScores = new Map();
    this.botScores = new Map();
    this.reputationCache = new Map();

    this.suspiciousPatterns = new Set([
      /union\s+select/i,
      /script>/i,
      /(\/\.\.)|(\.\.\/)/,
      /<[^>]*>/,
      /\$\{.*\}/i,
      /\{\{.*\}\}/i,
      /\$\(.*\)/i,
      /system\s*\(/i,
      /preg_replace\s*\(\s*['"]\s*\/.*\/e/i,
      /(?:\W|^)(?:javascript|data|vbscript|mhtml|about):/i,
      /\/dev\/(?:tcp|udp|null|zero|random)/i,
      /proc\/self/i,
      /\/etc\/(?:passwd|shadow|group)/i,
      /SELECT.*FROM/i,
      /INSERT.*INTO/i,
      /UPDATE.*SET/i,
      /DELETE.*FROM/i,
      /DROP.*TABLE/i,
      /ALTER.*TABLE/i,
      /EXEC.*sp_/i,
      /UNION.*ALL.*SELECT/i,
      /LOAD_FILE/i,
      /BENCHMARK\s*\(/i
    ]);

    this.advancedPatterns = {
      sql: new Set([
        /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
        /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
        /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
        /((\%27)|(\'))union/i,
        /exec(\s|\+)+(s|x)p\w+/i,
        /UNION(?:\s+ALL)?\s+SELECT/i,
        /INTO\s+(?:OUTFILE|DUMPFILE)/i,
        /INFORMATION_SCHEMA/i,
        /CONCAT\s*\(/i,
        /GROUP\s+BY/i,
        /HAVING\s+\d+=/i,
        /SLEEP\s*\(\s*\d+\s*\)/i,
        /WAITFOR\s+DELAY/i,
        /ORDER\s+BY\s+\d+/i,
        /(?:AND|OR)\s+\d+\s*=\s*\d+/i
      ]),
      xss: new Set([
        /<script[^>]*>[\s\S]*?<\/script>/i,
        /javascript:[^\n]*/i,
        /onerror\s*=\s*["\'][^"\']*["\']|onclick|onload|onmouseover/i,
        /<img[^>]+src[^>]*>/i,
        /data:text\/html[^>]*,/i,
        /expression\s*\(/i,
        /url\s*\(/i,
        /alert\s*\(/i,
        /prompt\s*\(/i,
        /confirm\s*\(/i,
        /eval\s*\(/i,
        /setTimeout\s*\(/i,
        /setInterval\s*\(/i,
        /Function\s*\(/i,
        /document\./i,
        /window\./i,
        /location\./i,
        /history\./i,
        /localStorage\./i,
        /sessionStorage\./i,
        /innerHTML/i,
        /outerHTML/i,
        /fromCharCode/i,
        /atob\s*\(/i,
        /btoa\s*\(/i
      ]),
      pathTraversal: new Set([
        /\.\.\/+/,
        /\/\.\.\/+/,
        /\.\.\\/,
        /\%2e\%2e\%2f/i,
        /\%252e\%252e\%252f/i,
        /\.\.%2f/i,
        /\.\.%5c/i,
        /%2e%2e%2f/i,
        /%2e%2e%5c/i,
        /\.\.\x2f/i,
        /\.\.\x5c/i,
        /\.\.\u2215/i,
        /\.\.\u2216/i
      ]),
      commandInjection: new Set([
        /\|\s*[\w-]+/,
        /;\s*[\w-]+/,
        /`[\s\S]*?`/,
        /\$\([^)]+\)/,
        /&\s*[\w-]+/,
        />\s*[\w-]+/,
        /<\s*[\w-]+/,
        /\|\|\s*[\w-]+/,
        /&&\s*[\w-]+/,
        /\$\{\w+\}/,
        /\$\[\w+\]/,
        /\/bin\/(?:bash|sh|zsh|ksh|csh|tcsh)/i,
        /\/usr\/bin\/(?:perl|python|ruby|lua|php)/i,
        /cmd\.exe/i,
        /powershell\.exe/i,
        /cscript\.exe/i,
        /wscript\.exe/i
      ]),
      fileInclusion: new Set([
        /php:\/\/(?:filter|input|data|expect)/i,
        /zip:\/\//i,
        /phar:\/\//i,
        /file:\/\//i,
        /gopher:\/\//i,
        /data:\/\//i,
        /expect:\/\//i,
        /php:\/\/(?:stdin|stdout|stderr)/i,
        /php:\/\/(?:memory|temp)/i,
        /php:\/\/(?:input|output)/i
      ]),
      ssrf: new Set([
        /internal\./i,
        /private\./i,
        /staging\./i,
        /prod\./i,
        /admin\./i,
        /intranet\./i,
        /corporate\./i,
        /169\.254\.169\.254/,
        /localhost/i
      ]),
      deserializationAttacks: new Set([
        /O:\d+:"[^"]+"/i,
        /^{.*"type".*"value".*}$/,
        /^<\?xml.*<!ENTITY/i,
        /java\.util\.HashMap/i,
        /java\.util\.LinkedHashMap/i,
        /java\.util\.ArrayList/i,
        /java\.util\.LinkedList/i,
        /System\.Collections/i,
        /System\.Data/i,
        /System\.IO/i,
        /System\.Net/i
      ])
    };

    this.thresholds = {
      maxAttemptsPerMinute: 10,
      maxBlockDuration: 24 * 60 * 60 * 1000,
      blockIncrementFactor: 2,
      suspiciousPatternScore: 1,
      maliciousPatternScore: 2,
      criticalPatternScore: 3,
      scoreThreshold: 5
    };

    this.initializeSecurityMonitoring();
  }

  initializeSecurityMonitoring() {
    // These background jobs keep temporary enforcement state bounded over time.
    const blockCleanupTimer = setInterval(() => this.cleanupTempBlocks(), 5 * 60 * 1000);
    const attackResetTimer = setInterval(() => this.resetAttackStats(), 60 * 60 * 1000);
    const transientCleanupTimer = setInterval(() => this.cleanupTransientState(), 60 * 1000);
    if (typeof blockCleanupTimer.unref === 'function') blockCleanupTimer.unref();
    if (typeof attackResetTimer.unref === 'function') attackResetTimer.unref();
    if (typeof transientCleanupTimer.unref === 'function') transientCleanupTimer.unref();
  }

  getProfileConfig(req) {
    return req?.k9shieldProfile || this.config.security.profiles.default || {};
  }

  normalizeLowercaseArray(list) {
    return Array.isArray(list) ? list.map((entry) => String(entry).toLowerCase()) : [];
  }

  testPattern(pattern, value) {
    if (!(pattern instanceof RegExp)) return false;
    return resetRegexState(pattern).test(value);
  }

  checkRequestMethod(req, res, ip) {
    if (!this.config.security.allowedMethods.includes(req.method)) {
      this.incrementAttackScore(ip, this.thresholds.suspiciousPatternScore);
      this.logger.log('warning', `Invalid method ${req.method} from ${ip}`, req);
      return false;
    }
    return true;
  }

  _parseRegexFromString(str) {
    if (typeof str !== 'string' || !str.startsWith('/') || str.length < 2) return null;
    const lastSlash = str.lastIndexOf('/');
    if (lastSlash <= 0) return null;
    const pattern = str.slice(1, lastSlash);
    const flags = str.slice(lastSlash + 1);
    if (flags !== '' && !/^[gimsuy]*$/.test(flags)) return null;
    try {
      return new RegExp(pattern, flags);
    } catch (error) {
      return null;
    }
  }

  checkUserAgent(req, res, ip) {
    if (this.getProfileConfig(req).skipUserAgentCheck) return true;
    const list = this.config.security.userAgentBlacklist;
    const ua = (req.headers['user-agent'] || '').trim();
    return this.checkBlockedValue(list, ua, ip, 'User-Agent', req);
  }

  checkReferer(req, ip) {
    const list = this.config.security.refererBlacklist;
    const referer = (req.headers.referer || '').trim();
    if (!referer) return true;
    return this.checkBlockedValue(list, referer, ip, 'Referer', req);
  }

  checkBlockedValue(list, value, ip, label, req) {
    if (!Array.isArray(list) || list.length === 0) return true;
    for (const entry of list) {
      if (typeof entry === 'string') {
        const regex = this._parseRegexFromString(entry);
        if (regex) {
          if (this.testPattern(regex, value)) {
            this.logger.log('warning', `Blocked ${label} (pattern) from ${ip}`, req);
            return false;
          }
        } else if (value.toLowerCase().includes(entry.toLowerCase())) {
          this.logger.log('warning', `Blocked ${label} from ${ip}`, req);
          return false;
        }
      } else if (entry instanceof RegExp && this.testPattern(entry, value)) {
        this.logger.log('warning', `Blocked ${label} (pattern) from ${ip}`, req);
        return false;
      }
    }
    return true;
  }

  isBlacklisted(req, res, ip) {
    if (this.blacklist.has(ip)) {
      this.logger.log('blocked', `Blocked request from blacklisted IP ${ip}`, req);
      return true;
    }
    if (
      this.blacklistParsedCIDRs.length > 0 &&
      this.ipUtils.matchIPInParsedRanges(ip, this.blacklistParsedCIDRs)
    ) {
      this.logger.log('blocked', `Blocked request from blacklisted CIDR ${ip}`, req);
      return true;
    }

    const tempBlock = this.tempBlockList.get(ip);
    if (tempBlock && tempBlock.expiry > Date.now()) {
      this.logger.log('blocked', `Blocked request from temporarily blocked IP ${ip}`, req);
      return true;
    }

    return false;
  }

  isWhitelisted(ip) {
    if (this.whitelist.has(ip)) return true;
    if (
      this.whitelistParsedCIDRs.length > 0 &&
      this.ipUtils.matchIPInParsedRanges(ip, this.whitelistParsedCIDRs)
    ) {
      return true;
    }
    return false;
  }

  checkPayloadSize(req, res, ip) {
    const rawLen = req.headers['content-length'];
    const contentLength = Number.parseInt(rawLen, 10);
    if (rawLen !== undefined && (!Number.isFinite(contentLength) || contentLength < 0)) {
      this.incrementAttackScore(ip, this.thresholds.suspiciousPatternScore);
      this.logger.log('warning', `Invalid Content-Length header from ${ip}`, req);
      return false;
    }
    if (contentLength > this.config.security.maxBodySize) {
      this.incrementAttackScore(ip, this.thresholds.suspiciousPatternScore);
      this.logger.log('warning', `Payload too large from ${ip}`, req);
      return false;
    }
    return true;
  }

  buildCheckString(components, maxLen) {
    const full = components.filter(Boolean).join(' ');
    return full.length > maxLen ? full.slice(0, maxLen) : full;
  }

  createCheckString(req) {
    try {
      const maxLen = this.config.security?.checkStringMaxLength ?? CHECK_STRING_MAX_LENGTH;
      const headersToCheck = Object.keys(req.headers).filter(
        (header) =>
          !this.config.security.requestHeaderWhitelist.includes(header.toLowerCase())
      );

      const filteredHeaders = headersToCheck.reduce((obj, key) => {
        obj[key.toLowerCase()] = req.headers[key];
        return obj;
      }, {});

      return this.buildCheckString(
        [
          req.url,
          typeof req.body === 'string' ? req.body : JSON.stringify(req.body || ''),
          JSON.stringify(filteredHeaders),
          req.query ? JSON.stringify(req.query) : '',
          req.params ? JSON.stringify(req.params) : ''
        ],
        maxLen
      );
    } catch (error) {
      this.logger.log('error', `Error creating check string: ${error.message}`);
      return '';
    }
  }

  containsPrefilterTokens(checkString) {
    const lowered = checkString.toLowerCase();
    return PREFILTER_TOKENS.some((token) => lowered.includes(token));
  }

  shouldDeepInspect(req, checkString) {
    const profile = this.getProfileConfig(req);
    if (profile.enableDeepInspection === false) return false;

    const fastInspection = this.config.security.fastInspection || {};
    if (fastInspection.enabled === false) return true;

    const methods = this.normalizeLowercaseArray(fastInspection.deepInspectMethods);
    if (methods.includes(String(req.method).toLowerCase())) return true;

    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    const contentTypes = this.normalizeLowercaseArray(fastInspection.deepInspectContentTypes);
    if (contentTypes.some((type) => contentType.includes(type))) return true;

    // Fast inspection is a cheap prefilter. If it does not see a risky method,
    // content-type, or token, we skip the heavier regex pass.
    return this.containsPrefilterTokens(checkString);
  }

  scoreStringPatterns(checkString, ip, req) {
    let totalScore = 0;
    const detectedPatterns = new Set();

    for (const pattern of this.suspiciousPatterns) {
      try {
        if (this.testPattern(pattern, checkString)) {
          totalScore += this.thresholds.suspiciousPatternScore;
          detectedPatterns.add(pattern.toString());
          if (totalScore >= this.thresholds.scoreThreshold) {
            return { totalScore, detectedPatterns, blocked: true };
          }
        }
      } catch (error) {
        this.logger.log('warning', `Pattern test error: ${error.message}`, req);
      }
    }

    for (const [category, patterns] of Object.entries(this.advancedPatterns)) {
      for (const pattern of patterns) {
        try {
          if (this.testPattern(pattern, checkString)) {
            totalScore += this.thresholds.maliciousPatternScore;
            detectedPatterns.add(`${category}:${pattern.toString()}`);
            if (totalScore >= this.thresholds.scoreThreshold) {
              return { totalScore, detectedPatterns, blocked: true };
            }
          }
        } catch (error) {
          this.logger.log(
            'warning',
            `Advanced pattern test error in ${category}: ${error.message}`,
            req
          );
        }
      }
    }

    return { totalScore, detectedPatterns, blocked: false };
  }

  hasSuspiciousPatterns(req, res, ip) {
    try {
      const checkString = this.createCheckString(req);
      if (!checkString) return false;

      const maxLen = this.config.security?.checkStringMaxLength ?? CHECK_STRING_MAX_LENGTH;
      if (checkString.length > maxLen) {
        this.incrementAttackScore(ip, this.thresholds.suspiciousPatternScore);
        this.logger.log('warning', `Request string too long from ${ip}`, req);
        return true;
      }

      let totalScore = 0;
      const detectedPatterns = new Set();

      // Run anomaly checks first because they are cheaper than the full regex suite.
      if (this.hasSpecialCharacterAnomaly(checkString)) {
        totalScore += this.thresholds.suspiciousPatternScore;
        detectedPatterns.add('special-char-anomaly');
      }
      if (this.hasEncodingAnomaly(checkString)) {
        totalScore += this.thresholds.suspiciousPatternScore;
        detectedPatterns.add('encoding-anomaly');
      }
      if (this.hasUnicodeEvasion(checkString)) {
        totalScore += this.thresholds.maliciousPatternScore;
        detectedPatterns.add('unicode-evasion');
      }

      if (totalScore >= this.thresholds.scoreThreshold) {
        this.handleSuspiciousRequest(ip, totalScore, detectedPatterns, req);
        return true;
      }

      if (!this.shouldDeepInspect(req, checkString)) {
        return false;
      }

      // Deep inspection is only for requests that already look risky enough to justify it.
      const result = this.scoreStringPatterns(checkString, ip, req);
      totalScore += result.totalScore;
      result.detectedPatterns.forEach((pattern) => detectedPatterns.add(pattern));
      if (result.blocked || totalScore >= this.thresholds.scoreThreshold) {
        this.handleSuspiciousRequest(ip, totalScore, detectedPatterns, req);
        return true;
      }

      return false;
    } catch (error) {
      this.logger.log('error', `Pattern checking error: ${error.message}`, req);
      return true;
    }
  }

  inspectParsedBody(body, ip) {
    try {
      if (body === undefined || body === null) return false;

      const maxScanSize =
        this.config.security?.parsedBodyInspection?.maxBodyScanSize || 64 * 1024;
      const serialized = typeof body === 'string' ? body : JSON.stringify(body);
      const candidate = serialized.length > maxScanSize ? serialized.slice(0, maxScanSize) : serialized;
      const result = this.scoreStringPatterns(candidate, ip);
      if (
        result.blocked ||
        result.totalScore >= this.thresholds.suspiciousPatternScore ||
        this.hasEncodingAnomaly(candidate) ||
        this.hasUnicodeEvasion(candidate)
      ) {
        this.handleSuspiciousRequest(ip, result.totalScore, result.detectedPatterns);
        return true;
      }
      return false;
    } catch (error) {
      this.logger.log('error', `Parsed body inspection failed: ${error.message}`);
      return true;
    }
  }

  handleSuspiciousRequest(ip, score, patterns, req) {
    this.incrementAttackScore(ip, score);

    const attackHistory = this.attackPatterns.get(ip) || [];
    attackHistory.push({
      timestamp: Date.now(),
      score,
      patterns: Array.from(patterns)
    });
    this.attackPatterns.set(ip, attackHistory);

    const blockDuration = this.calculateBlockDuration(ip, score);
    if (blockDuration > 0) {
      this.tempBlockList.set(ip, {
        expiry: Date.now() + blockDuration,
        reason: Array.from(patterns).join(', '),
        score
      });

      const history = this.blockHistory.get(ip) || [];
      history.push({ timestamp: Date.now(), duration: blockDuration, score });
      this.blockHistory.set(ip, history);
    }

    this.logger.log('attack', `Suspicious patterns detected from ${ip}`, {
      ip,
      score,
      patterns: Array.from(patterns),
      blockDuration
    });
  }

  calculateBlockDuration(ip, score) {
    const history = this.blockHistory.get(ip) || [];
    const blockCount = history.length;

    let duration = Math.min(
      30 * 60 * 1000 * Math.pow(this.thresholds.blockIncrementFactor, blockCount),
      this.thresholds.maxBlockDuration
    );

    if (score >= this.thresholds.scoreThreshold * 2) {
      duration *= 2;
    }

    return duration;
  }

  incrementAttackScore(ip, score) {
    const now = Date.now();
    const current = this.attackScores.get(ip) || { score: 0, windowStart: now };
    if (now - current.windowStart >= 60000) {
      current.score = 0;
      current.windowStart = now;
    }
    current.score += score;
    this.attackScores.set(ip, current);
    this.lastAttackTimestamps.set(ip, now);

    if (current.score >= this.thresholds.maxAttemptsPerMinute) {
      this.blacklist.add(ip);
      this.logger.log('banned', `IP ${ip} permanently banned due to high attack score`);
    }
  }

  hasSpecialCharacterAnomaly(str) {
    const specialCharCount = (str.match(/[^a-zA-Z0-9\s]/g) || []).length;
    return specialCharCount > str.length * 0.3;
  }

  hasEncodingAnomaly(str) {
    const encodedCount = (str.match(/%[0-9a-fA-F]{2}/g) || []).length;
    return encodedCount > str.length * 0.2;
  }

  hasUnicodeEvasion(str) {
    return /\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/i.test(str);
  }

  evaluateBotThreat(req, ip) {
    const botConfig = this.config.security.botProtection || {};
    if (botConfig.enabled !== true) return null;
    if (this.getProfileConfig(req).skipUserAgentCheck === true) return null;

    // The bot score is intentionally cumulative so repeated "almost suspicious" requests
    // can still be throttled or blocked without requiring a single obvious signature.
    const ua = String(req.headers['user-agent'] || '').trim().toLowerCase();
    const allowListed = this.normalizeLowercaseArray(botConfig.allowListedUserAgents);
    if (allowListed.some((value) => ua.includes(value))) return null;

    let delta = 0;
    if (!ua && !['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      delta += botConfig.emptyUserAgentScore || 2;
    }

    const knownBad = this.normalizeLowercaseArray(botConfig.knownBadUserAgents);
    if (knownBad.some((value) => ua.includes(value))) {
      delta += Math.max(botConfig.blockThreshold || 5, 5);
    }

    if (!req.headers.accept && req.method !== 'OPTIONS') {
      delta += botConfig.automationHeaderScore || 1;
    }

    if (req.headers['x-requested-with'] && !ua.includes('mozilla')) {
      delta += botConfig.automationHeaderScore || 1;
    }

    if (delta === 0) return null;

    const record = this.botScores.get(ip) || { score: 0, updatedAt: Date.now() };
    record.score = Math.max(0, record.score * 0.8) + delta;
    record.updatedAt = Date.now();
    this.botScores.set(ip, record);

    if (record.score >= (botConfig.blockThreshold || 5)) {
      this.tempBlockList.set(ip, {
        expiry: Date.now() + 15 * 60 * 1000,
        reason: 'bot-detected',
        score: record.score
      });
      return {
        decision: 'BLOCK',
        reason: 'botDetected',
        data: { score: record.score }
      };
    }

    if (record.score >= (botConfig.throttleThreshold || 3)) {
      return {
        decision: 'THROTTLE',
        reason: 'botDetected',
        data: { score: record.score }
      };
    }

    return null;
  }

  normalizeReputationResult(result) {
    if (typeof result === 'number') {
      return { score: result };
    }
    if (!result || typeof result !== 'object') return { score: 0 };
    return result;
  }

  toReputationDecision(result) {
    if (!result) return null;

    const reputationConfig = this.config.security.reputation || {};
    if (
      result.action === 'block' ||
      result.score >= (reputationConfig.blockThreshold || 80)
    ) {
      return {
        decision: 'BLOCK',
        reason: 'reputationBlocked',
        data: result
      };
    }

    if (
      result.action === 'throttle' ||
      result.score >= (reputationConfig.throttleThreshold || 50)
    ) {
      return {
        decision: 'THROTTLE',
        reason: 'reputationThrottled',
        data: result
      };
    }

    return null;
  }

  async evaluateReputation(req, ip) {
    const reputationConfig = this.config.security.reputation || {};
    if (reputationConfig.enabled !== true || typeof reputationConfig.resolver !== 'function') {
      return null;
    }

    // Cache resolver output because reputation providers are usually slower than local checks.
    const cacheKey = `${ip}:${req.path}`;
    const cached = this.reputationCache.get(cacheKey);
    if (cached && cached.expiry > Date.now()) {
      return this.toReputationDecision(cached.value);
    }

    const result = this.normalizeReputationResult(
      await reputationConfig.resolver({ ip, req })
    );
    const normalized = {
      score: result.score || 0,
      action: result.action || null,
      reason: result.reason || 'reputation'
    };
    this.reputationCache.set(cacheKey, {
      value: normalized,
      expiry: Date.now() + (result.ttl || reputationConfig.ttl || 5 * 60 * 1000)
    });

    return this.toReputationDecision(normalized);
  }

  getCsrfSecret() {
    // Double-submit CSRF should work without forcing application teams to wire a secret first.
    // A configured secret still takes precedence when callers want stable cross-restart tokens.
    return this.config.security?.csrfProtection?.secret || this.runtimeCsrfSecret;
  }

  generateCsrfToken(subject = 'anonymous') {
    const secret = this.getCsrfSecret();

    const payload = {
      sub: String(subject),
      iat: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex')
    };
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
    return `${encoded}.${signature}`;
  }

  verifyCsrfToken(token, subject = null) {
    const secret = this.getCsrfSecret();
    if (!secret || typeof token !== 'string') return false;

    const parts = token.split('.');
    if (parts.length !== 2) return false;

    const [encoded, signature] = parts;
    const expected = crypto.createHmac('sha256', secret).update(encoded).digest('base64url');
    if (!safeCompare(expected, signature)) return false;

    try {
      const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
      const maxAgeMs = this.config.security?.csrfProtection?.tokenMaxAgeMs || 2 * 60 * 60 * 1000;
      if (!payload.iat || Date.now() - payload.iat > maxAgeMs) return false;
      if (subject !== null && String(payload.sub) !== String(subject)) return false;
      return true;
    } catch (error) {
      return false;
    }
  }

  validateCsrfDoubleSubmit(req) {
    const csrfConfig = this.config.security?.csrfProtection || {};
    const cookies = parseCookies(req.headers.cookie);
    const cookieToken = cookies[csrfConfig.cookieName || 'k9shield_csrf'];
    const headerName = String(csrfConfig.headerName || 'x-csrf-token').toLowerCase();
    const headerToken = req.headers[headerName];

    // Double-submit mode requires a signed token in both cookie and header.
    // Matching values alone are not enough; the token must also verify cryptographically.
    if (!cookieToken || !headerToken) {
      return { decision: 'BLOCK', reason: 'csrfMissingToken' };
    }

    if (!safeCompare(cookieToken, headerToken)) {
      return { decision: 'BLOCK', reason: 'csrfTokenMismatch' };
    }

    if (!this.verifyCsrfToken(headerToken)) {
      return { decision: 'BLOCK', reason: 'csrfInvalidToken' };
    }

    return null;
  }

  attachStreamingProtection(req, res, ip, onViolation) {
    const streamConfig = this.config.security.streamingProtection || {};
    if (
      streamConfig.enabled !== true ||
      req._k9shieldStreamingGuardAttached === true ||
      !Array.isArray(streamConfig.applyToMethods) ||
      !streamConfig.applyToMethods.includes(req.method)
    ) {
      return;
    }

    // Streaming protection must not consume the request stream itself, otherwise it can
    // starve downstream body parsers. We only observe socket progress here.
    req._k9shieldStreamingGuardAttached = true;
    const maxBodySize = streamConfig.maxBodySize || this.config.security.maxBodySize;
    const minBytesPerSecond = streamConfig.minBytesPerSecond || 128;
    const gracePeriodMs = streamConfig.gracePeriodMs || 1500;
    const checkIntervalMs = streamConfig.checkIntervalMs || 500;

    const startedAt = Date.now();
    const initialBytesRead = req.socket?.bytesRead || 0;
    let finished = false;

    const cleanup = () => {
      if (finished) return;
      finished = true;
      clearInterval(interval);
      req.off('end', cleanup);
      req.off('close', cleanup);
      req.off('aborted', cleanup);
      res.off('close', cleanup);
      res.off('finish', cleanup);
    };

    const fail = (reason, data) => {
      if (finished) return;
      cleanup();
      onViolation(reason, data);
      if (typeof req.destroy === 'function') {
        req.destroy();
      }
    };

    const interval = setInterval(() => {
      if (finished) return;
      const contentLength = Number.parseInt(req.headers['content-length'], 10) || 0;
      const elapsed = Date.now() - startedAt;
      const bodyBytesRead = Math.max(0, (req.socket?.bytesRead || 0) - initialBytesRead);

      if (bodyBytesRead > maxBodySize) {
        fail('payloadTooLarge', { receivedBytes: bodyBytesRead, limit: maxBodySize });
        return;
      }

      if (elapsed < gracePeriodMs) return;

      // Only enforce slow-upload checks when the sender claimed a body and it is still incomplete.
      const bytesPerSecond = bodyBytesRead / Math.max(elapsed / 1000, 1);
      if (
        contentLength > 0 &&
        bodyBytesRead < contentLength &&
        bodyBytesRead > 0 &&
        bytesPerSecond < minBytesPerSecond
      ) {
        fail('slowRequest', { bytesPerSecond: Math.floor(bytesPerSecond) });
      }
    }, checkIntervalMs);

    if (typeof interval.unref === 'function') interval.unref();

    req.on('end', cleanup);
    req.on('close', cleanup);
    req.on('aborted', cleanup);
    res.on('close', cleanup);
    res.on('finish', cleanup);
  }

  cleanupTempBlocks() {
    const now = Date.now();
    for (const [ip, block] of this.tempBlockList.entries()) {
      if (block.expiry <= now) {
        this.tempBlockList.delete(ip);
        this.logger.log('info', `Temporary block expired for IP ${ip}`);
      }
    }
  }

  resetAttackStats() {
    const now = Date.now();
    for (const [ip, timestamp] of this.lastAttackTimestamps.entries()) {
      if (now - timestamp > 60 * 60 * 1000) {
        this.lastAttackTimestamps.delete(ip);
        this.attackPatterns.delete(ip);
        this.attackScores.delete(ip);
      }
    }
  }

  cleanupTransientState() {
    // Bot scores and reputation cache entries are intentionally short-lived signals.
    const now = Date.now();
    for (const [ip, state] of this.botScores.entries()) {
      if (now - state.updatedAt > 10 * 60 * 1000) {
        this.botScores.delete(ip);
      }
    }

    for (const [key, record] of this.reputationCache.entries()) {
      if (record.expiry <= now) {
        this.reputationCache.delete(key);
      }
    }
  }

  blockIP(ip) {
    this.blacklist.add(ip);
    if (typeof ip === 'string' && ip.includes('/')) {
      const parsed = this.ipUtils.parseCIDR(ip);
      if (parsed) this.blacklistParsedCIDRs.push({ raw: ip, parsed });
    }
    this.logger.log('manual', `IP ${ip} manually blocked`);
  }

  unblockIP(ip) {
    this.blacklist.delete(ip);
    this.blacklistParsedCIDRs = this.blacklistParsedCIDRs.filter((range) => range.raw !== ip);
    this.tempBlockList.delete(ip);
    this.logger.log('manual', `IP ${ip} manually unblocked`);
  }

  whitelistIP(ip) {
    this.whitelist.add(ip);
    if (typeof ip === 'string' && ip.includes('/')) {
      const parsed = this.ipUtils.parseCIDR(ip);
      if (parsed) this.whitelistParsedCIDRs.push({ raw: ip, parsed });
    }
    this.blacklist.delete(ip);
    this.tempBlockList.delete(ip);
    this.logger.log('manual', `IP ${ip} manually whitelisted`);
  }

  unwhitelistIP(ip) {
    this.whitelist.delete(ip);
    this.whitelistParsedCIDRs = this.whitelistParsedCIDRs.filter((range) => range.raw !== ip);
    this.logger.log('manual', `IP ${ip} manually unwhitelisted`);
  }

  addSuspiciousPattern(pattern) {
    if (!(pattern instanceof RegExp)) {
      throw new Error('Pattern must be a RegExp instance');
    }

    this.suspiciousPatterns.add(pattern);
    this.logger.log('info', `New suspicious pattern added: ${pattern}`);
  }

  reset() {
    this.blacklist.clear();
    this.whitelist.clear();
    this.blacklistParsedCIDRs = [];
    this.whitelistParsedCIDRs = [];
    this.tempBlockList.clear();
    this.blockHistory.clear();
    this.lastAttackTimestamps.clear();
    this.attackPatterns.clear();
    this.attackScores.clear();
    this.botScores.clear();
    this.reputationCache.clear();
  }
}

module.exports = Security;
