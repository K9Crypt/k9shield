const MAX_TRACKED_IPS = 50000;
const MAX_REQUESTS_PER_IP = 500;
const MAX_PATTERNS_PER_IP = 100;
const MAX_PATH_COUNTER_KEYS = 100000;

class DDoSProtection {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.connections = new Map();
    // stores expiry timestamps instead of bare membership to prevent timer race
    this.blockedIPs = new Map();
    this.connectionStats = new Map();
    this.blockHistory = new Map();
    this.syncService = null;
    this.requestPatterns = new Map();
    this.anomalyScores = new Map();
    this.lastCleanup = Date.now();

    this.thresholds = {
      maxRequestsPerSecond: 50,
      maxRequestsPerMinute: 1000,
      maxConcurrentConnections: 100,
      maxPayloadSize: 1024 * 1024,
      maxHeaderSize: 8192,
      maxUrlLength: 2048,
      burstThreshold: 20,
      slowRequestThreshold: 5,
      anomalyScoreThreshold: 100,
      blockDurationMultiplier: 2,
      maxBlockDuration: 24 * 60 * 60 * 1000
    };

    this.init();
  }

  init() {
    setInterval(() => {
      this.cleanupData();
      this.updateAnomalyScores();
    }, 60000);

    setInterval(() => {
      this.checkInstantLoad();
    }, 5000);
  }

  checkAttack(req, res, ip) {
    if (!this.config.ddosProtection.enabled) return false;

    try {
      const now = Date.now();

      // LRU eviction: evict IP with oldest lastRequest when at cap
      if (!this.connectionStats.has(ip) && this.connectionStats.size >= MAX_TRACKED_IPS) {
        let oldestIP = null;
        let oldestTime = Infinity;
        for (const [candIP, stats] of this.connectionStats) {
          const t = stats.lastRequest || 0;
          if (t < oldestTime) {
            oldestTime = t;
            oldestIP = candIP;
          }
        }
        if (oldestIP != null) {
          this.connectionStats.delete(oldestIP);
          this.requestPatterns.delete(oldestIP);
          this.anomalyScores.delete(oldestIP);
        }
      }

      const stats = this.getStats(ip);
      let anomalyScore = 0;

      stats.lastRequest = now;
      // cap stored timestamps to prevent unbounded growth per IP
      if (stats.requests.length < MAX_REQUESTS_PER_IP) {
        stats.requests.push(now);
      }
      stats.totalRequests = (stats.totalRequests || 0) + 1;

      this.analyzeRequestPattern(ip, req);

      const recentRequests = stats.requests.filter((time) => now - time < 1000);
      if (recentRequests.length > this.thresholds.maxRequestsPerSecond) {
        anomalyScore += 30;
      }

      const minuteRequests = stats.requests.filter(
        (time) => now - time < 60000
      );
      if (minuteRequests.length > this.thresholds.maxRequestsPerMinute) {
        anomalyScore += 20;
      }

      const contentLength = parseInt(req.headers['content-length'], 10) || 0;
      if (contentLength > this.thresholds.maxPayloadSize) {
        anomalyScore += 25;
      }

      const headerSize = JSON.stringify(req.headers).length;
      if (headerSize > this.thresholds.maxHeaderSize) {
        anomalyScore += 15;
      }

      if (req.url.length > this.thresholds.maxUrlLength) {
        anomalyScore += 10;
      }

      if (this.isSlowRequest(req)) {
        stats.slowRequests = (stats.slowRequests || 0) + 1;
        if (stats.slowRequests > this.thresholds.slowRequestThreshold) {
          anomalyScore += 20;
        }
      }

      const patternScore = this.checkRequestPatternAnomaly(ip);
      anomalyScore += patternScore;

      this.updateAnomalyScore(ip, anomalyScore);

      const totalScore = this.anomalyScores.get(ip) || 0;
      if (totalScore > this.thresholds.anomalyScoreThreshold) {
        this.handleAttack(ip, res, totalScore, req);
        return true;
      }

      if (this.isPathRateLimitExceeded(req.path, ip, now)) {
        this.handleAttack(ip, res, anomalyScore, req);
        return true;
      }

      return false;
    } catch (error) {
      this.logger.log('error', `Error in DDoS check: ${error.message}`);
      return false;
    }
  }

  isUnderAttack(stats, req) {
    const now = Date.now();

    const recentRequests = stats.requests.filter(
      (time) => now - time < 1000
    ).length;
    if (recentRequests > this.thresholds.maxRequestsPerSecond) {
      return true;
    }

    const minuteRequests = stats.requests.filter(
      (time) => now - time < 60000
    ).length;
    if (minuteRequests > this.thresholds.maxRequestsPerMinute) {
      return true;
    }

    if (recentRequests > this.thresholds.burstThreshold) {
      return true;
    }

    if (this.isSlowRequest(req)) {
      stats.slowRequests = (stats.slowRequests || 0) + 1;
      if (stats.slowRequests > this.thresholds.slowRequestThreshold) {
        return true;
      }
    }

    return false;
  }

  handleAttack(ip, res, score, req) {
    try {
      const now = Date.now();
      const blockCount = (this.blockHistory.get(ip) || []).length + 1;
      const blockDuration = Math.min(
        this.config.ddosProtection.config.blockDuration *
          Math.pow(this.thresholds.blockDurationMultiplier, blockCount - 1),
        this.thresholds.maxBlockDuration
      );

      const newExpiry = now + blockDuration;
      // extend existing block if already blocked for longer duration
      const existingExpiry = this.blockedIPs.get(ip) || 0;
      this.blockedIPs.set(ip, Math.max(existingExpiry, newExpiry));

      const history = this.blockHistory.get(ip) || [];
      history.push({
        timestamp: now,
        duration: blockDuration,
        score: score,
        method: req ? req.method : 'unknown',
        path: req ? req.path : 'unknown'
      });
      this.blockHistory.set(ip, history);

      this.logger.log('attack', `DDoS attack detected from IP ${ip}`, {
        blockCount,
        blockDuration,
        score,
        history: history.length,
        method: req ? req.method : 'unknown',
        path: req ? req.path : 'unknown'
      });

      if (this.syncService) {
        this.syncService.reportAttack(ip, blockDuration, score);
      }

      return {
        message: 'Suspicious traffic pattern detected',
        blockDuration: blockDuration / 1000,
        remainingAttempts: Math.max(0, 3 - blockCount),
        nextBlockDuration:
          (blockDuration * this.thresholds.blockDurationMultiplier) / 1000,
        score: score
      };
    } catch (error) {
      this.logger.log('error', `Error handling attack: ${error.message}`);
      return {
        message: 'Error handling attack',
        error: error.message
      };
    }
  }

  analyzeRequestPattern(ip, req) {
    try {
      const pattern = {
        method: req.method,
        path: req.path,
        headers: Object.keys(req.headers).sort().join(','),
        timestamp: Date.now()
      };

      if (!this.requestPatterns.has(ip)) {
        this.requestPatterns.set(ip, []);
      }

      const patterns = this.requestPatterns.get(ip);
      // use index-based overwrite (ring buffer behaviour) instead of shift() O(n)
      if (patterns.length >= MAX_PATTERNS_PER_IP) {
        patterns[patterns._head || 0] = pattern;
        patterns._head = ((patterns._head || 0) + 1) % MAX_PATTERNS_PER_IP;
      } else {
        patterns.push(pattern);
      }
    } catch (error) {
      this.logger.log(
        'error',
        `Error analyzing request pattern: ${error.message}`
      );
    }
  }

  checkRequestPatternAnomaly(ip) {
    try {
      const patterns = this.requestPatterns.get(ip);
      if (!patterns || patterns.length < 10) return 0;

      let anomalyScore = 0;

      const pathCounts = new Map();
      patterns.forEach((p) => {
        pathCounts.set(p.path, (pathCounts.get(p.path) || 0) + 1);
      });

      const maxPathCount = Math.max(...pathCounts.values());
      if (maxPathCount > patterns.length * 0.8) {
        anomalyScore += 15;
      }

      const timeGaps = [];
      for (let i = 1; i < patterns.length; i++) {
        timeGaps.push(patterns[i].timestamp - patterns[i - 1].timestamp);
      }

      const avgGap = timeGaps.reduce((a, b) => a + b, 0) / timeGaps.length;
      if (avgGap < 100) {
        anomalyScore += 20;
      }

      const headerPatterns = new Set(patterns.map((p) => p.headers));
      if (headerPatterns.size === 1 && patterns.length > 10) {
        anomalyScore += 10;
      }

      return anomalyScore;
    } catch (error) {
      this.logger.log(
        'error',
        `Error checking request pattern anomaly: ${error.message}`
      );
      return 0;
    }
  }

  updateAnomalyScore(ip, score) {
    try {
      const currentScore = this.anomalyScores.get(ip) || 0;
      const newScore = Math.min(currentScore + score, 1000);
      this.anomalyScores.set(ip, newScore);
      // decay is handled by the periodic updateAnomalyScores() job — no per-request timers
    } catch (error) {
      this.logger.log(
        'error',
        `Error updating anomaly score: ${error.message}`
      );
    }
  }

  isSlowRequest(req) {
    return (
      req.headers['content-length'] &&
      parseInt(req.headers['content-length']) > 0 &&
      req.socket.bytesRead < parseInt(req.headers['content-length'])
    );
  }

  isPathRateLimitExceeded(path, ip, now) {
    const config = this.config.ddosProtection.config.rateLimitByPath;
    if (!this._pathCounters) this._pathCounters = new Map();
    if (this._pathCounters.size >= MAX_PATH_COUNTER_KEYS) {
      this.evictOldestPathCounters(now);
    }
    for (const [pattern, limit] of Object.entries(config)) {
      if (!this.matchPath(path, pattern)) continue;
      const pathKey = `${ip}:${pattern}`;
      const bucket = this._pathCounters.get(pathKey) || [];
      const recent = bucket.filter((t) => now - t < 60000);
      recent.push(now);
      this._pathCounters.set(pathKey, recent);
      if (recent.length > limit) return true;
    }
    return false;
  }

  evictOldestPathCounters(now) {
    if (!this._pathCounters || this._pathCounters.size < MAX_PATH_COUNTER_KEYS) return;
    const byOldest = [];
    for (const [key, bucket] of this._pathCounters) {
      const times = bucket.filter((t) => now - t < 60000);
      const oldestInBucket = times.length > 0 ? Math.min(...times) : now;
      byOldest.push({ key, oldest: oldestInBucket });
    }
    byOldest.sort((a, b) => a.oldest - b.oldest);
    const toRemove = Math.ceil(MAX_PATH_COUNTER_KEYS * 0.1);
    for (let i = 0; i < toRemove && i < byOldest.length; i++) {
      this._pathCounters.delete(byOldest[i].key);
    }
  }

  matchPath(path, pattern) {
    if (pattern === '*') return true;
    if (pattern.endsWith('/*')) {
      const prefix = pattern.slice(0, -2);
      return path.startsWith(prefix);
    }
    return path === pattern;
  }

  getStats(ip) {
    if (!this.connectionStats.has(ip)) {
      this.connectionStats.set(ip, {
        requests: [],
        slowRequests: 0,
        lastRequest: Date.now(),
        totalRequests: 0
      });
    }
    return this.connectionStats.get(ip);
  }

  checkInstantLoad() {
    try {
      const now = Date.now();
      let totalConnections = 0;
      let suspiciousIPs = new Set();

      for (const [ip, stats] of this.connectionStats) {
        const recentRequests = stats.requests.filter(
          (time) => now - time < 1000
        ).length;
        totalConnections += recentRequests;

        if (recentRequests > this.thresholds.maxRequestsPerSecond) {
          suspiciousIPs.add(ip);
        }
      }

      if (totalConnections > this.thresholds.maxRequestsPerSecond * 10) {
        this.logger.log('warning', 'System under heavy load', {
          totalConnections,
          suspiciousIPs: Array.from(suspiciousIPs)
        });

        for (const ip of suspiciousIPs) {
          if (!this.blockedIPs.has(ip)) {
            this.handleAttack(ip, null, 100, null);
          }
        }
      }
    } catch (error) {
      this.logger.log('error', `Error checking instant load: ${error.message}`);
    }
  }

  cleanupData() {
    try {
      const ddosConfig = this.config?.ddosProtection?.config || {
        timeWindow: 60000,
        blockDuration: 3600000
      };

      const now = Date.now();
      const timeWindow = ddosConfig.timeWindow || 60000;

      for (const [ip, stats] of this.connectionStats) {
        if (now - (stats.lastRequest || now) > timeWindow * 2) {
          this.connectionStats.delete(ip);
          this.requestPatterns.delete(ip);
          this.anomalyScores.delete(ip);
        } else {
          stats.requests = stats.requests.filter(
            (time) => now - time < timeWindow
          );
        }
      }

      // purge expired block entries (Map<ip, expiryTs>)
      for (const [ip, expiry] of this.blockedIPs) {
        if (now >= expiry) this.blockedIPs.delete(ip);
      }

      // purge path rate-limit buckets
      if (this._pathCounters) {
        for (const [key, bucket] of this._pathCounters) {
          const fresh = bucket.filter((t) => now - t < 60000);
          if (fresh.length === 0) {
            this._pathCounters.delete(key);
          } else {
            this._pathCounters.set(key, fresh);
          }
        }
      }

      for (const [ip, history] of this.blockHistory) {
        const cleanHistory = history.filter(
          (entry) => now - entry.timestamp < 24 * 60 * 60 * 1000
        );

        if (cleanHistory.length === 0) {
          this.blockHistory.delete(ip);
        } else {
          this.blockHistory.set(ip, cleanHistory);
        }
      }

      this.lastCleanup = now;
    } catch (error) {
      this.logger.log('error', `Error cleaning up data: ${error.message}`, {
        configExists: !!this.config,
        ddosConfigExists: !!this.config?.ddosProtection,
        stackTrace: error.stack
      });
    }
  }

  updateAnomalyScores() {
    try {
      const now = Date.now();
      for (const [ip, score] of this.anomalyScores) {
        if (score > 0) {
          const newScore = Math.max(0, score * 0.8);
          this.anomalyScores.set(ip, newScore);
        }
      }
    } catch (error) {
      this.logger.log(
        'error',
        `Error updating anomaly scores: ${error.message}`
      );
    }
  }

  isBlocked(ip) {
    const expiry = this.blockedIPs.get(ip);
    if (expiry === undefined) return false;
    if (Date.now() < expiry) return true;
    // lazily remove expired entries
    this.blockedIPs.delete(ip);
    return false;
  }
}

module.exports = DDoSProtection;
