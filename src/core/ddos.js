const MAX_TRACKED_IPS = 50000;
const MAX_REQUESTS_PER_IP = 500;
const MAX_PATTERNS_PER_IP = 100;
const MAX_PATH_COUNTER_KEYS = 100000;
const { matchesRoutePattern } = require('../utils/routes');

class DDoSProtection {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.connections = new Map();
    this.blockedIPs = new Map();
    this.connectionStats = new Map();
    this.blockHistory = new Map();
    this.syncService = null;
    this.requestPatterns = new Map();
    this.anomalyScores = new Map();
    this.lastCleanup = Date.now();
    this.thresholds = {
      maxPayloadSize: 1024 * 1024,
      maxHeaderSize: 8192,
      maxUrlLength: 2048,
      anomalyScoreThreshold: 100,
      blockDurationMultiplier: 2,
      maxBlockDuration: 24 * 60 * 60 * 1000
    };

    this.init();
  }

  init() {
    const cleanupTimer = setInterval(() => {
      this.cleanupData();
      this.updateAnomalyScores();
    }, 60000);
    const loadTimer = setInterval(() => {
      this.checkInstantLoad();
    }, 5000);
    if (typeof cleanupTimer.unref === 'function') cleanupTimer.unref();
    if (typeof loadTimer.unref === 'function') loadTimer.unref();
  }

  getRuntimeConfig() {
    const ddosConfig = this.config?.ddosProtection?.config || {};
    return {
      timeWindow: ddosConfig.timeWindow || 60000,
      blockDuration: ddosConfig.blockDuration || 3600000,
      requestThreshold: ddosConfig.requestThreshold || 100,
      burstThreshold: ddosConfig.burstThreshold || 20,
      slowRequestThreshold: ddosConfig.slowRequestThreshold || 5,
      maxConnections: ddosConfig.maxConnections || 100,
      rateLimitByPath: ddosConfig.rateLimitByPath || {}
    };
  }

  checkAttack(req, res, ip) {
    if (!this.config.ddosProtection.enabled) return false;

    try {
      const runtimeConfig = this.getRuntimeConfig();
      const now = Date.now();

      if (!this.connectionStats.has(ip) && this.connectionStats.size >= MAX_TRACKED_IPS) {
        this.evictOldestTrackedIP();
      }

      const stats = this.getStats(ip);
      let anomalyScore = 0;

      stats.lastRequest = now;
      stats.totalRequests = (stats.totalRequests || 0) + 1;
      this.recordRequestTimestamp(stats, now);
      const recentCounts = this.pruneAndCountRequests(stats, now, runtimeConfig.timeWindow);

      this.analyzeRequestPattern(ip, req);

      if (recentCounts.lastSecond > runtimeConfig.burstThreshold) {
        anomalyScore += 30;
      }

      if (recentCounts.windowCount > runtimeConfig.requestThreshold) {
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
        if (stats.slowRequests > runtimeConfig.slowRequestThreshold) {
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

      if (recentCounts.lastSecond > runtimeConfig.maxConnections) {
        this.handleAttack(ip, res, totalScore || anomalyScore || 100, req);
        return true;
      }

      if (this.isPathRateLimitExceeded(req.path, ip, now, runtimeConfig.timeWindow)) {
        this.handleAttack(ip, res, anomalyScore || 50, req);
        return true;
      }

      return false;
    } catch (error) {
      this.logger.log('error', `Error in DDoS check: ${error.message}`);
      return false;
    }
  }

  evictOldestTrackedIP() {
    let oldestIP = null;
    let oldestTime = Infinity;
    for (const [candidateIP, stats] of this.connectionStats) {
      const lastSeen = stats.lastRequest || 0;
      if (lastSeen < oldestTime) {
        oldestTime = lastSeen;
        oldestIP = candidateIP;
      }
    }
    if (oldestIP !== null) {
      this.connectionStats.delete(oldestIP);
      this.requestPatterns.delete(oldestIP);
      this.anomalyScores.delete(oldestIP);
    }
  }

  recordRequestTimestamp(stats, now) {
    if (stats.requests.length >= MAX_REQUESTS_PER_IP) {
      stats.requests.shift();
    }
    stats.requests.push(now);
  }

  pruneAndCountRequests(stats, now, timeWindow) {
    let writeIndex = 0;
    let lastSecond = 0;

    for (let i = 0; i < stats.requests.length; i++) {
      const timestamp = stats.requests[i];
      if (now - timestamp < timeWindow) {
        stats.requests[writeIndex++] = timestamp;
        if (now - timestamp < 1000) lastSecond++;
      }
    }

    stats.requests.length = writeIndex;

    return {
      lastSecond,
      windowCount: writeIndex
    };
  }

  handleAttack(ip, res, score, req) {
    try {
      const now = Date.now();
      const runtimeConfig = this.getRuntimeConfig();
      const blockCount = (this.blockHistory.get(ip) || []).length + 1;
      const blockDuration = Math.min(
        runtimeConfig.blockDuration *
          Math.pow(this.thresholds.blockDurationMultiplier, blockCount - 1),
        this.thresholds.maxBlockDuration
      );

      const newExpiry = now + blockDuration;
      const existingExpiry = this.blockedIPs.get(ip) || 0;
      this.blockedIPs.set(ip, Math.max(existingExpiry, newExpiry));

      const history = this.blockHistory.get(ip) || [];
      history.push({
        timestamp: now,
        duration: blockDuration,
        score,
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
        score
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
      if (patterns.length >= MAX_PATTERNS_PER_IP) {
        patterns[patterns._head || 0] = pattern;
        patterns._head = ((patterns._head || 0) + 1) % MAX_PATTERNS_PER_IP;
      } else {
        patterns.push(pattern);
      }
    } catch (error) {
      this.logger.log('error', `Error analyzing request pattern: ${error.message}`);
    }
  }

  checkRequestPatternAnomaly(ip) {
    try {
      const patterns = this.requestPatterns.get(ip);
      if (!patterns || patterns.length < 10) return 0;

      let anomalyScore = 0;
      const pathCounts = new Map();
      for (const pattern of patterns) {
        pathCounts.set(pattern.path, (pathCounts.get(pattern.path) || 0) + 1);
      }

      const maxPathCount = Math.max(...pathCounts.values());
      if (maxPathCount > patterns.length * 0.8) {
        anomalyScore += 15;
      }

      let totalGap = 0;
      for (let i = 1; i < patterns.length; i++) {
        totalGap += patterns[i].timestamp - patterns[i - 1].timestamp;
      }
      const avgGap = totalGap / (patterns.length - 1);
      if (avgGap < 100) {
        anomalyScore += 20;
      }

      const headerPatterns = new Set(patterns.map((pattern) => pattern.headers));
      if (headerPatterns.size === 1 && patterns.length > 10) {
        anomalyScore += 10;
      }

      return anomalyScore;
    } catch (error) {
      this.logger.log('error', `Error checking request pattern anomaly: ${error.message}`);
      return 0;
    }
  }

  updateAnomalyScore(ip, score) {
    try {
      const currentScore = this.anomalyScores.get(ip) || 0;
      const newScore = Math.min(currentScore + score, 1000);
      this.anomalyScores.set(ip, newScore);
    } catch (error) {
      this.logger.log('error', `Error updating anomaly score: ${error.message}`);
    }
  }

  isSlowRequest(req) {
    return (
      req.headers['content-length'] &&
      parseInt(req.headers['content-length'], 10) > 0 &&
      req.socket.bytesRead < parseInt(req.headers['content-length'], 10)
    );
  }

  isPathRateLimitExceeded(path, ip, now, timeWindow) {
    const config = this.getRuntimeConfig().rateLimitByPath;
    if (!this._pathCounters) this._pathCounters = new Map();
    if (this._pathCounters.size >= MAX_PATH_COUNTER_KEYS) {
      this.evictOldestPathCounters(now);
    }

    for (const [pattern, limit] of Object.entries(config)) {
      if (!this.matchPath(path, pattern)) continue;

      const pathKey = `${ip}:${pattern}`;
      const bucket = this._pathCounters.get(pathKey) || [];
      let writeIndex = 0;
      for (let i = 0; i < bucket.length; i++) {
        if (now - bucket[i] < timeWindow) {
          bucket[writeIndex++] = bucket[i];
        }
      }
      bucket.length = writeIndex;
      bucket.push(now);
      this._pathCounters.set(pathKey, bucket);
      if (bucket.length > limit) return true;
    }
    return false;
  }

  evictOldestPathCounters(now) {
    if (!this._pathCounters || this._pathCounters.size < MAX_PATH_COUNTER_KEYS) return;
    const byOldest = [];
    for (const [key, bucket] of this._pathCounters) {
      let oldest = now;
      for (const timestamp of bucket) {
        if (timestamp < oldest) oldest = timestamp;
      }
      byOldest.push({ key, oldest });
    }
    byOldest.sort((a, b) => a.oldest - b.oldest);
    const toRemove = Math.ceil(MAX_PATH_COUNTER_KEYS * 0.1);
    for (let i = 0; i < toRemove && i < byOldest.length; i++) {
      this._pathCounters.delete(byOldest[i].key);
    }
  }

  matchPath(path, pattern) {
    return matchesRoutePattern(path, pattern);
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
      const runtimeConfig = this.getRuntimeConfig();
      let totalConnections = 0;
      const suspiciousIPs = new Set();

      for (const [ip, stats] of this.connectionStats) {
        const recentCounts = this.pruneAndCountRequests(stats, now, runtimeConfig.timeWindow);
        totalConnections += recentCounts.lastSecond;

        if (recentCounts.lastSecond > runtimeConfig.burstThreshold) {
          suspiciousIPs.add(ip);
        }
      }

      if (totalConnections > runtimeConfig.maxConnections) {
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
      const runtimeConfig = this.getRuntimeConfig();
      const now = Date.now();

      for (const [ip, stats] of this.connectionStats) {
        if (now - (stats.lastRequest || now) > runtimeConfig.timeWindow * 2) {
          this.connectionStats.delete(ip);
          this.requestPatterns.delete(ip);
          this.anomalyScores.delete(ip);
        } else {
          this.pruneAndCountRequests(stats, now, runtimeConfig.timeWindow);
        }
      }

      for (const [ip, expiry] of this.blockedIPs) {
        if (now >= expiry) this.blockedIPs.delete(ip);
      }

      if (this._pathCounters) {
        for (const [key, bucket] of this._pathCounters) {
          let writeIndex = 0;
          for (let i = 0; i < bucket.length; i++) {
            if (now - bucket[i] < runtimeConfig.timeWindow) {
              bucket[writeIndex++] = bucket[i];
            }
          }
          bucket.length = writeIndex;
          if (bucket.length === 0) {
            this._pathCounters.delete(key);
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
      for (const [ip, score] of this.anomalyScores) {
        if (score > 0) {
          this.anomalyScores.set(ip, Math.max(0, score * 0.8));
        }
      }
    } catch (error) {
      this.logger.log('error', `Error updating anomaly scores: ${error.message}`);
    }
  }

  isBlocked(ip) {
    const expiry = this.blockedIPs.get(ip);
    if (expiry === undefined) return false;
    if (Date.now() < expiry) return true;
    this.blockedIPs.delete(ip);
    return false;
  }

  reset() {
    this.connectionStats.clear();
    this.blockedIPs.clear();
    this.blockHistory.clear();
    this.requestPatterns.clear();
    this.anomalyScores.clear();
    if (this._pathCounters) this._pathCounters.clear();
  }
}

module.exports = DDoSProtection;
