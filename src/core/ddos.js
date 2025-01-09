class DDoSProtection {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.connections = new Map();
        this.blockedIPs = new Set();
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
            const stats = this.getStats(ip);
            let anomalyScore = 0;

            stats.connections++;
            stats.lastRequest = now;
            stats.requests.push(now);
            stats.totalRequests = (stats.totalRequests || 0) + 1;

            this.analyzeRequestPattern(ip, req);

            const recentRequests = stats.requests.filter(time => now - time < 1000);
            if (recentRequests.length > this.thresholds.maxRequestsPerSecond) {
                anomalyScore += 30;
            }

            const minuteRequests = stats.requests.filter(time => now - time < 60000);
            if (minuteRequests.length > this.thresholds.maxRequestsPerMinute) {
                anomalyScore += 20;
            }

            if (stats.connections > this.thresholds.maxConcurrentConnections) {
                anomalyScore += 15;
            }

            const contentLength = parseInt(req.headers['content-length']) || 0;
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

            if (this.isPathRateLimitExceeded(req.path, stats)) {
                this.handleAttack(ip, res, anomalyScore, req);
                return true;
            }

            this.connectionStats.set(ip, stats);
            return false;
        } catch (error) {
            this.logger.log('error', `Error in DDoS check: ${error.message}`);
            return false;
        }
    }

    isUnderAttack(stats, req) {
        const now = Date.now();

        const recentRequests = stats.requests.filter(time => now - time < 1000).length;
        if (recentRequests > this.thresholds.maxRequestsPerSecond) {
            return true;
        }

        const minuteRequests = stats.requests.filter(time => now - time < 60000).length;
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
            this.blockedIPs.add(ip);
            
            const blockCount = (this.blockHistory.get(ip) || []).length + 1;
            const blockDuration = Math.min(
                this.config.ddosProtection.config.blockDuration * Math.pow(this.thresholds.blockDurationMultiplier, blockCount - 1),
                this.thresholds.maxBlockDuration
            );
            
            const history = this.blockHistory.get(ip) || [];
            history.push({
                timestamp: Date.now(),
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
            
            this.logger.log('warning', `DDoS attack blocked`, req);
            
            setTimeout(() => {
                this.blockedIPs.delete(ip);
                this.logger.log('info', `DDoS block removed for IP ${ip}`, req);
            }, blockDuration);
            
            return {
                message: 'Suspicious traffic pattern detected',
                blockDuration: blockDuration / 1000,
                remainingAttempts: Math.max(0, 3 - blockCount),
                nextBlockDuration: blockDuration * this.thresholds.blockDurationMultiplier / 1000,
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
            patterns.push(pattern);

            if (patterns.length > 100) {
                patterns.shift();
            }

            this.requestPatterns.set(ip, patterns);
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
            patterns.forEach(p => {
                pathCounts.set(p.path, (pathCounts.get(p.path) || 0) + 1);
            });

            const maxPathCount = Math.max(...pathCounts.values());
            if (maxPathCount > patterns.length * 0.8) {
                anomalyScore += 15;
            }

            const timeGaps = [];
            for (let i = 1; i < patterns.length; i++) {
                timeGaps.push(patterns[i].timestamp - patterns[i-1].timestamp);
            }

            const avgGap = timeGaps.reduce((a, b) => a + b, 0) / timeGaps.length;
            if (avgGap < 100) {
                anomalyScore += 20;
            }

            const headerPatterns = new Set(patterns.map(p => p.headers));
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

            setTimeout(() => {
                const score = this.anomalyScores.get(ip);
                if (score) {
                    this.anomalyScores.set(ip, Math.max(0, score - 10));
                }
            }, 60000);
        } catch (error) {
            this.logger.log('error', `Error updating anomaly score: ${error.message}`);
        }
    }

    isSlowRequest(req) {
        return req.headers['content-length'] &&
               parseInt(req.headers['content-length']) > 0 &&
               req.socket.bytesRead < parseInt(req.headers['content-length']);
    }

    isPathRateLimitExceeded(path, stats) {
        const config = this.config.ddosProtection.config.rateLimitByPath;
        for (const [pattern, limit] of Object.entries(config)) {
            if (this.matchPath(path, pattern) && stats.requests.length > limit) {
                return true;
            }
        }
        return false;
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
                connections: 0,
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
                const recentRequests = stats.requests.filter(time => now - time < 1000).length;
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
                    stats.requests = stats.requests.filter(time => now - time < timeWindow);
                }
            }

            for (const [ip, history] of this.blockHistory) {
                const cleanHistory = history.filter(entry => 
                    now - entry.timestamp < 24 * 60 * 60 * 1000
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
            this.logger.log('error', `Error updating anomaly scores: ${error.message}`);
        }
    }

    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }
}

module.exports = DDoSProtection; 