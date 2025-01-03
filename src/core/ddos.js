class DDoSProtection {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.connections = new Map();
        this.blockedIPs = new Set();
        this.connectionStats = new Map();
        this.blockHistory = new Map();
        this.syncService = null;

        this.init();
    }

    init() {
        setInterval(() => {
            this.cleanupData();
        }, 60000);
    }

    checkAttack(req, res, ip) {
        if (!this.config.ddosProtection.enabled) return false;

        const now = Date.now();
        const stats = this.getStats(ip);

        stats.connections++;
        stats.lastRequest = now;
        stats.requests.push(now);

        stats.requests = stats.requests.filter(time =>
            now - time < this.config.ddosProtection.config.timeWindow
        );

        if (this.isUnderAttack(stats, req)) {
            this.handleAttack(ip, res);
            return true;
        }

        return false;
    }

    isUnderAttack(stats, req) {
        const now = Date.now();

        if (typeof stats.slowRequests !== 'number') {
            stats.slowRequests = 0;
        }

        if (stats.requests.length > this.config.ddosProtection.config.requestThreshold) {
            return true;
        }

        const lastSecondRequests = stats.requests.filter(time =>
            now - time < 1000
        ).length;

        if (lastSecondRequests > this.config.ddosProtection.config.burstThreshold) {
            return true;
        }

        if (req.headers['content-length'] &&
            parseInt(req.headers['content-length']) > 0 &&
            req.socket.bytesRead < parseInt(req.headers['content-length'])) {
            stats.slowRequests++;
            if (stats.slowRequests > this.config.ddosProtection.config.slowRequestThreshold) {
                return true;
            }
        }

        const path = req.path;
        for (const [pattern, limit] of Object.entries(this.config.ddosProtection.config.rateLimitByPath)) {
            if (this.matchPath(path, pattern) && stats.requests.length > limit) {
                return true;
            }
        }

        return false;
    }

    handleAttack(ip, res) {
        this.blockedIPs.add(ip);
        
        const blockCount = (this.blockHistory.get(ip) || 0) + 1;
        this.blockHistory.set(ip, blockCount);
        
        const blockDuration = this.config.ddosProtection.config.blockDuration * Math.pow(2, blockCount - 1);
        
        this.logger.log('attack', `DDoS attack detected from IP ${ip} - Block count: ${blockCount}, Duration: ${blockDuration}ms`);
        
        if (this.syncService) {
            this.syncService.reportAttack(ip, blockDuration);
        }
        
        setTimeout(() => {
            this.blockedIPs.delete(ip);
            this.logger.log('info', `DDoS block removed for IP ${ip}`);
        }, blockDuration);
        
        return {
            message: 'Suspicious traffic pattern detected',
            blockDuration: blockDuration / 1000,
            remainingAttempts: Math.max(0, 3 - blockCount),
            nextBlockDuration: blockDuration * 2 / 1000
        };
    }

    getStats(ip) {
        if (!this.connectionStats.has(ip)) {
            this.connectionStats.set(ip, {
                connections: 0,
                requests: [],
                slowRequests: 0,
                lastRequest: Date.now()
            });
        }
        return this.connectionStats.get(ip);
    }

    cleanupData() {
        const now = Date.now();

        for (const [ip, stats] of this.connectionStats) {
            if (now - stats.lastRequest > this.config.ddosProtection.config.timeWindow * 2) {
                this.connectionStats.delete(ip);
            }
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

    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }
}

module.exports = DDoSProtection; 