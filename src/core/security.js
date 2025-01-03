class Security {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.blacklist = new Set();
        this.whitelist = new Set();
        this.suspiciousPatterns = new Set([
            /union\s+select/i,
            /script>/i,
            /(\/\.\.)|(\.\.\/)/,
            /<[^>]*>/
        ]);
        this.advancedPatterns = {
            sql: new Set([
                /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
                /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
                /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
                /((\%27)|(\'))union/i,
                /exec(\s|\+)+(s|x)p\w+/i,
                /UNION(?:\s+ALL)?\s+SELECT/i
            ]),
            xss: new Set([
                /<script[^>]*>[\s\S]*?<\/script>/i,
                /javascript:[^\n]*/i,
                /onerror\s*=\s*["\'][^"\']*["\']|onclick|onload|onmouseover/i,
                /<img[^>]+src[^>]*>/i,
                /data:text\/html[^>]*,/i
            ]),
            pathTraversal: new Set([
                /\.\.\/+/g,
                /\/\.\.\/+/g,
                /\.\.\\/g,
                /\%2e\%2e\%2f/i,
                /\%252e\%252e\%252f/i
            ]),
            commandInjection: new Set([
                /\|\s*[\w\-]+/,
                /;\s*[\w\-]+/,
                /`[\s\S]*?`/,
                /\$\([^)]+\)/
            ])
        };
    }

    checkRequestMethod(req, res, ip) {
        if (!this.config.security.allowedMethods.includes(req.method)) {
            this.logger.log('warning', `Invalid method ${req.method} from ${ip}`, req);
            return false;
        }
        return true;
    }

    isBlacklisted(req, res, ip) {
        if (Array.from(this.blacklist).some(blacklistEntry => this.matchIP(ip, blacklistEntry))) {
            this.logger.log('blocked', `Blocked request from blacklisted IP ${ip}`, req);
            return true;
        }
        return false;
    }

    isWhitelisted(ip) {
        return Array.from(this.whitelist).some(whitelistEntry => this.matchIP(ip, whitelistEntry));
    }

    checkPayloadSize(req, res, ip) {
        if (req.headers['content-length'] > this.config.security.maxBodySize) {
            this.logger.log('warning', `Payload too large from ${ip}`, req);
            return false;
        }
        return true;
    }

    hasSuspiciousPatterns(req, res, ip) {
        try {
            const checkString = this.createCheckString(req);
            if (!checkString) return false;

            if (checkString.length > 50000) {
                this.logger.log('warning', `Request string too long from ${ip}`, req);
                return true;
            }

            const basicPatternMatch = Array.from(this.suspiciousPatterns).some(pattern => {
                try {
                    return pattern.test(checkString.substring(0, 50000));
                } catch (e) {
                    this.logger.log('warning', `Invalid pattern test: ${pattern}`, req);
                    return false;
                }
            });

            if (basicPatternMatch) {
                this.logger.log('attack', `Basic suspicious pattern detected from ${ip}`, req);
                return true;
            }

            return this.checkAdvancedPatterns(req);
        } catch (e) {
            this.logger.log('error', `Error in pattern checking: ${e.message}`, req);
            return true;
        }
    }

    checkAdvancedPatterns(req) {
        const checkString = this.createCheckString(req);
        if (!checkString || checkString.length > 50000) return true;

        const sample = checkString.substring(0, 50000);
        let matchFound = false;

        for (const [category, patterns] of Object.entries(this.advancedPatterns)) {
            for (const pattern of patterns) {
                try {
                    if (pattern.test(sample)) {
                        this.logger.log('attack', `Detected ${category} attack pattern`);
                        matchFound = true;
                        break;
                    }
                } catch (e) {
                    this.logger.log('error', `Pattern matching error in ${category}: ${e.message}`);
                    continue;
                }
            }
            if (matchFound) break;
        }

        return matchFound;
    }

    createCheckString(req) {
        const headersToCheck = Object.keys(req.headers).filter(header => 
            !this.config.security.requestHeaderWhitelist.includes(header)
        );
        const filteredHeaders = headersToCheck.reduce((obj, key) => {
            obj[key] = req.headers[key];
            return obj;
        }, {});

        return [
            req.url,
            JSON.stringify(req.body),
            JSON.stringify(filteredHeaders)
        ].join(' ');
    }

    isUserAgentBlacklisted(req, res, ip) {
        const userAgent = req.headers['user-agent'];
        if (userAgent && this.config.security.userAgentBlacklist.some(pattern => 
            new RegExp(pattern).test(userAgent)
        )) {
            this.logger.log('userAgentBlocked', 
                `Blocked request from IP ${ip} due to blacklisted User-Agent: ${userAgent}`, req);
            this.blockIP(ip);
            return true;
        }
        return false;
    }

    isRefererBlacklisted(req, res, ip) {
        const referer = req.headers['referer'];
        if (referer && this.config.security.refererBlacklist.some(pattern => 
            new RegExp(pattern).test(referer)
        )) {
            this.logger.log('refererBlocked', 
                `Blocked request from IP ${ip} due to blacklisted Referer: ${referer}`, req);
            this.blockIP(ip);
            return true;
        }
        return false;
    }

    blockIP(ip) {
        this.blacklist.add(ip);
        this.logger.log('manual', `IP ${ip} manually blocked`);
    }

    unblockIP(ip) {
        this.blacklist.delete(ip);
        this.logger.log('manual', `IP ${ip} manually unblocked`);
    }

    whitelistIP(ip) {
        this.whitelist.add(ip);
        this.logger.log('manual', `IP ${ip} manually whitelisted`);
    }

    unwhitelistIP(ip) {
        this.whitelist.delete(ip);
        this.logger.log('manual', `IP ${ip} manually unwhitelisted`);
    }

    addSuspiciousPattern(pattern) {
        this.suspiciousPatterns.add(pattern);
    }

    reset() {
        this.blacklist.clear();
        this.whitelist.clear();
    }
}

module.exports = Security; 