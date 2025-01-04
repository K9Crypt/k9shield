class Security {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.blacklist = new Set();
        this.whitelist = new Set();
        this.tempBlockList = new Map();
        this.blockHistory = new Map();
        this.lastAttackTimestamps = new Map();
        this.attackPatterns = new Map();

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
                /encodeURI/i,
                /decodeURI/i,
                /atob\s*\(/i,
                /btoa\s*\(/i
            ]),
            pathTraversal: new Set([
                /\.\.\/+/g,
                /\/\.\.\/+/g,
                /\.\.\\/g,
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
                /\|\s*[\w\-]+/,
                /;\s*[\w\-]+/,
                /`[\s\S]*?`/,
                /\$\([^)]+\)/,
                /&\s*[\w\-]+/,
                />\s*[\w\-]+/,
                /<\s*[\w\-]+/,
                /\|\|\s*[\w\-]+/,
                /&&\s*[\w\-]+/,
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
                /127\.0\.0\.1/,
                /localhost/i,
                /0\.0\.0\.0/,
                /::1/,
                /0:0:0:0:0:0:0:1/,
                /internal\./i,
                /private\./i,
                /example\./i,
                /test\./i,
                /dev\./i,
                /staging\./i,
                /prod\./i,
                /admin\./i,
                /intranet\./i,
                /corporate\./i
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
            maxSuspiciousPatterns: 3,
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
        setInterval(() => this.cleanupTempBlocks(), 5 * 60 * 1000);
        setInterval(() => this.resetAttackStats(), 60 * 60 * 1000);
    }

    checkRequestMethod(req, res, ip) {
        if (!this.config.security.allowedMethods.includes(req.method)) {
            this.incrementAttackScore(ip, this.thresholds.suspiciousPatternScore);
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

        const tempBlock = this.tempBlockList.get(ip);
        if (tempBlock && tempBlock.expiry > Date.now()) {
            this.logger.log('blocked', `Blocked request from temporarily blocked IP ${ip}`, req);
            return true;
        }

        return false;
    }

    isWhitelisted(ip) {
        return Array.from(this.whitelist).some(whitelistEntry => this.matchIP(ip, whitelistEntry));
    }

    checkPayloadSize(req, res, ip) {
        if (req.headers['content-length'] > this.config.security.maxBodySize) {
            this.incrementAttackScore(ip, this.thresholds.suspiciousPatternScore);
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
                this.incrementAttackScore(ip, this.thresholds.suspiciousPatternScore);
                this.logger.log('warning', `Request string too long from ${ip}`, req);
                return true;
            }

            let totalScore = 0;
            const detectedPatterns = new Set();

            for (const pattern of this.suspiciousPatterns) {
                try {
                    if (pattern.test(checkString)) {
                        totalScore += this.thresholds.suspiciousPatternScore;
                        detectedPatterns.add(pattern.toString());
                    }
                } catch (e) {
                    this.logger.log('warning', `Pattern test error: ${e.message}`, req);
                }
            }

            for (const [category, patterns] of Object.entries(this.advancedPatterns)) {
                for (const pattern of patterns) {
                    try {
                        if (pattern.test(checkString)) {
                            totalScore += this.thresholds.maliciousPatternScore;
                            detectedPatterns.add(`${category}:${pattern.toString()}`);
                        }
                    } catch (e) {
                        this.logger.log('warning', `Advanced pattern test error in ${category}: ${e.message}`, req);
                    }
                }
            }

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

            return false;
        } catch (e) {
            this.logger.log('error', `Pattern checking error: ${e.message}`, req);
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
        const lastTimestamp = this.lastAttackTimestamps.get(ip) || 0;
        
        if (now - lastTimestamp < 60000) {
            const currentScore = this.attackPatterns.get(ip)?.length || 0;
            if (currentScore + score >= this.thresholds.maxAttemptsPerMinute) {
                this.blacklist.add(ip);
                this.logger.log('banned', `IP ${ip} permanently banned due to high attack score`);
            }
        }
        
        this.lastAttackTimestamps.set(ip, now);
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

    createCheckString(req) {
        try {
            const headersToCheck = Object.keys(req.headers).filter(header => 
                !this.config.security.requestHeaderWhitelist.includes(header.toLowerCase())
            );

            const filteredHeaders = headersToCheck.reduce((obj, key) => {
                obj[key.toLowerCase()] = req.headers[key];
                return obj;
            }, {});

            const components = [
                req.url,
                typeof req.body === 'string' ? req.body : JSON.stringify(req.body),
                JSON.stringify(filteredHeaders),
                req.query ? JSON.stringify(req.query) : '',
                req.params ? JSON.stringify(req.params) : ''
            ];

            return components.filter(Boolean).join(' ');
        } catch (e) {
            this.logger.log('error', `Error creating check string: ${e.message}`);
            return '';
        }
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
            }
        }
    }

    blockIP(ip) {
        this.blacklist.add(ip);
        this.logger.log('manual', `IP ${ip} manually blocked`);
    }

    unblockIP(ip) {
        this.blacklist.delete(ip);
        this.tempBlockList.delete(ip);
        this.logger.log('manual', `IP ${ip} manually unblocked`);
    }

    whitelistIP(ip) {
        this.whitelist.add(ip);
        this.blacklist.delete(ip);
        this.tempBlockList.delete(ip);
        this.logger.log('manual', `IP ${ip} manually whitelisted`);
    }

    unwhitelistIP(ip) {
        this.whitelist.delete(ip);
        this.logger.log('manual', `IP ${ip} manually unwhitelisted`);
    }

    addSuspiciousPattern(pattern) {
        if (pattern instanceof RegExp) {
            this.suspiciousPatterns.add(pattern);
            this.logger.log('info', `New suspicious pattern added: ${pattern}`);
        } else {
            throw new Error('Pattern must be a RegExp instance');
        }
    }

    reset() {
        this.blacklist.clear();
        this.whitelist.clear();
        this.tempBlockList.clear();
        this.blockHistory.clear();
        this.lastAttackTimestamps.clear();
        this.attackPatterns.clear();
    }
}

module.exports = Security; 