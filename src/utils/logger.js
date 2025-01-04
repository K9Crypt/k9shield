const LOG_LEVELS = {
    'info': 1,
    'warning': 2,
    'blocked': 3,
    'attack': 4,
    'ratelimit': 5,
    'banned': 6,
    'manual': 7,
    'throttled': 8,
    'userAgentBlocked': 9,
    'refererBlocked': 10
};

class Logger {
    constructor(config) {
        this.config = config;
        this.logs = [];
        this.externalLogService = null;
    }

    async log(type, message, req = null) {
        if (!this.config.logging.enable || LOG_LEVELS[type] < LOG_LEVELS[this.config.logging.level]) return;

        const logEntry = {
            timestamp: new Date().toISOString(),
            type,
            message,
            method: req ? req.method : null,
            path: req ? req.path : null,
            userAgent: req && req.headers ? req.headers['user-agent'] : null,
            referer: req && req.headers ? req.headers['referer'] : null
        };

        setImmediate(() => {
            this.logs.push(logEntry);
            
            console.log(`[K9Shield] ${logEntry.timestamp} - ${type}: ${message}${req && req.method && req.path ? ` (${req.method} ${req.path})` : ''}${req && req.headers && req.headers['user-agent'] ? ` User-Agent: ${req.headers['user-agent']}` : ''}${req && req.headers && req.headers['referer'] ? ` Referer: ${req.headers['referer']}` : ''}`);
            
            this.rotateAndArchiveLogs().catch(error => {
                console.error('Log rotation error:', error);
            });
        });

        if (this.externalLogService) {
            this.externalLogService.log(logEntry).catch(error => {
                console.error('External logging error:', error);
            });
        }
    }

    async rotateAndArchiveLogs() {
        try {
            if (!Array.isArray(this.logs)) {
                this.logs = [];
                return;
            }

            if (this.logs.length >= this.config.logging.maxLogSize) {
                const archiveTimestamp = new Date().toISOString();
                const logsToArchive = this.logs.slice(0);
                
                this.logs = [];
                
                const archive = {
                    timestamp: archiveTimestamp,
                    logs: logsToArchive,
                    rotationInfo: {
                        totalEntries: logsToArchive.length,
                        maxSize: this.config.logging.maxLogSize
                    }
                };

                if (this.logArchiveStore) {
                    try {
                        await this.logArchiveStore.saveArchive(archive);
                    } catch (error) {
                        console.error('Log archive store error:', error);
                        if (!Array.isArray(this.config.logging.archives)) {
                            this.config.logging.archives = [];
                        }
                        this.config.logging.archives.unshift(archive);
                    }
                } else {
                    if (!Array.isArray(this.config.logging.archives)) {
                        this.config.logging.archives = [];
                    }
                    this.config.logging.archives.unshift(archive);
                }

                if (this.config.logging.archives.length > this.config.logging.archiveLimit) {
                    const excessArchives = this.config.logging.archives.splice(
                        this.config.logging.archiveLimit
                    );
                    
                    if (this.logArchiveStore && excessArchives.length > 0) {
                        this.logArchiveStore.archiveOldLogs(excessArchives).catch(error => {
                            console.error('Error archiving old logs:', error);
                        });
                    }
                }

                setImmediate(() => {
                    this.log('info', `Log rotation performed at ${archiveTimestamp}`);
                });
            }
        } catch (e) {
            console.error('Log rotation failed:', e);
            this.logs = [];
        }
    }

    getLogs() {
        return this.logs;
    }

    getArchivedLogs() {
        return this.config.logging.archives;
    }

    reset() {
        this.logs = [];
    }
}

module.exports = { Logger, LOG_LEVELS };
