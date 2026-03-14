const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warning: 2,
  blocked: 3,
  attack: 4,
  ratelimit: 5,
  banned: 6,
  manual: 7,
  throttled: 8,
  userAgentBlocked: 9,
  refererBlocked: 10
};

class Logger {
  constructor(config) {
    this.config = config;
    this.logs = [];
    this.externalLogService = null;
  }

  sanitizeField(value, maxLen = 256) {
    if (typeof value !== 'string') return null;
    // strip CR/LF/ANSI/control chars to prevent log injection
    return value.replace(/[\r\n\t\x00-\x1f\x7f\x1b]/g, ' ').slice(0, maxLen);
  }

  async log(type, message, req = null) {
    if (
      !this.config.logging.enable ||
      LOG_LEVELS[type] < LOG_LEVELS[this.config.logging.level]
    )
      return;

    const isReqObj = req && typeof req === 'object' && req.method && req.path;

    const logEntry = {
      timestamp: new Date().toISOString(),
      type,
      message: this.sanitizeField(String(message), 1024),
      method: isReqObj ? req.method : null,
      path: isReqObj ? this.sanitizeField(req.path) : null,
      userAgent: isReqObj && req.headers ? this.sanitizeField(req.headers['user-agent']) : null,
      referer: isReqObj && req.headers ? this.sanitizeField(req.headers['referer']) : null
    };

    setImmediate(() => {
      this.logs.push(logEntry);

      const suffix = [
        logEntry.method && logEntry.path ? ` (${logEntry.method} ${logEntry.path})` : '',
        logEntry.userAgent ? ` UA: ${logEntry.userAgent}` : '',
        logEntry.referer ? ` Ref: ${logEntry.referer}` : ''
      ].join('');

      console.log(`[K9Shield] ${logEntry.timestamp} - ${type}: ${logEntry.message}${suffix}`);

      if (this.logs.length >= this.config.logging.maxLogSize) {
        this.rotateAndArchiveLogs().catch((error) => {
          console.error('Log rotation error:', error);
        });
      }
    });

    if (this.externalLogService) {
      this.externalLogService.log(logEntry).catch((error) => {
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

        if (
          this.config.logging.archives.length > this.config.logging.archiveLimit
        ) {
          const excessArchives = this.config.logging.archives.splice(
            this.config.logging.archiveLimit
          );

          if (this.logArchiveStore && excessArchives.length > 0) {
            this.logArchiveStore
              .archiveOldLogs(excessArchives)
              .catch((error) => {
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
