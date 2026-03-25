const ipaddr = require('ipaddr.js');

class IPUtils {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
  }

  stripPort(raw) {
    if (typeof raw !== 'string') return raw;
    const trimmed = raw.trim();
    if (trimmed.startsWith('[')) {
      const bracketEnd = trimmed.indexOf(']');
      return bracketEnd > -1 ? trimmed.slice(1, bracketEnd) : trimmed;
    }
    const colonCount = (trimmed.match(/:/g) || []).length;
    if (colonCount === 1 && trimmed.includes('.')) {
      return trimmed.slice(0, trimmed.lastIndexOf(':'));
    }
    return trimmed;
  }

  normalizeIP(raw) {
    if (!raw) return null;
    try {
      const cleaned = this.stripPort(raw);
      const addr = ipaddr.parse(cleaned.trim());
      if (addr.kind() === 'ipv6') {
        if (addr.isIPv4MappedAddress()) return addr.toIPv4Address().toString();
        if (cleaned.trim() === '::1') return '127.0.0.1';
      }
      return addr.toString();
    } catch (error) {
      return null;
    }
  }

  isPeerTrusted(peerIP) {
    const trustedProxies = this.config.security.trustedProxies || [];
    if (trustedProxies.length === 0) return false;
    for (const entry of trustedProxies) {
      if (this.matchIP(peerIP, entry)) return true;
    }
    return false;
  }

  getClientIP(req) {
    try {
      const peerRaw = req.socket?.remoteAddress || req.connection?.remoteAddress || null;
      const peerIP = this.normalizeIP(peerRaw);

      if (this.config.security.trustProxy && peerIP && this.isPeerTrusted(peerIP)) {
        const xff = req.headers['x-forwarded-for'];
        if (xff) {
          const chain = xff
            .split(',')
            .map((segment) => this.normalizeIP(segment))
            .filter(Boolean)
            .reverse();
          for (const hopIP of chain) {
            if (!this.isPeerTrusted(hopIP)) return hopIP;
          }
        }

        const xri = req.headers['x-real-ip'];
        if (xri) {
          const realIP = this.normalizeIP(xri);
          if (realIP) return realIP;
        }
      }

      if (peerIP) {
        if (this.isPrivateIP(peerIP) && !this.config.security.allowPrivateIPs) {
          if (process.env.NODE_ENV !== 'development' && process.env.NODE_ENV !== 'test') {
            this.logger.log('warning', `Private IP blocked: ${peerIP}`);
            return null;
          }
        }
        return peerIP;
      }

      const fallback = this.normalizeIP(req.ip);
      if (fallback) return fallback;

      this.logger.log('warning', 'Unable to determine client IP');
      return null;
    } catch (error) {
      this.logger.log('error', `IP processing error: ${error.message}`);
      return null;
    }
  }

  isPrivateIP(ip) {
    try {
      const addr = ipaddr.parse(ip);
      return (
        addr.range() === 'private' ||
        addr.range() === 'loopback' ||
        addr.range() === 'linkLocal' ||
        addr.range() === 'uniqueLocal'
      );
    } catch (error) {
      this.logger.log('warning', `Private IP check error: ${error.message}`);
      return false;
    }
  }

  matchIP(ip, entry) {
    if (!ip || !entry) {
      this.logger.log('debug', 'IP or entry is missing for matching');
      return false;
    }

    try {
      if (typeof entry === 'string') {
        if (entry.includes('/')) {
          const range = ipaddr.parseCIDR(entry);
          const addr = ipaddr.parse(ip);
          return addr.kind() === range[0].kind() && addr.match(range);
        }
        return ipaddr.parse(ip).toString() === ipaddr.parse(entry).toString();
      }
      return false;
    } catch (error) {
      this.logger.log(
        'warning',
        `IP matching error: ${error.message}, IP: ${ip}, Entry: ${entry}`
      );
      return false;
    }
  }

  parseCIDR(entry) {
    if (!entry || typeof entry !== 'string' || !entry.includes('/')) return null;
    try {
      return ipaddr.parseCIDR(entry.trim());
    } catch (error) {
      return null;
    }
  }

  matchIPInParsedRanges(ip, parsedRanges) {
    if (!ip || !Array.isArray(parsedRanges) || parsedRanges.length === 0) return false;
    try {
      const addr = ipaddr.parse(ip);
      for (const range of parsedRanges) {
        const parsed = Array.isArray(range) ? range : range?.parsed;
        if (!parsed || !Array.isArray(parsed)) continue;
        try {
          if (addr.kind() === parsed[0].kind() && addr.match(parsed)) return true;
        } catch (error) {
          continue;
        }
      }
      return false;
    } catch (error) {
      this.logger.log('debug', `matchIPInParsedRanges error: ${error.message}`);
      return false;
    }
  }
}

module.exports = IPUtils;
