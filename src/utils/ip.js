const ipaddr = require('ipaddr.js');

class IPUtils {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
  }

  normalizeIP(raw) {
    if (!raw) return null;
    try {
      const addr = ipaddr.parse(raw.trim());
      if (addr.kind() === 'ipv6') {
        if (addr.isIPv4MappedAddress()) return addr.toIPv4Address().toString();
        if (raw.trim() === '::1') return '127.0.0.1';
      }
      return addr.toString();
    } catch (e) {
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
      const peerRaw =
        req.socket?.remoteAddress ||
        req.connection?.remoteAddress ||
        null;

      const peerIP = this.normalizeIP(peerRaw);

      // only honour forwarded headers when the direct peer is an explicitly trusted proxy
      if (this.config.security.trustProxy && peerIP && this.isPeerTrusted(peerIP)) {
        const xff = req.headers['x-forwarded-for'];
        if (xff) {
          // walk right-to-left; return first untrusted hop
          const chain = xff.split(',').map((s) => s.trim()).reverse();
          for (const hop of chain) {
            const hopIP = this.normalizeIP(hop);
            if (hopIP && !this.isPeerTrusted(hopIP)) return hopIP;
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
          if (process.env.NODE_ENV !== 'development') {
            this.logger.log('warning', `Private IP blocked: ${peerIP}`);
            return null;
          }
        }
        return peerIP;
      }

      // last resort: req.ip set by Express trust proxy chain
      const fallback = this.normalizeIP(req.ip);
      if (fallback) return fallback;

      this.logger.log('warning', 'Unable to determine client IP');
      return null;
    } catch (e) {
      this.logger.log('error', `IP processing error: ${e.message}`);
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
    } catch (e) {
      this.logger.log('warning', `Private IP check error: ${e.message}`);
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
    } catch (e) {
      this.logger.log(
        'warning',
        `IP matching error: ${e.message}, IP: ${ip}, Entry: ${entry}`
      );
      return false;
    }
  }

  /**
   * Parse a CIDR string into [addr, prefixLen]. Returns null if not a valid CIDR.
   * Used to cache parsed CIDRs for O(1) match without re-parsing.
   */
  parseCIDR(entry) {
    if (!entry || typeof entry !== 'string' || !entry.includes('/')) return null;
    try {
      return ipaddr.parseCIDR(entry.trim());
    } catch (e) {
      return null;
    }
  }

  /**
   * Check if IP matches any of the pre-parsed CIDR ranges.
   * parsedRanges: array of [addr, prefixLen] from parseCIDR.
   * Avoids re-parsing on every request (performance).
   */
  matchIPInParsedRanges(ip, parsedRanges) {
    if (!ip || !Array.isArray(parsedRanges) || parsedRanges.length === 0) return false;
    try {
      const addr = ipaddr.parse(ip);
      for (const range of parsedRanges) {
        if (!range || !Array.isArray(range)) continue;
        try {
          if (addr.kind() === range[0].kind() && addr.match(range)) return true;
        } catch (e) {
          // skip invalid range
        }
      }
      return false;
    } catch (e) {
      this.logger.log('debug', `matchIPInParsedRanges error: ${e.message}`);
      return false;
    }
  }
}

module.exports = IPUtils;
