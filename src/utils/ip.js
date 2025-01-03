const ipaddr = require('ipaddr.js');

class IPUtils {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
    }

    getClientIP(req) {
        try {
            const possibleIPs = [
                req.ip,
                req.headers['x-real-ip'],
                req.headers['x-forwarded-for']?.split(',')[0].trim(),
                req.connection?.remoteAddress,
                req.socket?.remoteAddress
            ].filter(Boolean);

            let ip = possibleIPs[0] || '127.0.0.1';

            if (ip.includes(':')) {
                try {
                    const addr = ipaddr.parse(ip);
                    if (addr.kind() === 'ipv6') {
                        if (addr.isIPv4MappedAddress()) {
                            ip = addr.toIPv4Address().toString();
                        } else if (ip === '::1') {
                            ip = '127.0.0.1';
                        }
                    }
                } catch (e) {
                    this.logger.log('warning', `IPv6 parsing error: ${e.message}, IP: ${ip}`);
                    return null;
                }
            }

            try {
                const addr = ipaddr.parse(ip);
                const isPrivate = this.isPrivateIP(ip);
                
                if (process.env.NODE_ENV === 'development') {
                    return ip;
                }

                if (isPrivate && !this.config.security.allowPrivateIPs) {
                    this.logger.log('warning', `Private IP blocked: ${ip}`);
                    return null;
                }

                return addr.toString();
            } catch (e) {
                this.logger.log('warning', `Invalid IP address: ${ip}, Error: ${e.message}`);
                return null;
            }
        } catch (e) {
            this.logger.log('error', `IP processing error: ${e.message}`);
            return null;
        }
    }

    isPrivateIP(ip) {
        try {
            const addr = ipaddr.parse(ip);
            return addr.range() === 'private' || 
                   addr.range() === 'loopback' || 
                   addr.range() === 'linkLocal' ||
                   addr.range() === 'uniqueLocal';
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
            this.logger.log('warning', `IP matching error: ${e.message}, IP: ${ip}, Entry: ${entry}`);
            return false;
        }
    }
}

module.exports = IPUtils; 