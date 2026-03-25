const crypto = require('crypto');

function parseCookies(header) {
  if (typeof header !== 'string' || header.trim() === '') return {};

  return header.split(';').reduce((cookies, part) => {
    const index = part.indexOf('=');
    if (index === -1) return cookies;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!key) return cookies;

    try {
      cookies[key] = decodeURIComponent(value);
    } catch (error) {
      cookies[key] = value;
    }

    return cookies;
  }, {});
}

function safeCompare(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value);
  if (value === undefined || value === null) return Buffer.alloc(0);
  return Buffer.from(JSON.stringify(value));
}

module.exports = {
  parseCookies,
  safeCompare,
  toBuffer
};
