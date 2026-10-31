const crypto = require('crypto');
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    return `scrypt$${salt}$${crypto.scryptSync(password, salt, 64).toString('hex')}`;
}
function verifyPassword(password, stored) {
    if (typeof password !== 'string' || typeof stored !== 'string') return false;
    if (!stored.startsWith('scrypt$')) return false;
    const [, salt, hash] = stored.split('$');
    const expected = Buffer.from(hash || '', 'hex');
    const actual = crypto.scryptSync(password, salt, 64);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}
module.exports = { hashPassword, verifyPassword };
