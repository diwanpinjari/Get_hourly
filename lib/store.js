const { run, get } = require('./data');

async function createSession(db, token, role, userId, expiresAt, options = {}) {
    await run(db, `INSERT INTO app_sessions (token, role, user_id, dept_id, meta, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [token, role, userId, options.deptId ?? null, options.meta ?? null, expiresAt]);
}

async function getSession(db, token) {
    if (!token) return null;
    const row = await get(db, `SELECT token, role, user_id, dept_id, meta, expires_at
        FROM app_sessions WHERE token = ? AND expires_at > ?`, [token, Date.now()]);
    return row || null;
}

async function deleteSession(db, token) {
    if (token) await run(db, 'DELETE FROM app_sessions WHERE token = ?', [token]);
}

async function setOtp(db, email, purpose, otp, expiresAt, deptId = null) {
    await run(db, `INSERT INTO otp_codes (email, purpose, otp, dept_id, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(email, purpose) DO UPDATE SET otp = excluded.otp, dept_id = excluded.dept_id, expires_at = excluded.expires_at`,
        [email, purpose, otp, deptId, expiresAt]);
}

async function takeOtp(db, email, purpose) {
    const row = await get(db, 'SELECT otp, dept_id, expires_at FROM otp_codes WHERE email = ? AND purpose = ?', [email, purpose]);
    if (!row) return null;
    await run(db, 'DELETE FROM otp_codes WHERE email = ? AND purpose = ?', [email, purpose]);
    if (Date.now() > row.expires_at) return null;
    return row;
}

async function hitRateLimit(db, key, limit, windowMs) {
    const now = Date.now();
    const existing = await get(db, 'SELECT count, expires_at FROM rate_limits WHERE key = ?', [key]);
    if (!existing || existing.expires_at < now) {
        await run(db, `INSERT INTO rate_limits (key, count, expires_at) VALUES (?, 1, ?)
            ON CONFLICT(key) DO UPDATE SET count = 1, expires_at = excluded.expires_at`, [key, now + windowMs]);
        return true;
    }
    const count = existing.count + 1;
    await run(db, 'UPDATE rate_limits SET count = ? WHERE key = ?', [count, key]);
    return count <= limit;
}

async function cleanup(db) {
    const now = Date.now();
    await Promise.all([
        run(db, 'DELETE FROM app_sessions WHERE expires_at < ?', [now]),
        run(db, 'DELETE FROM otp_codes WHERE expires_at < ?', [now]),
        run(db, 'DELETE FROM rate_limits WHERE expires_at < ?', [now]),
        // Keep only the last 30 days of classroom photos used by the daily email.
        run(db, 'DELETE FROM attendance_photos WHERE created_at < ?', [now - 30 * 24 * 60 * 60 * 1000])
    ]).catch(() => {});
}

module.exports = { createSession, getSession, deleteSession, setOtp, takeOtp, hitRateLimit, cleanup };
