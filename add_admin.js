require('dotenv').config();
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { hashPassword } = require('./lib/auth');
const { run } = require('./lib/data');

async function main() {
    const [id, name, email] = process.argv.slice(2);
    if (!id || !name || !email || !process.env.ADMIN_PASSWORD) {
        throw new Error('Usage: npm run add-admin -- ID "Full Name" email@example.com (set ADMIN_PASSWORD in environment first).');
    }
    const db = new sqlite3.Database(path.join(process.env.DATA_DIR || __dirname, 'attendance.db'));
    try {
        await run(db, `CREATE TABLE IF NOT EXISTS admin_users (
            admin_id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, role TEXT DEFAULT 'Super Admin', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
        await run(db, `INSERT INTO admin_users (admin_id,name,email,password,role) VALUES (?,?,?,?,'Super Admin')
            ON CONFLICT(admin_id) DO UPDATE SET name=excluded.name,email=excluded.email,password=excluded.password`,
            [id.trim().toUpperCase(), name.trim(), email.trim(), hashPassword(process.env.ADMIN_PASSWORD)]);
        console.log('Administrator saved.');
    } finally { db.close(); }
}
main().catch(err => { console.error(err.message); process.exitCode = 1; });
