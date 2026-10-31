require('dotenv').config();
const path = require('path');
const { hashPassword } = require('./lib/auth');
const { createDatabase } = require('./lib/db');
const { initializeSchema } = require('./lib/schema');
const { run } = require('./lib/data');

async function main() {
    const [id, name, email] = process.argv.slice(2);
    if (!id || !name || !email || !process.env.ADMIN_PASSWORD) {
        throw new Error('Usage: npm run add-admin -- ID "Full Name" email@example.com (set ADMIN_PASSWORD in environment first).');
    }
    const db = createDatabase({
        url: process.env.TURSO_DATABASE_URL || process.env.LIBSQL_URL,
        authToken: process.env.TURSO_AUTH_TOKEN,
        filename: path.join(process.env.DATA_DIR || __dirname, 'attendance.db')
    });
    try {
        await initializeSchema(db);
        await run(db, `INSERT INTO admin_users (admin_id,name,email,password,role) VALUES (?,?,?,?,'Super Admin')
            ON CONFLICT(admin_id) DO UPDATE SET name=excluded.name,email=excluded.email,password=excluded.password`,
            [id.trim().toUpperCase(), name.trim(), email.trim(), hashPassword(process.env.ADMIN_PASSWORD)]);
        console.log('Administrator saved.');
    } finally {
        db.close();
    }
}
main().catch(err => { console.error(err.message); process.exitCode = 1; });
