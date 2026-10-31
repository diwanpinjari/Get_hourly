require('dotenv').config();
const path = require('path');
const { createDatabase } = require('../lib/db');
const { initializeSchema } = require('../lib/schema');
const { all } = require('../lib/data');

const TABLES = [
    ['branches', ['id', 'name']],
    ['departments', ['id', 'name', 'branch_id', 'doe_name', 'doe_email']],
    ['batch_years', ['id', 'name', 'branch_id']],
    ['sections', ['id', 'name', 'branch_id', 'dept_id', 'batch_year_id']],
    ['faculty', ['faculty_id', 'name', 'password', 'created_at']],
    ['mentors', ['mentor_id', 'name', 'email']],
    ['section_mentors', ['id', 'branch_id', 'dept_id', 'batch_year_id', 'section_id', 'mentor_id']],
    ['students', ['roll_number', 'name', 'phone_number', 'parent_number', 'branch_id', 'dept_id', 'batch_year_id', 'section_id']],
    ['attendance_logs', ['id', 'roll_number', 'date', 'hour_slot', 'subject_name', 'status', 'faculty_id', 'faculty_name', 'submission_time', 'branch_id', 'dept_id', 'batch_year_id', 'section_id']],
    ['admin_users', ['admin_id', 'name', 'email', 'password', 'role', 'created_at']]
];

async function main() {
    const remoteUrl = process.env.TURSO_DATABASE_URL || process.env.LIBSQL_URL;
    const remoteToken = process.env.TURSO_AUTH_TOKEN;
    if (!remoteUrl || !remoteToken) {
        throw new Error('Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN before migrating.');
    }

    const localFile = process.env.DATA_DIR
        ? path.join(process.env.DATA_DIR, 'attendance.db')
        : path.join(__dirname, '..', 'attendance.db');
    const local = createDatabase({ filename: localFile });
    const remote = createDatabase({ url: remoteUrl, authToken: remoteToken });

    try {
        await initializeSchema(remote);
        for (const [table, columns] of TABLES) {
            let rows;
            try {
                rows = await all(local, `SELECT ${columns.join(', ')} FROM ${table}`);
            } catch {
                console.log(`Skipping ${table} (not present locally).`);
                continue;
            }
            if (!rows.length) {
                console.log(`${table}: 0 rows`);
                continue;
            }

            const placeholders = columns.map(() => '?').join(', ');
            const sql = `INSERT OR REPLACE INTO ${table} (${columns.join(', ')}) VALUES (${placeholders})`;
            const statements = rows.map(row => ({ sql, args: columns.map(column => row[column] ?? null) }));

            for (let index = 0; index < statements.length; index += 100) {
                await remote.client.batch(statements.slice(index, index + 100), 'write');
            }

            const [{ total }] = await all(remote, `SELECT COUNT(*) AS total FROM ${table}`);
            console.log(`${table}: ${rows.length} copied, ${total} now stored`);
        }
        console.log('Migration complete.');
    } finally {
        local.close();
        remote.close();
    }
}

main().catch(error => {
    console.error('Migration failed:', error.message);
    process.exitCode = 1;
});
