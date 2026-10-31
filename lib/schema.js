const { hashPassword } = require('./auth');

async function initializeSchema(db) {
    await db.run('PRAGMA foreign_keys = ON;').catch(() => {});

    await db.run(`CREATE TABLE IF NOT EXISTS admin_users (
        admin_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'Super Admin',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    if (process.env.ADMIN_PASSWORD) {
        await db.run(`INSERT OR IGNORE INTO admin_users (admin_id, name, email, password, role)
            VALUES ('ADMIN01', 'System Administrator', ?, ?, 'Super Admin')`,
            [process.env.ADMIN_EMAIL || 'admin@college.edu', hashPassword(process.env.ADMIN_PASSWORD)]);
    }

    await db.run(`CREATE TABLE IF NOT EXISTS branches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        branch_id INTEGER NOT NULL,
        doe_name TEXT DEFAULT '',
        doe_email TEXT DEFAULT '',
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        UNIQUE(name, branch_id)
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS batch_years (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        branch_id INTEGER NOT NULL,
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        UNIQUE(name, branch_id)
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS sections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        branch_id INTEGER NOT NULL,
        dept_id INTEGER NOT NULL,
        batch_year_id INTEGER NOT NULL,
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        FOREIGN KEY(dept_id) REFERENCES departments(id) ON DELETE CASCADE,
        FOREIGN KEY(batch_year_id) REFERENCES batch_years(id) ON DELETE CASCADE,
        UNIQUE(name, branch_id, dept_id, batch_year_id)
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS faculty (
        faculty_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS mentors (
        mentor_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS section_mentors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        branch_id INTEGER NOT NULL,
        dept_id INTEGER NOT NULL,
        batch_year_id INTEGER NOT NULL,
        section_id INTEGER NOT NULL,
        mentor_id INTEGER NOT NULL,
        UNIQUE(branch_id, dept_id, batch_year_id, section_id),
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        FOREIGN KEY(dept_id) REFERENCES departments(id) ON DELETE CASCADE,
        FOREIGN KEY(batch_year_id) REFERENCES batch_years(id) ON DELETE CASCADE,
        FOREIGN KEY(section_id) REFERENCES sections(id) ON DELETE CASCADE,
        FOREIGN KEY(mentor_id) REFERENCES mentors(mentor_id) ON DELETE CASCADE
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS students (
        roll_number TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        phone_number TEXT DEFAULT '',
        parent_number TEXT DEFAULT '',
        branch_id INTEGER,
        dept_id INTEGER,
        batch_year_id INTEGER,
        section_id INTEGER,
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE SET NULL,
        FOREIGN KEY(dept_id) REFERENCES departments(id) ON DELETE SET NULL,
        FOREIGN KEY(batch_year_id) REFERENCES batch_years(id) ON DELETE SET NULL,
        FOREIGN KEY(section_id) REFERENCES sections(id) ON DELETE SET NULL
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS attendance_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_number TEXT NOT NULL,
        date TEXT NOT NULL,
        hour_slot TEXT NOT NULL,
        subject_name TEXT NOT NULL,
        status TEXT NOT NULL,
        faculty_id TEXT NOT NULL,
        faculty_name TEXT NOT NULL,
        submission_time TEXT DEFAULT '',
        branch_id INTEGER,
        dept_id INTEGER,
        batch_year_id INTEGER,
        section_id INTEGER,
        UNIQUE(roll_number, date, hour_slot)
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS app_sessions (
        token TEXT PRIMARY KEY,
        role TEXT NOT NULL,
        user_id TEXT NOT NULL,
        dept_id INTEGER,
        meta TEXT,
        expires_at INTEGER NOT NULL
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS otp_codes (
        email TEXT NOT NULL,
        purpose TEXT NOT NULL,
        otp TEXT NOT NULL,
        dept_id INTEGER,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (email, purpose)
    )`);

    await db.run(`CREATE TABLE IF NOT EXISTS rate_limits (
        key TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )`);

    // Column migrations for databases created by older versions.
    for (const statement of [
        `ALTER TABLE departments ADD COLUMN doe_name TEXT DEFAULT ''`,
        `ALTER TABLE departments ADD COLUMN doe_email TEXT DEFAULT ''`,
        `ALTER TABLE attendance_logs ADD COLUMN submission_time TEXT DEFAULT ''`
    ]) {
        await db.run(statement).catch(() => {});
    }
}

module.exports = { initializeSchema };
