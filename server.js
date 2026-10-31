require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');
const { hashPassword, verifyPassword } = require('./lib/auth');
const { saveAttendance, transaction, run, all } = require('./lib/data');

const app = express();
const PORT = process.env.PORT || 3000;
const dbPath = process.env.DATA_DIR
    ? path.join(process.env.DATA_DIR, 'attendance.db')
    : path.join(__dirname, 'attendance.db');
const db = new sqlite3.Database(dbPath);
db.configure('busyTimeout', 5000);

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const attempts = new Map();
app.use('/api', (req, res, next) => {
    if (/login$|request-otp$|verify-otp$|request-delete-otp$/.test(req.path)) {
        const key = `${req.ip}:${req.path}`;
        let entry = attempts.get(key);
        if (!entry || entry.until < Date.now()) attempts.set(key, entry = { count: 0, until: Date.now() + 10 * 60 * 1000 });
        if (++entry.count > 20) return res.status(429).json({ success: false, message: 'Too many attempts. Retry in ten minutes.' });
    }
    next();
});

function validDate(value) {
    return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
}
app.use('/api', (req, res, next) => {
    if (['POST', 'PUT'].includes(req.method) && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body))) return res.status(400).json({ success: false, message: 'JSON object required.' });
    for (const field of ['name', 'email', 'password', 'username', 'faculty_id', 'admin_id', 'doe_name', 'doe_email', 'otp', 'subjectName']) {
        if (req.body?.[field] !== undefined && typeof req.body[field] !== 'string') return res.status(400).json({ success: false, message: `Invalid ${field}.` });
    }
    const { from_date, to_date } = req.query;
    if ((from_date && !validDate(from_date)) || (to_date && !validDate(to_date)) || (from_date && to_date && from_date > to_date)) return res.status(400).json({ success: false, message: 'Invalid date range.' });
    next();
});

const sessions = new Map();
function issueSession(res, role, user) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { role, user, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
    res.cookie(`${role}_session`, token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 });
}
app.use('/api', (req, res, next) => {
    const role = req.path.startsWith('/admin/') && req.path !== '/admin/login' ? 'admin'
        : (/^\/(faculty\/|attendance\/|students$)/.test(req.path) ? 'faculty' : null);
    if (!role) return next();
    const cookie = (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith(`${role}_session=`));
    const token = cookie?.slice(cookie.indexOf('=') + 1);
    const auth = sessions.get(token);
    if (!auth || auth.role !== role || Date.now() > auth.expiresAt) {
        sessions.delete(token);
        return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
    }
    req.auth = auth;
    if (role === 'admin') req.headers['x-admin-email'] = auth.user.email;
    if (role === 'faculty') {
        if (req.query.faculty_id && req.query.faculty_id !== auth.user.id) return res.status(403).json({ message: 'Faculty access denied.' });
        if (req.body) {
            req.body.facultyId = auth.user.id;
            req.body.facultyName = auth.user.name;
            req.body.faculty_id = auth.user.id;
        }
    }
    const table = role === 'admin' ? 'admin_users' : 'faculty';
    const key = role === 'admin' ? 'admin_id' : 'faculty_id';
    db.get(`SELECT ${key}, name${role === 'admin' ? ', email' : ''} FROM ${table} WHERE ${key}=?`, [auth.user.id], (err, account) => {
        if (err || !account) return res.status(401).json({ success: false, message: 'Account unavailable. Please log in again.' });
        auth.user.name = account.name;
        if (role === 'admin') {
            auth.user.email = account.email;
            req.headers['x-admin-email'] = account.email;
        } else if (req.body) req.body.facultyName = account.name;
        next();
    });
});
app.post('/api/logout', (req, res) => {
    for (const role of ['admin', 'faculty']) {
        const cookie = (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith(`${role}_session=`));
        if (cookie) sessions.delete(cookie.slice(cookie.indexOf('=') + 1));
        res.clearCookie(`${role}_session`);
    }
    res.json({ success: true });
});
app.use('/api', (req, res, next) => {
    if (req.body && typeof req.body.password === 'string' && !['/login', '/admin/login'].includes(req.path)) {
        if (req.body.password.trim()) req.body.password = hashPassword(req.body.password.trim());
    }
    next();
});

// =========================================================================
// CAMPUS GEOFENCING CONFIGURATION (ACE Engineering College, Ankushapur)
// =========================================================================
const CAMPUS_LAT = parseFloat(process.env.CAMPUS_LAT) || 17.4725;
const CAMPUS_LNG = parseFloat(process.env.CAMPUS_LNG) || 78.6888;
const ALLOWED_RADIUS_METERS = parseInt(process.env.CAMPUS_RADIUS_METERS, 10) || 20000;

function calculateDistanceMeters(lat1, lon1, lat2, lon2) {
    const R = 6371e3; // Earth radius in meters
    const phi1 = (lat1 * Math.PI) / 180;
    const phi2 = (lat2 * Math.PI) / 180;
    const deltaPhi = ((lat2 - lat1) * Math.PI) / 180;
    const deltaLambda = ((lon2 - lon1) * Math.PI) / 180;

    const a = Math.sin(deltaPhi / 2) * Math.sin(deltaPhi / 2) +
              Math.cos(phi1) * Math.cos(phi2) *
              Math.sin(deltaLambda / 2) * Math.sin(deltaLambda / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

// =========================================================================
// DATABASE SCHEMA INITIALIZATION & SELF-HEALING MIGRATIONS
// =========================================================================
db.serialize(() => {
    db.run(`PRAGMA foreign_keys = ON;`);

    // Admin Users Table
    db.run(`CREATE TABLE IF NOT EXISTS admin_users (
        admin_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'Super Admin',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    if (process.env.ADMIN_PASSWORD) db.run(`INSERT OR IGNORE INTO admin_users (admin_id, name, email, password, role)
            VALUES ('ADMIN01', 'System Administrator', ?, ?, 'Super Admin')`,
            [process.env.ADMIN_EMAIL || 'admin@college.edu', hashPassword(process.env.ADMIN_PASSWORD)]);

    // Branches / Courses Table
    db.run(`CREATE TABLE IF NOT EXISTS branches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )`);

    // Departments Table
    db.run(`CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        branch_id INTEGER NOT NULL,
        doe_name TEXT DEFAULT '',
        doe_email TEXT DEFAULT '',
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        UNIQUE(name, branch_id)
    )`);

    // Batch Years Table
    db.run(`CREATE TABLE IF NOT EXISTS batch_years (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        branch_id INTEGER NOT NULL,
        FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE CASCADE,
        UNIQUE(name, branch_id)
    )`);

    // Sections Table
    db.run(`CREATE TABLE IF NOT EXISTS sections (
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

    // Faculty Accounts Table
    db.run(`CREATE TABLE IF NOT EXISTS faculty (
        faculty_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Mentors Table
    db.run(`CREATE TABLE IF NOT EXISTS mentors (
        mentor_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
    )`);

    // Section Mentors Mapping Table
    db.run(`CREATE TABLE IF NOT EXISTS section_mentors (
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

    // Students Table
    db.run(`CREATE TABLE IF NOT EXISTS students (
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

    // Attendance Logs Table
    db.run(`CREATE TABLE IF NOT EXISTS attendance_logs (
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

    // Column migrations
    db.run(`ALTER TABLE departments ADD COLUMN doe_name TEXT DEFAULT ''`, () => {});
    db.run(`ALTER TABLE departments ADD COLUMN doe_email TEXT DEFAULT ''`, () => {});
    db.run(`ALTER TABLE attendance_logs ADD COLUMN submission_time TEXT DEFAULT ''`, () => {});
});

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

// In-Memory Token & OTP Stores
const deleteOtpStore = new Map();
// In-memory store for DOE OTPs and verified session tokens
const doeOtpStore = new Map();     // email -> { otp, expiresAt }
const doeSessionStore = new Map(); // token -> { email, dept_id, expiresAt }
setInterval(() => {
    for (const store of [sessions, deleteOtpStore, doeOtpStore, doeSessionStore, attempts]) {
        for (const [key, value] of store) if ((value.expiresAt || value.until) < Date.now()) store.delete(key);
    }
}, 60000).unref();

app.use('/api/admin', async (req, res, next) => {
    if (!['POST', 'PUT'].includes(req.method) || /login|request-delete-otp/.test(req.path)) return next();
    const entity = req.path.split('/')[1];
    const required = {
        branches: ['name'], departments: req.path.endsWith('/doe') ? ['doe_name', 'doe_email'] : ['name'],
        'batch-years': ['name'], sections: ['name'], faculty: req.method === 'POST' ? ['faculty_id', 'name', 'password'] : ['name'],
        mentors: ['name', 'email'], admins: req.method === 'POST' ? ['admin_id', 'name', 'email', 'password'] : ['name', 'email'],
        students: req.method === 'PUT' ? ['name'] : []
    }[entity] || [];
    if (required.some(key => typeof req.body[key] !== 'string' || !req.body[key].trim())) return res.status(400).json({ success: false, message: 'Complete all required fields.' });
    try {
        const b = req.body;
        if (req.method === 'POST' && ['sections', 'section-mentors'].includes(entity)) {
            const valid = await all(db, `SELECT d.id FROM departments d JOIN batch_years y ON y.branch_id=d.branch_id WHERE d.id=? AND y.id=? AND d.branch_id=?`, [b.dept_id, b.batch_year_id, b.branch_id]);
            if (!valid.length) throw new Error('Department and batch must belong to the selected course.');
            if (entity === 'section-mentors') {
                const section = await all(db, 'SELECT id FROM sections WHERE id=? AND branch_id=? AND dept_id=? AND batch_year_id=?', [b.section_id, b.branch_id, b.dept_id, b.batch_year_id]);
                if (!section.length) throw new Error('Section does not belong to the selected class.');
            }
        }
        next();
    } catch (err) { res.status(400).json({ success: false, message: err.message }); }
});

function verifyAdminOtp(adminEmail, inputOtp) {
    if (!adminEmail || !inputOtp) return false;
    const stored = deleteOtpStore.get(adminEmail.toLowerCase().trim());
    if (!stored || Date.now() > stored.expiresAt) {
        deleteOtpStore.delete(adminEmail.toLowerCase().trim());
        return false;
    }
    const isValid = stored.otp === inputOtp.trim();
    if (isValid) deleteOtpStore.delete(adminEmail.toLowerCase().trim());
    return isValid;
}

function formatTimeHM(timeStr) {
    if (!timeStr) return '';
    const match = timeStr.match(/^(\d{1,2}):(\d{2})(?::\d{2})?\s*([a-zA-Z]{2})?/);
    if (match) {
        const hour = match[1];
        const min = match[2];
        const ampm = match[3] ? ` ${match[3].toLowerCase()}` : '';
        return `${hour}:${min}${ampm}`;
    }
    return timeStr;
}

function getSlotRoman(slotName) {
    const map = { 'Hour 1': 'I', 'Hour 2': 'II', 'Hour 3': 'III', 'Hour 4': 'IV', 'Hour 5': 'V', 'Hour 6': 'VI' };
    return map[slotName] || slotName;
}

// =========================================================================
// 1. AUTHENTICATION & ADMIN PROFILE APIs
// =========================================================================

app.post('/api/login', (req, res) => {
    const { faculty_id, password } = req.body;
    db.get(`SELECT faculty_id, name, password FROM faculty WHERE TRIM(UPPER(faculty_id)) = TRIM(UPPER(?))`,
        [faculty_id], (err, row) => {
            if (err || !row || !verifyPassword(password, row.password)) return res.status(401).json({ success: false, message: 'Invalid Faculty Credentials' });
            issueSession(res, 'faculty', { id: row.faculty_id, name: row.name });
            res.json({ success: true, faculty: { id: row.faculty_id, name: row.name } });
        }
    );
});

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Enter both Admin ID and Password.' });
    db.get(`SELECT admin_id, name, email, role, password FROM admin_users WHERE TRIM(UPPER(admin_id)) = TRIM(UPPER(?))`,
        [username.trim()], (err, row) => {
            if (err || !row || !verifyPassword(password.trim(), row.password)) return res.status(401).json({ success: false, message: 'Invalid Admin Credentials' });
            issueSession(res, 'admin', { id: row.admin_id, email: row.email });
            res.json({ success: true, admin: { id: row.admin_id, name: row.name, email: row.email, role: row.role } });
        }
    );
});

app.get('/api/admin/admins', (req, res) => {
    db.all(`SELECT admin_id, name, email, role, created_at FROM admin_users ORDER BY created_at ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/admin/admins', (req, res) => {
    const { admin_id, name, email, password, role } = req.body;
    if (!admin_id || !name || !email || !password) return res.status(400).json({ success: false, message: 'All admin fields required.' });
    db.run(`INSERT INTO admin_users (admin_id, name, email, password, role) VALUES (?, ?, ?, ?, ?)`,
        [admin_id.toUpperCase().trim(), name.trim(), email.trim(), password.trim(), role || 'Admin'],
        function(err) {
            if (err) return res.status(400).json({ success: false, message: 'Admin ID or Email already exists.' });
            res.json({ success: true, message: `Admin profile ${name} created successfully!` });
        }
    );
});

app.put('/api/admin/admins/:id', (req, res) => {
    const { name, email, password, role } = req.body;
    let query = `UPDATE admin_users SET name = ?, email = ?, role = ?`;
    let params = [name.trim(), email.trim(), role || 'Admin'];
    if (password && password.trim() !== '') {
        query += `, password = ?`;
        params.push(password.trim());
    }
    query += ` WHERE admin_id = ?`;
    params.push(req.params.id);

    db.run(query, params, function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Admin updated successfully.' });
    });
});

app.delete('/api/admin/admins/:id', (req, res) => {
    if (req.params.id === 'ADMIN01') return res.status(403).json({ success: false, message: 'Primary Super Admin (ADMIN01) cannot be deleted.' });
    db.run(`DELETE FROM admin_users WHERE admin_id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Admin deleted.' });
    });
});

app.post('/api/admin/request-delete-otp', async (req, res) => {
    const { entity_type } = req.body;
    const admin_email = req.auth.user.email;
    if (!admin_email) return res.status(400).json({ success: false, message: 'Admin email required.' });
    if (typeof entity_type !== 'string') return res.status(400).json({ success: false, message: 'Entity type required.' });

    const generatedOtp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    deleteOtpStore.set(admin_email.toLowerCase().trim(), { otp: generatedOtp, expiresAt });

    try {
        await transporter.sendMail({
            from: '"College Admin Security" <no-reply@college.edu>',
            to: admin_email,
            subject: `[OTP Verification] Delete ${entity_type.toUpperCase()}`,
            text: `Your OTP to authorize deletion of this ${entity_type} is: ${generatedOtp}\nValid for 5 minutes.`
        });
        res.json({ success: true, message: `Deletion OTP sent to ${admin_email}` });
    } catch (err) {
        deleteOtpStore.delete(admin_email.toLowerCase().trim());
        res.status(502).json({ success: false, message: 'Unable to send deletion OTP. Check email configuration.' });
    }
});

// =========================================================================
// 2. METADATA & CASCADING DROPDOWNS
// =========================================================================

app.get('/api/metadata', (req, res) => {
    db.all(`SELECT id, name FROM branches ORDER BY name ASC`, [], (err, branches) => {
        db.all(`SELECT mentor_id, name, email FROM mentors ORDER BY name ASC`, [], (err, mentors) => {
            res.json({ branches: branches || [], mentors: mentors || [] });
        });
    });
});

app.get('/api/departments', (req, res) => {
    const { branch_id } = req.query;
    if (!branch_id) return res.json([]);
    db.all(`SELECT id, name, doe_name, doe_email, branch_id FROM departments WHERE branch_id = ? ORDER BY name ASC`, [branch_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/batch-years', (req, res) => {
    const { branch_id } = req.query;
    if (!branch_id) return res.json([]);
    db.all(`SELECT id, name FROM batch_years WHERE branch_id = ? ORDER BY name ASC`, [branch_id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/sections', (req, res) => {
    const { branch_id, dept_id, batch_year_id } = req.query;
    if (!branch_id || !dept_id) return res.json([]);
    let query = `SELECT id, name FROM sections WHERE branch_id = ? AND dept_id = ?`;
    let params = [branch_id, dept_id];
    if (batch_year_id) { query += ` AND batch_year_id = ?`; params.push(batch_year_id); }
    query += ` ORDER BY name ASC`;
    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// =========================================================================
// 3. ADMIN MASTER DATA CRUD APIs
// =========================================================================

// Branches
app.get('/api/admin/branches', (req, res) => {
    db.all(`SELECT * FROM branches ORDER BY name ASC`, [], (err, rows) => res.json(rows || []));
});
app.post('/api/admin/branches', (req, res) => {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ success: false, message: 'Course name cannot be empty.' });
    db.run(`INSERT INTO branches (name) VALUES (?)`, [name], function(err) {
        if (err) return res.status(400).json({ success: false, message: `Course "${name}" already exists.` });
        res.json({ success: true, id: this.lastID, message: 'Course created successfully.' });
    });
});
app.put('/api/admin/branches/:id', (req, res) => {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ success: false, message: 'Course name cannot be empty.' });
    db.run(`UPDATE branches SET name = ? WHERE id = ?`, [name, req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Course updated.' });
    });
});
app.delete('/api/admin/branches/:id', (req, res) => {
    if (!verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp'])) {
        return res.status(401).json({ success: false, message: 'Invalid or expired OTP.' });
    }
    db.run(`DELETE FROM branches WHERE id = ?`, [req.params.id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Course deleted.' });
    });
});

// Departments
app.post('/api/admin/departments', (req, res) => {
    const { name, branch_id } = req.body;
    if (!name || !branch_id) return res.status(400).json({ success: false, message: 'Select Course and enter Department Name.' });
    db.run(`INSERT INTO departments (name, branch_id, doe_name, doe_email) VALUES (?, ?, '', '')`,
        [name.trim(), branch_id], function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, id: this.lastID, message: `Department "${name.trim()}" added.` });
        }
    );
});
app.put('/api/admin/departments/:id', (req, res) => {
    const { name, doe_name, doe_email, branch_id } = req.body;
    db.run(`UPDATE departments SET name = ?, doe_name = ?, doe_email = ? WHERE id = ?`,
        [name.trim(), (doe_name || '').trim(), (doe_email || '').trim(), req.params.id], function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, message: 'Department updated.' });
        }
    );
});
app.put('/api/admin/departments/:id/doe', (req, res) => {
    const { doe_name, doe_email } = req.body;
    db.run(`UPDATE departments SET doe_name = ?, doe_email = ? WHERE id = ?`,
        [doe_name.trim(), doe_email.trim(), req.params.id], function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, message: 'DOE assigned successfully.' });
        }
    );
});
app.delete('/api/admin/departments/:id', (req, res) => {
    if (!verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp'])) {
        return res.status(401).json({ success: false, message: 'Invalid or expired OTP.' });
    }
    db.run(`DELETE FROM departments WHERE id = ?`, [req.params.id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Department deleted.' });
    });
});

// Batch Years
app.post('/api/admin/batch-years', (req, res) => {
    const { name, branch_id } = req.body;
    db.run(`INSERT INTO batch_years (name, branch_id) VALUES (?, ?)`, [name.trim(), branch_id], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, id: this.lastID, message: 'Batch Year added.' });
    });
});
app.put('/api/admin/batch-years/:id', (req, res) => {
    db.run(`UPDATE batch_years SET name = ? WHERE id = ?`, [req.body.name.trim(), req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Batch Year updated.' });
    });
});
app.delete('/api/admin/batch-years/:id', (req, res) => {
    if (!verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp'])) {
        return res.status(401).json({ success: false, message: 'Invalid or expired OTP.' });
    }
    db.run(`DELETE FROM batch_years WHERE id = ?`, [req.params.id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Batch Year deleted.' });
    });
});

// Sections
app.post('/api/admin/sections', (req, res) => {
    const { name, branch_id, dept_id, batch_year_id } = req.body;
    db.run(`INSERT INTO sections (name, branch_id, dept_id, batch_year_id) VALUES (?, ?, ?, ?)`,
        [name.toUpperCase().trim(), branch_id, dept_id, batch_year_id], function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, id: this.lastID, message: `Section ${name.toUpperCase().trim()} created.` });
        }
    );
});
app.put('/api/admin/sections/:id', (req, res) => {
    db.run(`UPDATE sections SET name = ? WHERE id = ?`, [req.body.name.toUpperCase().trim(), req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Section updated.' });
    });
});
app.delete('/api/admin/sections/:id', (req, res) => {
    if (!verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp'])) {
        return res.status(401).json({ success: false, message: 'Invalid or expired OTP.' });
    }
    db.run(`DELETE FROM sections WHERE id = ?`, [req.params.id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Section deleted.' });
    });
});

// Faculty Accounts
app.get('/api/admin/faculty', (req, res) => {
    db.all(`SELECT faculty_id, name, created_at FROM faculty ORDER BY created_at DESC`, [], (err, rows) => res.json(rows || []));
});
app.post('/api/admin/faculty', (req, res) => {
    const { faculty_id, name, password } = req.body;
    db.run(`INSERT INTO faculty (faculty_id, name, password) VALUES (?, ?, ?)`,
        [faculty_id.trim().toUpperCase(), name.trim(), password.trim()], function(err) {
            if (err) return res.status(400).json({ success: false, message: 'Faculty ID already exists.' });
            res.json({ success: true, message: `Faculty ${name} registered successfully.` });
        }
    );
});
app.put('/api/admin/faculty/:faculty_id', (req, res) => {
    const { name, password } = req.body;
    let query = `UPDATE faculty SET name = ?`;
    let params = [name.trim()];
    if (password && password.trim() !== '') {
        query += `, password = ?`;
        params.push(password.trim());
    }
    query += ` WHERE faculty_id = ?`;
    params.push(req.params.faculty_id);

    db.run(query, params, function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Faculty updated.' });
    });
});
app.delete('/api/admin/faculty/:faculty_id', (req, res) => {
    db.run(`DELETE FROM faculty WHERE faculty_id = ?`, [req.params.faculty_id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Faculty deleted.' });
    });
});

// Mentors
app.get('/api/admin/mentors', (req, res) => {
    db.all(`SELECT * FROM mentors ORDER BY name ASC`, [], (err, rows) => res.json(rows || []));
});
app.post('/api/admin/mentors', (req, res) => {
    db.run(`INSERT INTO mentors (name, email) VALUES (?, ?)`, [req.body.name.trim(), req.body.email.trim()], function(err) {
        if (err) return res.status(400).json({ success: false, message: 'Email already registered.' });
        res.json({ success: true, message: 'Mentor registered.' });
    });
});
app.put('/api/admin/mentors/:id', (req, res) => {
    db.run(`UPDATE mentors SET name = ?, email = ? WHERE mentor_id = ?`, [req.body.name.trim(), req.body.email.trim(), req.params.id], function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Mentor updated.' });
    });
});
app.delete('/api/admin/mentors/:mentor_id', (req, res) => {
    db.run(`DELETE FROM mentors WHERE mentor_id = ?`, [req.params.mentor_id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Mentor deleted.' });
    });
});

// Section Mentors Mapping
app.get('/api/admin/section-mentors', (req, res) => {
    const query = `
        SELECT sm.id, sm.branch_id, sm.dept_id, sm.batch_year_id, sm.section_id, sm.mentor_id,
               b.name as branch_name, d.name as dept_name, by.name as batch_year_name, s.name as sec_name,
               m.name as mentor_name, m.email as mentor_email
        FROM section_mentors sm
        JOIN branches b ON sm.branch_id = b.id
        JOIN departments d ON sm.dept_id = d.id
        JOIN batch_years by ON sm.batch_year_id = by.id
        JOIN sections s ON sm.section_id = s.id
        JOIN mentors m ON sm.mentor_id = m.mentor_id
        ORDER BY b.name ASC, d.name ASC, by.name ASC, s.name ASC
    `;
    db.all(query, [], (err, rows) => res.json(rows || []));
});
app.post('/api/admin/section-mentors', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, mentor_id } = req.body;
    const query = `
        INSERT INTO section_mentors (branch_id, dept_id, batch_year_id, section_id, mentor_id)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(branch_id, dept_id, batch_year_id, section_id)
        DO UPDATE SET mentor_id = excluded.mentor_id
    `;
    db.run(query, [branch_id, dept_id, batch_year_id, section_id, mentor_id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Section mentor assigned.' });
    });
});
app.delete('/api/admin/section-mentors/:id', (req, res) => {
    db.run(`DELETE FROM section_mentors WHERE id = ?`, [req.params.id], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Assignment removed.' });
    });
});

// Students
app.get('/api/admin/students', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id } = req.query;
    db.all(`SELECT * FROM students WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? ORDER BY roll_number ASC`,
        [branch_id, dept_id, batch_year_id, section_id], (err, rows) => res.json(rows || []));
});
app.post('/api/admin/students/bulk', async (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, students } = req.body;
    if (!Array.isArray(students) || !students.length || students.some(s => !s || typeof s.roll_number !== 'string' || !s.roll_number.trim() || typeof s.name !== 'string' || !s.name.trim())) {
        return res.status(400).json({ success: false, message: 'Provide student roll numbers and names.' });
    }
    if (new Set(students.map(s => s.roll_number.trim().toUpperCase())).size !== students.length) return res.status(400).json({ success: false, message: 'Duplicate roll numbers in import.' });
    try {
    await transaction(dbPath, async connection => {
    const sections = await all(connection, 'SELECT id FROM sections WHERE id=? AND branch_id=? AND dept_id=? AND batch_year_id=?', [section_id, branch_id, dept_id, batch_year_id]);
    if (!sections.length) throw new Error('Select a valid class section.');
    const query = `
        INSERT INTO students (roll_number, name, phone_number, parent_number, branch_id, dept_id, batch_year_id, section_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(roll_number) DO UPDATE SET
            name = excluded.name,
            phone_number = excluded.phone_number,
            parent_number = excluded.parent_number,
            branch_id = excluded.branch_id,
            dept_id = excluded.dept_id,
            batch_year_id = excluded.batch_year_id,
            section_id = excluded.section_id
    `;
    for (const s of students) await run(connection, query, [s.roll_number.trim().toUpperCase(), s.name.trim(), s.phone_number || '', s.parent_number || '', branch_id, dept_id, batch_year_id, section_id]);
    });
    res.json({ success: true, message: `Enrolled ${students.length} students successfully.` });
    } catch (err) {
        res.status(400).json({ success: false, message: err.message });
    }
});
app.put('/api/admin/students/:roll_number', (req, res) => {
    const { name, phone_number, parent_number } = req.body;
    db.run(`UPDATE students SET name = ?, phone_number = ?, parent_number = ? WHERE roll_number = ?`,
        [(name || '').trim(), (phone_number || '').trim(), (parent_number || '').trim(), req.params.roll_number],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            res.json({ success: true, message: 'Student updated.' });
        }
    );
});
app.delete('/api/admin/students/:roll_number', (req, res) => {
    db.run(`DELETE FROM students WHERE roll_number = ?`, [req.params.roll_number], err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: 'Student deleted.' });
    });
});

// =========================================================================
// 4. FACULTY AUDIT REPORTS & HISTORY APIs
// =========================================================================

app.get('/api/faculty/sessions-history', (req, res) => {
    const { faculty_id, from_date, to_date, branch_id, dept_id, batch_year_id, section_id, hour_slot, search } = req.query;
    if (!faculty_id) return res.status(400).json({ error: 'Faculty ID required' });

    let query = `
        SELECT al.date, al.hour_slot, al.subject_name, al.submission_time, al.branch_id, al.dept_id, al.batch_year_id, al.section_id,
               b.name as branch_name, d.name as dept_name, by.name as batch_year_name, s.name as sec_name,
               COUNT(CASE WHEN al.status = 'Present' THEN 1 END) as present_count,
               COUNT(CASE WHEN al.status = 'Absent' THEN 1 END) as absent_count,
               COUNT(CASE WHEN al.status != 'Leisure' THEN 1 END) as total_students
        FROM attendance_logs al
        JOIN branches b ON al.branch_id = b.id
        JOIN departments d ON al.dept_id = d.id
        JOIN batch_years by ON al.batch_year_id = by.id
        JOIN sections s ON al.section_id = s.id
        WHERE al.faculty_id = ?
    `;
    const params = [faculty_id];

    if (from_date) { query += ` AND al.date >= ?`; params.push(from_date); }
    if (to_date) { query += ` AND al.date <= ?`; params.push(to_date); }
    if (branch_id) { query += ` AND al.branch_id = ?`; params.push(branch_id); }
    if (dept_id) { query += ` AND al.dept_id = ?`; params.push(dept_id); }
    if (batch_year_id) { query += ` AND al.batch_year_id = ?`; params.push(batch_year_id); }
    if (section_id) { query += ` AND al.section_id = ?`; params.push(section_id); }
    if (hour_slot) { query += ` AND al.hour_slot = ?`; params.push(hour_slot); }
    if (search) { query += ` AND (al.subject_name LIKE ? OR s.name LIKE ?)`; params.push(`%${search}%`, `%${search}%`); }

    query += ` GROUP BY al.date, al.hour_slot, al.branch_id, al.dept_id, al.batch_year_id, al.section_id ORDER BY al.date DESC, al.hour_slot ASC`;

    db.all(query, params, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.get('/api/faculty/session-students', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, date, hour_slot } = req.query;
    const query = `
        SELECT al.roll_number, st.name as student_name, st.phone_number, st.parent_number,
               al.status, al.subject_name, al.submission_time, al.faculty_name
        FROM attendance_logs al
        LEFT JOIN students st ON al.roll_number = st.roll_number
        WHERE al.branch_id = ? AND al.dept_id = ? AND al.batch_year_id = ? AND al.section_id = ?
          AND al.date = ? AND al.hour_slot = ?
        ORDER BY al.roll_number ASC
    `;
    db.all(query, [branch_id, dept_id, batch_year_id, section_id, date, hour_slot], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.put('/api/faculty/update-student-status', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, date, hour_slot, roll_number, new_status, faculty_id } = req.body;
    if (!['Present', 'Absent'].includes(new_status)) return res.status(400).json({ success: false, message: 'Invalid attendance status.' });
    db.run(
        `UPDATE attendance_logs SET status = ?
         WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? AND date = ? AND hour_slot = ? AND roll_number = ? AND faculty_id = ?`,
        [new_status, branch_id, dept_id, batch_year_id, section_id, date, hour_slot, roll_number, faculty_id],
        function(err) {
            if (err) return res.status(500).json({ success: false, message: err.message });
            if (!this.changes) return res.status(404).json({ success: false, message: 'Your attendance record was not found.' });
            res.json({ success: true, message: `Updated ${roll_number} to ${new_status}.` });
        }
    );
});

app.post('/api/faculty/resend-report', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, date } = req.body;
    const sectionQuery = `
        SELECT sm.mentor_id, m.name AS mentor_name, m.email AS mentor_email,
               b.name as branch_name, d.name as dept_name, d.doe_name, d.doe_email,
               by.name as batch_year_name, s.name as sec_name
        FROM section_mentors sm
        JOIN mentors m ON sm.mentor_id = m.mentor_id
        JOIN branches b ON sm.branch_id = b.id
        JOIN departments d ON sm.dept_id = d.id
        JOIN batch_years by ON sm.batch_year_id = by.id
        JOIN sections s ON sm.section_id = s.id
        WHERE sm.branch_id = ? AND sm.dept_id = ? AND sm.batch_year_id = ? AND sm.section_id = ?
    `;
    db.get(sectionQuery, [branch_id, dept_id, batch_year_id, section_id], (err, sectionInfo) => {
        if (err || !sectionInfo) return res.status(400).json({ success: false, message: 'Class or mentor mapping not found.' });

        const logsQuery = `
            SELECT hour_slot, subject_name, faculty_name, roll_number, status, submission_time
            FROM attendance_logs
            WHERE date = ? AND branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
            ORDER BY hour_slot ASC, roll_number ASC
        `;
        db.all(logsQuery, [date, branch_id, dept_id, batch_year_id, section_id], (err, allTodayLogs) => {
            db.all(`SELECT roll_number FROM students WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? ORDER BY roll_number ASC`,
                [branch_id, dept_id, batch_year_id, section_id], async (err, enrolledStudents) => {
                    try {
                        const pdfBuffer = await generateSinglePageHorizontalPDF(sectionInfo, date, allTodayLogs, enrolledStudents || []);
                        await transporter.sendMail({
                            from: '"ACE College Attendance" <no-reply@college.edu>',
                            to: sectionInfo.mentor_email,
                            subject: `[ATTENDANCE STATEMENT] ${sectionInfo.branch_name} ${sectionInfo.dept_name} Sec-${sectionInfo.sec_name} (${date})`,
                            text: `Respected Mentor (${sectionInfo.mentor_name}),\n\nPlease find attached the official Daily Attendance Statement for ${date}.`,
                            attachments: [{ filename: `Attendance_Statement_${date}.pdf`, content: pdfBuffer }]
                        });
                        res.json({ success: true, message: `Statement successfully re-sent to ${sectionInfo.mentor_email}` });
                    } catch (e) {
                        res.status(500).json({ success: false, message: 'Dispatch failed: ' + e.message });
                    }
                }
            );
        });
    });
});

app.get('/api/faculty/reports/consolidated-pdf', (req, res) => {
    const { faculty_id, from_date, to_date, branch_id, dept_id, batch_year_id, section_id } = req.query;
    if (!faculty_id) return res.status(400).send("Faculty ID required");

    let query = `
        SELECT al.date, al.hour_slot, al.subject_name, al.submission_time, al.faculty_name,
               b.name as branch_name, d.name as dept_name, by.name as batch_year_name, s.name as sec_name,
               COUNT(CASE WHEN al.status = 'Present' THEN 1 END) as present_count,
               COUNT(CASE WHEN al.status = 'Absent' THEN 1 END) as absent_count,
               COUNT(CASE WHEN al.status != 'Leisure' THEN 1 END) as total_students
        FROM attendance_logs al
        JOIN branches b ON al.branch_id = b.id
        JOIN departments d ON al.dept_id = d.id
        JOIN batch_years by ON al.batch_year_id = by.id
        JOIN sections s ON al.section_id = s.id
        WHERE al.faculty_id = ?
    `;
    const params = [faculty_id];
    if (from_date) { query += ` AND al.date >= ?`; params.push(from_date); }
    if (to_date) { query += ` AND al.date <= ?`; params.push(to_date); }
    if (branch_id) { query += ` AND al.branch_id = ?`; params.push(branch_id); }
    if (dept_id) { query += ` AND al.dept_id = ?`; params.push(dept_id); }
    if (batch_year_id) { query += ` AND al.batch_year_id = ?`; params.push(batch_year_id); }
    if (section_id) { query += ` AND al.section_id = ?`; params.push(section_id); }

    query += ` GROUP BY al.date, al.hour_slot, al.branch_id, al.dept_id, al.batch_year_id, al.section_id ORDER BY al.date DESC, al.hour_slot ASC`;

    db.all(query, params, (err, rows) => {
        if (err || !rows || rows.length === 0) return res.status(404).send("No records found for date range.");

        const doc = new PDFDocument({ margin: 30, size: 'A4', layout: 'landscape' });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=Faculty_Consolidated_Audit_${from_date || 'all'}_${to_date || 'all'}.pdf`);
        doc.pipe(res);

        const facultyName = rows[0].faculty_name;
        doc.fontSize(16).font('Helvetica-Bold').fillColor('#0F172A').text('FACULTY CONSOLIDATED ACADEMIC DOSSIER', { align: 'center' }).moveDown(0.2);
        doc.fontSize(10).font('Helvetica-Bold').fillColor('#1D4ED8').text(`CONDUCTED SESSIONS AUDIT STATEMENT`, { align: 'center' }).moveDown(0.2);
        doc.fontSize(8.5).font('Helvetica').fillColor('#475569').text(
            `Faculty: ${facultyName} (${faculty_id})  |  Date Window: ${from_date || 'Start'} to ${to_date || 'Latest'}  |  Total Sessions: ${rows.length}`,
            { align: 'center' }
        ).moveDown(0.8);

        doc.moveTo(30, doc.y).lineTo(812, doc.y).stroke('#94A3B8').moveDown(0.6);

        let y = doc.y;
        doc.rect(30, y, 782, 22).fill('#1E293B');
        doc.font('Helvetica-Bold').fontSize(8).fillColor('#FFFFFF');
        doc.text('Date', 38, y + 7);
        doc.text('Slot', 105, y + 7);
        doc.text('Class & Section', 165, y + 7);
        doc.text('Subject', 380, y + 7);
        doc.text('Recorded Time', 530, y + 7);
        doc.text('Presents', 625, y + 7);
        doc.text('Absentees', 685, y + 7);
        doc.text('Attendance %', 745, y + 7);

        y += 24;
        rows.forEach(r => {
            if (y > 530) { doc.addPage(); y = 40; }
            const pct = r.total_students > 0 ? ((r.present_count / r.total_students) * 100).toFixed(1) : '100.0';
            doc.font('Helvetica').fontSize(8).fillColor('#000000');
            doc.text(r.date, 38, y);
            doc.font('Helvetica-Bold').text(r.hour_slot, 105, y);
            doc.font('Helvetica').text(`${r.branch_name} ${r.dept_name} (Sec-${r.sec_name})`, 165, y);
            doc.text(r.subject_name.substring(0, 26), 380, y);
            doc.text(formatTimeHM(r.submission_time) || 'N/A', 530, y);
            doc.font('Helvetica-Bold').fillColor('#16A34A').text(`${r.present_count}`, 630, y);
            doc.fillColor('#DC2626').text(`${r.absent_count}`, 690, y);
            doc.fillColor('#1D4ED8').text(`${pct}%`, 745, y);
            y += 18;
        });

        if (y > 500) doc.addPage();
        const signY = 535;
        doc.moveTo(45, signY).lineTo(180, signY).stroke('#94A3B8');
        doc.moveTo(630, signY).lineTo(780, signY).stroke('#94A3B8');
        doc.font('Helvetica-Bold').fontSize(8).fillColor('#475569');
        doc.text('Faculty Signature', 65, signY + 5);
        doc.text('Principal / Dean Approval', 645, signY + 5);

        doc.end();
    });
});

app.get('/api/faculty/reports/hourly-pdf', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, date, hour_slot } = req.query;
    if (!branch_id || !dept_id || !batch_year_id || !section_id || !date || !hour_slot) {
        return res.status(400).send("Missing session parameters.");
    }

    const sectionQuery = `
        SELECT sm.mentor_id, m.name AS mentor_name, m.email AS mentor_email,
               b.name as branch_name, d.name as dept_name, d.doe_name, d.doe_email,
               by.name as batch_year_name, s.name as sec_name
        FROM section_mentors sm
        JOIN mentors m ON sm.mentor_id = m.mentor_id
        JOIN branches b ON sm.branch_id = b.id
        JOIN departments d ON sm.dept_id = d.id
        JOIN batch_years by ON sm.batch_year_id = by.id
        JOIN sections s ON sm.section_id = s.id
        WHERE sm.branch_id = ? AND sm.dept_id = ? AND sm.batch_year_id = ? AND sm.section_id = ?
    `;
    db.get(sectionQuery, [branch_id, dept_id, batch_year_id, section_id], (err, sectionInfo) => {
        if (err || !sectionInfo) return res.status(400).send("Class details not found.");

        const logsQuery = `
            SELECT hour_slot, subject_name, faculty_name, roll_number, status, submission_time
            FROM attendance_logs
            WHERE date = ? AND branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
            ORDER BY hour_slot ASC, roll_number ASC
        `;
        db.all(logsQuery, [date, branch_id, dept_id, batch_year_id, section_id], (err, allTodayLogs) => {
            db.all(`SELECT roll_number FROM students WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? ORDER BY roll_number ASC`,
                [branch_id, dept_id, batch_year_id, section_id], async (err, enrolledStudents) => {
                    const doc = new PDFDocument({ margin: 25, size: 'A4', layout: 'landscape' });
                    res.setHeader('Content-Type', 'application/pdf');
                    res.setHeader('Content-Disposition', `attachment; filename=Attendance_Statement_${date}_${hour_slot.replace(/\s+/g, '_')}.pdf`);
                    doc.pipe(res);
                    await renderAceMasterPdf(doc, sectionInfo, date, allTodayLogs, enrolledStudents || []);
                    doc.end();
                }
            );
        });
    });
});

// =========================================================================
// 5. ATTENDANCE SUBMISSION (GEOFENCE + DISPATCH LOGIC)
// =========================================================================

app.get('/api/students', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, hour_slot, date } = req.query;
    db.get(`SELECT faculty_id, faculty_name, subject_name FROM attendance_logs WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? AND hour_slot = ? AND date = ? LIMIT 1`,
        [branch_id, dept_id, batch_year_id, section_id, hour_slot, date], (err, existingRecord) => {
            if (err) return res.status(500).json({ error: err.message });
            db.all(`SELECT st.roll_number, st.name, st.phone_number, st.parent_number, al.status
                FROM students st LEFT JOIN attendance_logs al ON al.roll_number = st.roll_number AND al.date = ? AND al.hour_slot = ?
                AND al.branch_id = st.branch_id AND al.dept_id = st.dept_id AND al.batch_year_id = st.batch_year_id AND al.section_id = st.section_id
                WHERE st.branch_id = ? AND st.dept_id = ? AND st.batch_year_id = ? AND st.section_id = ? ORDER BY st.roll_number ASC`,
                [date, hour_slot, branch_id, dept_id, batch_year_id, section_id], (err, students) => {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ alreadySubmitted: !!existingRecord, existingDetails: existingRecord || null, students: students || [] });
                });
        });
});

app.get('/api/attendance/previous-hour', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, date, previousHour } = req.query;
    db.all(`SELECT roll_number, status FROM attendance_logs WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? AND date = ? AND hour_slot = ?`,
        [branch_id, dept_id, batch_year_id, section_id, date, previousHour], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows || []);
        });
});

app.get('/api/faculty/daily-progress', (req, res) => {
    const { branch_id, dept_id, batch_year_id, section_id, date } = req.query;
    const query = `
        SELECT hour_slot, subject_name, faculty_id, faculty_name, submission_time
        FROM attendance_logs
        WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? AND date = ?
        GROUP BY hour_slot ORDER BY hour_slot ASC
    `;
    db.all(query, [branch_id, dept_id, batch_year_id, section_id, date], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const hours = ['Hour 1', 'Hour 2', 'Hour 3', 'Hour 4', 'Hour 5', 'Hour 6'];
        const progress = hours.map(slot => {
            const found = (rows || []).find(r => r.hour_slot === slot);
            return found ? { slot, status: 'Submitted', faculty_id: found.faculty_id, faculty_name: found.faculty_name, subject_name: found.subject_name, submission_time: found.submission_time }
                         : { slot, status: 'Pending', faculty_id: null, faculty_name: null, subject_name: null, submission_time: null };
        });
        res.json(progress);
    });
});

app.post('/api/attendance/submit', (req, res) => {
    const { facultyId, facultyName, subjectName, hourSlot, date, classDetails, attendance, classroomPhoto, location } = req.body;
    if (!classDetails || !['branch_id', 'dept_id', 'batch_year_id', 'section_id'].every(k => Number.isInteger(Number(classDetails[k])) && Number(classDetails[k]) > 0)
        || typeof subjectName !== 'string' || !subjectName.trim() || !/^Hour [1-6]$/.test(hourSlot)
        || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date
        || !Array.isArray(attendance) || !attendance.length || attendance.some(s => !s || typeof s.roll_number !== 'string' || !['Present', 'Absent', 'Leisure'].includes(s.status))) {
        return res.status(400).json({ success: false, message: 'Invalid class, date, subject, or attendance list.' });
    }
    if (attendance.some(s => s.status === 'Leisure') && !attendance.every(s => s.status === 'Leisure')) return res.status(400).json({ success: false, message: 'Leisure applies to the whole class.' });

    // 1. Mandatory Location Check
    if (!location || !Number.isFinite(location.latitude) || !Number.isFinite(location.longitude) || Math.abs(location.latitude) > 90 || Math.abs(location.longitude) > 180) {
        return res.status(400).json({
            success: false,
            message: 'Device location is required. Please turn on GPS/Location services.'
        });
    }

    // 2. Server-Side Radius Verification
    const distance = calculateDistanceMeters(CAMPUS_LAT, CAMPUS_LNG, location.latitude, location.longitude);
    if (distance > ALLOWED_RADIUS_METERS) {
        return res.status(403).json({
            success: false,
            message: `Location Access Denied: You are ${Math.round(distance)}m away from campus. Attendance can only be recorded within ${ALLOWED_RADIUS_METERS}m.`
        });
    }

    if (typeof classroomPhoto !== 'string' || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(classroomPhoto)) {
        return res.status(400).json({ success: false, message: 'Classroom verification photo is strictly mandatory.' });
    }

    const submissionTime = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });

    const lockCheckQuery = `
        SELECT faculty_id, faculty_name FROM attendance_logs
        WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? AND hour_slot = ? AND date = ? LIMIT 1
    `;

    db.get(lockCheckQuery, [classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id, hourSlot, date], (err, existingLock) => {
        if (err) return res.status(500).json({ success: false, message: 'Database lock verification error.' });

        if (existingLock && existingLock.faculty_id !== facultyId) {
            return res.status(403).json({
                success: false,
                message: `Access Denied: ${hourSlot} was already submitted by ${existingLock.faculty_name} (${existingLock.faculty_id}).`
            });
        }

        const sectionQuery = `
            SELECT sm.mentor_id, m.name AS mentor_name, m.email AS mentor_email,
                   b.name as branch_name, d.name as dept_name, d.doe_name, d.doe_email,
                   by.name as batch_year_name, s.name as sec_name
            FROM section_mentors sm
            JOIN mentors m ON sm.mentor_id = m.mentor_id
            JOIN branches b ON sm.branch_id = b.id
            JOIN departments d ON sm.dept_id = d.id
            JOIN batch_years by ON sm.batch_year_id = by.id
            JOIN sections s ON sm.section_id = s.id
            WHERE sm.branch_id = ? AND sm.dept_id = ? AND sm.batch_year_id = ? AND sm.section_id = ?
        `;

        db.get(sectionQuery, [classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id], async (err, sectionInfo) => {
            if (err || !sectionInfo) {
                return res.status(400).json({ success: false, message: "No mentor assigned to this section. Contact administrator." });
            }

            try {
                await saveAttendance(dbPath, req.body, submissionTime);
            } catch (writeError) {
                return res.status(409).json({ success: false, message: writeError.message });
            }

                res.json({ success: true, message: `Attendance for ${hourSlot} recorded successfully!` });

                let photoBuffer = null;
                try {
                    const cleanBase64 = classroomPhoto.replace(/^data:image\/\w+;base64,/, "");
                    photoBuffer = Buffer.from(cleanBase64, 'base64');
                } catch (bErr) {
                    console.error("Photo base64 error:", bErr.message);
                }

                const logsQuery = `
                    SELECT hour_slot, subject_name, faculty_name, roll_number, status, submission_time
                    FROM attendance_logs
                    WHERE date = ? AND branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
                    ORDER BY hour_slot ASC, roll_number ASC
                `;

                db.all(logsQuery, [date, classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id], async (err, allTodayLogs) => {
                    if (err) return;

                    db.all(`SELECT roll_number FROM students WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? ORDER BY roll_number ASC`,
                        [classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id], async (err, enrolledStudents) => {
                            try {
                                // 1. Dispatch Mentor Report (Full 6-Period Table + Watermarked Photo)
                                const mentorPdfBuffer = await generateSinglePageHorizontalPDF(sectionInfo, date, allTodayLogs, enrolledStudents || []);
                                const mentorAttachments = [{ filename: `Attendance_Statement_${date}.pdf`, content: mentorPdfBuffer }];
                                if (photoBuffer) {
                                    mentorAttachments.push({
                                        filename: `Classroom_Proof_${date}_${hourSlot.replace(/\s+/g, '_')}.jpg`,
                                        content: photoBuffer
                                    });
                                }

                                await transporter.sendMail({
                                    from: '"ACE College Attendance" <no-reply@college.edu>',
                                    to: sectionInfo.mentor_email,
                                    subject: `[Attendance Statement + Photo] ${sectionInfo.branch_name} ${sectionInfo.dept_name} Sec-${sectionInfo.sec_name} (${hourSlot})`,
                                    text: `Respected Mentor (${sectionInfo.mentor_name}),\n\nAttendance for ${hourSlot} was recorded at ${submissionTime} by ${facultyName}.\n\nAttached is the official statement and watermarked classroom photo.`,
                                    attachments: mentorAttachments
                                }).catch(err => console.error('Mentor email dispatch failed:', err.message));

                                // 2. Dynamic First-Period DOE Dispatch
                                const morningHours = ['Hour 1', 'Hour 2', 'Hour 3'];
                                const afternoonHours = ['Hour 4', 'Hour 5', 'Hour 6'];
                                let isDoeTarget = false;
                                let sessionType = '';

                                if (morningHours.includes(hourSlot)) {
                                    sessionType = 'Morning';
                                    const currentIndex = morningHours.indexOf(hourSlot);
                                    const priorMorningHours = morningHours.slice(0, currentIndex);
                                    if (attendance[0].status !== 'Leisure' && !allTodayLogs.some(log => priorMorningHours.includes(log.hour_slot) && log.status !== 'Leisure')) isDoeTarget = true;
                                } else if (afternoonHours.includes(hourSlot)) {
                                    sessionType = 'Afternoon';
                                    const currentIndex = afternoonHours.indexOf(hourSlot);
                                    const priorAfternoonHours = afternoonHours.slice(0, currentIndex);
                                    if (attendance[0].status !== 'Leisure' && !allTodayLogs.some(log => priorAfternoonHours.includes(log.hour_slot) && log.status !== 'Leisure')) isDoeTarget = true;
                                }

                                if (isDoeTarget && sectionInfo.doe_email) {
                                    const currentSlotLogs = allTodayLogs.filter(l => l.hour_slot === hourSlot);
                                    const doePdfBuffer = await generateDoeSingleSlipPDF(sectionInfo, date, hourSlot, sessionType, currentSlotLogs, enrolledStudents || []);

                                    const appBaseUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
                                    const currentSessionCode = sessionType === 'Morning' ? 'FN' : 'AN';

                                    // Secure verification link mapped to this specific department and session
                                    const doeSecureLink = `${appBaseUrl}/doe?dept_id=${classDetails.dept_id}&date=${date}&session=${currentSessionCode}`;

                                    await transporter.sendMail({
                                        from: '"Directorate of Evaluation" <no-reply@college.edu>',
                                        to: sectionInfo.doe_email,
                                        subject: `[DOE Attendance Slip - ${currentSessionCode}] ${sectionInfo.dept_name} Sec-${sectionInfo.sec_name} (${hourSlot})`,
                                        html: `
                                            <div style="font-family: sans-serif; padding: 20px; border: 1px solid #cbd5e1; border-radius: 12px; max-width: 580px;">
                                                <h3 style="color: #0f172a; margin-top: 0;">ACE Engineering College — Directorate of Evaluation</h3>
                                                <p style="font-size: 13px; color: #334155;">
                                                    First conducted period recorded for <strong>Department of ${sectionInfo.dept_name}</strong>:
                                                </p>
                                                <ul style="font-size: 12px; color: #475569; line-height: 1.6;">
                                                    <li><strong>Session:</strong> ${sessionType} (${currentSessionCode}) — ${hourSlot}</li>
                                                    <li><strong>Subject:</strong> ${subjectName}</li>
                                                    <li><strong>Faculty:</strong> ${facultyName} (${facultyId})</li>
                                                    <li><strong>Submission Time:</strong> ${formatTimeHM(submissionTime)}</li>
                                                </ul>
                                                <div style="margin: 22px 0;">
                                                    <a href="${doeSecureLink}" style="background-color: #1e3a8a; color: #ffffff; padding: 11px 20px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 13px; display: inline-block;">
                                                        🛡️ Authenticate &amp; Print 8-Up Slips (A4) &rarr;
                                                    </a>
                                                </div>
                                                <p style="font-size: 11px; color: #64748b;">
                                                    * For security compliance, an OTP will be dispatched to this email address (${sectionInfo.doe_email}) upon opening the link.
                                                </p>
                                            </div>
                                        `,
                                        attachments: [
                                            { filename: `DOE_Chit_${currentSessionCode}_${date}.pdf`, content: doePdfBuffer }
                                        ]
                                    });
                                }
                            } catch (e) {
                                console.error("Email dispatch failed:", e.message);
                            }
                        }
                    );
                });
        });
    });
});

// =========================================================================
// 6. DOE OTP AUTHENTICATION & BATCH 8-UP SLIP ROUTES
// =========================================================================

// 1. Send OTP to Respective Department DOE
app.post('/api/doe/request-otp', (req, res) => {
    const { dept_id, email } = req.body;

    // Verify email belongs to the selected department
    db.get(`SELECT id, name, doe_name, doe_email FROM departments WHERE id = ?`, [dept_id], async (err, dept) => {
        if (err || !dept || !dept.doe_email) {
            return res.status(404).json({ success: false, message: 'Department or registered DOE email not found.' });
        }

        const registeredEmail = dept.doe_email.toLowerCase().trim();
        const inputEmail = (email || '').toLowerCase().trim();

        if (inputEmail && inputEmail !== registeredEmail) {
            return res.status(403).json({ success: false, message: 'Entered email does not match the official DOE on record for this department.' });
        }

        const otp = crypto.randomInt(100000, 1000000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes validity

        doeOtpStore.set(registeredEmail, { otp, dept_id: dept.id, expiresAt });

        try {
            await transporter.sendMail({
                from: '"ACE Examination Authority" <no-reply@college.edu>',
                to: registeredEmail,
                subject: `[DOE Access Code] Login OTP for ${dept.name}`,
                text: `Dear ${dept.doe_name || 'Director of Evaluation'},\n\nYour one-time security passkey to access and print official attendance slips for Department of ${dept.name} is:\n\n${otp}\n\nThis OTP is valid for 10 minutes. Do not share this passkey.`
            });
            res.json({ success: true, message: `Access OTP sent to registered DOE email (${registeredEmail.replace(/(.{2})(.*)(@.*)/, "$1***$3")})` });
        } catch (mailErr) {
            doeOtpStore.delete(registeredEmail);
            res.status(500).json({ success: false, message: 'Failed to send OTP email: ' + mailErr.message });
        }
    });
});

// 2. Verify OTP & Issue Department-Restricted Access Token
app.post('/api/doe/verify-otp', (req, res) => {
    const { dept_id, otp } = req.body;

    db.get(`SELECT id, name, doe_email FROM departments WHERE id = ?`, [dept_id], (err, dept) => {
        if (err || !dept) return res.status(404).json({ success: false, message: 'Department not found.' });

        const registeredEmail = dept.doe_email.toLowerCase().trim();
        const record = doeOtpStore.get(registeredEmail);

        if (!record || record.dept_id !== dept.id || Date.now() > record.expiresAt) {
            doeOtpStore.delete(registeredEmail);
            return res.status(401).json({ success: false, message: 'OTP has expired. Please request a new code.' });
        }

        if (record.otp !== (otp || '').trim()) {
            return res.status(401).json({ success: false, message: 'Invalid verification code.' });
        }

        // Clean up OTP and issue short-lived session token (valid 2 hours)
        doeOtpStore.delete(registeredEmail);
        const token = crypto.randomBytes(32).toString('hex');
        doeSessionStore.set(token, {
            email: registeredEmail,
            dept_id: dept.id,
            dept_name: dept.name,
            expiresAt: Date.now() + 2 * 60 * 60 * 1000
        });

        res.json({ success: true, token, dept_id: dept.id, dept_name: dept.name });
    });
});

// 3. Batch PDF Route (Restricted Strictly to Token's Authorized Department)
app.get('/api/doe/reports/batch-slips-pdf', (req, res) => {
    const { token, from_date, to_date, session } = req.query;

    const auth = doeSessionStore.get(token);
    if (!auth || Date.now() > auth.expiresAt) {
        return res.status(401).send("Unauthorized: Invalid or expired DOE session. Please authenticate via email OTP.");
    }

    const authorizedDeptId = auth.dept_id; // Strictly locked to verified DOE department
    const targetFrom = from_date || new Date().toISOString().split('T')[0];
    const targetTo = to_date || targetFrom;
    const sessionFilter = (session || 'ALL').toUpperCase();

    let query = `
        SELECT al.date, al.hour_slot, al.subject_name, al.faculty_name, al.submission_time,
               al.branch_id, al.dept_id, al.batch_year_id, al.section_id,
               b.name as branch_name, d.name as dept_name, by.name as batch_year_name, s.name as sec_name
        FROM attendance_logs al
        JOIN branches b ON al.branch_id = b.id
        JOIN departments d ON al.dept_id = d.id
        JOIN batch_years by ON al.batch_year_id = by.id
        JOIN sections s ON al.section_id = s.id
        WHERE al.dept_id = ? AND al.date BETWEEN ? AND ?
          AND al.status != 'Leisure'
          AND NOT EXISTS (SELECT 1 FROM attendance_logs earlier
              WHERE earlier.date=al.date AND earlier.branch_id=al.branch_id AND earlier.dept_id=al.dept_id
                AND earlier.batch_year_id=al.batch_year_id AND earlier.section_id=al.section_id
                AND earlier.status != 'Leisure' AND earlier.hour_slot < al.hour_slot
                AND ((earlier.hour_slot IN ('Hour 1','Hour 2','Hour 3') AND al.hour_slot IN ('Hour 1','Hour 2','Hour 3'))
                  OR (earlier.hour_slot IN ('Hour 4','Hour 5','Hour 6') AND al.hour_slot IN ('Hour 4','Hour 5','Hour 6'))))
    `;
    const params = [authorizedDeptId, targetFrom, targetTo];

    if (sessionFilter === 'FN') {
        query += ` AND al.hour_slot IN ('Hour 1', 'Hour 2', 'Hour 3')`;
    } else if (sessionFilter === 'AN') {
        query += ` AND al.hour_slot IN ('Hour 4', 'Hour 5', 'Hour 6')`;
    }

    query += ` GROUP BY al.date, al.hour_slot, al.branch_id, al.dept_id, al.batch_year_id, al.section_id ORDER BY al.date ASC, al.hour_slot ASC`;

    db.all(query, params, (err, sessions) => {
        if (err || !sessions || sessions.length === 0) {
            return res.status(404).send(`No attendance slips recorded for Department of ${auth.dept_name} in this date range.`);
        }

        const doc = new PDFDocument({ margin: 0, size: 'A4', layout: 'portrait' });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename=DOE_${auth.dept_name}_Slips_${targetFrom}.pdf`);
        doc.pipe(res);

        const slipW = 275;
        const slipH = 194;
        const colGap = 13;
        const rowGap = 8;
        const startX = 16;
        const startY = 18;

        let processed = 0;
        const renderNextSession = (sIdx) => {
            if (sIdx >= sessions.length) {
                doc.end();
                return;
            }

            const sess = sessions[sIdx];
            const sessionType = ['Hour 1', 'Hour 2', 'Hour 3'].includes(sess.hour_slot) ? 'Morning' : 'Afternoon';

            db.all(`SELECT roll_number, status, faculty_name, submission_time FROM attendance_logs WHERE date = ? AND branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? AND hour_slot = ?`,
                [sess.date, sess.branch_id, sess.dept_id, sess.batch_year_id, sess.section_id, sess.hour_slot],
                (lErr, slotLogs) => {
                    db.all(`SELECT roll_number FROM students WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? ORDER BY roll_number ASC`,
                        [sess.branch_id, sess.dept_id, sess.batch_year_id, sess.section_id],
                        (stErr, enrolledStudents) => {
                            const slipIndexOnPage = processed % 8;
                            if (processed > 0 && slipIndexOnPage === 0) {
                                doc.addPage();
                            }

                            const col = slipIndexOnPage % 2;
                            const row = Math.floor(slipIndexOnPage / 2);
                            const x = startX + col * (slipW + colGap);
                            const y = startY + row * (slipH + rowGap);

                            drawSingleDoeSlip(doc, x, y, slipW, slipH, sess, sess.date, sess.hour_slot, sessionType, slotLogs || [], enrolledStudents || []);
                            processed++;
                            renderNextSession(sIdx + 1);
                        }
                    );
                }
            );
        };

        renderNextSession(0);
    });
});

// =========================================================================
// 7. PDF ENGINES (MENTOR MASTER + DOE CHIT)
// =========================================================================

function generateSinglePageHorizontalPDF(sectionInfo, date, allLogs, enrolledStudents) {
    return new Promise((resolve) => {
        const doc = new PDFDocument({ margin: 25, size: 'A4', layout: 'landscape' });
        let buffers = [];
        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        renderAceMasterPdf(doc, sectionInfo, date, allLogs, enrolledStudents);
        doc.end();
    });
}

function renderAceMasterPdf(doc, sectionInfo, date, allLogs, enrolledStudents) {
    const startX = 35;
    const tableWidth = 770;
    const totalStrength = (enrolledStudents || []).length;

    // Institutional Header
    doc.font('Helvetica-Bold').fontSize(16).fillColor('#000000').text('ACE', 0, 16, { align: 'center' });
    doc.font('Helvetica-Bold').fontSize(14).text('Engineering College', 0, 32, { align: 'center' });
    doc.font('Helvetica').fontSize(8).fillColor('#333333').text('Ankushapur(V), Ghatkesar(M), Medchal Dist.501301.', 0, 48, { align: 'center' });
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#000000').text(`Department of ${sectionInfo.dept_name || 'CSE'}`, 0, 59, { align: 'center' });

    // Mentor Details
    const mentorInfoStr = `Mentor: ${sectionInfo.mentor_name || 'Not Configured'}   |   Email: ${sectionInfo.mentor_email || 'N/A'}`;
    doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#1D4ED8').text(mentorInfoStr, 0, 72, { align: 'center' });

    // Upper Class Details
    const metaY1 = 86;
    const metaY2 = 100;
    doc.font('Helvetica-Bold').fontSize(9).fillColor('#000000');
    doc.text(`Program : ${sectionInfo.branch_name || 'B.Tech'}`, startX, metaY1);
    doc.text(`Department : ${sectionInfo.dept_name || 'CSE'}`, 210, metaY1);
    doc.text(`Batch / Year : ${sectionInfo.batch_year_name || '2026-2029'}`, startX, metaY2);
    doc.text(`Section : Sec-${sectionInfo.sec_name || 'LE'}`, 210, metaY2);
    doc.fillColor('#16A34A').text(`Total Strength : ${totalStrength}`, 360, metaY2);

    doc.fillColor('#000000').text('Date :', 645, metaY1 + 3);
    doc.rect(680, metaY1 - 1, 125, 18).lineWidth(0.9).stroke('#000000');
    doc.font('Helvetica-Bold').fontSize(9.5).text(date, 685, metaY1 + 3, { width: 115, align: 'center' });

    // Main 5-Column Table Header
    const tableTop = 118;
    const colW = { period: 58, subject: 107, absentees: 415, total: 75, faculty: 115 };
    const headerH = 24;
    doc.rect(startX, tableTop, tableWidth, headerH).lineWidth(1).stroke('#000000');

    let curX = startX;
    doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#000000');
    doc.text('Period', curX, tableTop + 7, { width: colW.period, align: 'center' });
    curX += colW.period; doc.moveTo(curX, tableTop).lineTo(curX, tableTop + headerH).stroke('#000000');
    doc.text('Subject/Lab', curX, tableTop + 7, { width: colW.subject, align: 'center' });
    curX += colW.subject; doc.moveTo(curX, tableTop).lineTo(curX, tableTop + headerH).stroke('#000000');
    doc.text('Roll Nos. of Absentees', curX, tableTop + 7, { width: colW.absentees, align: 'center' });
    curX += colW.absentees; doc.moveTo(curX, tableTop).lineTo(curX, tableTop + headerH).stroke('#000000');
    doc.text('TotalNo.of\nAbsentees', curX, tableTop + 3, { width: colW.total, align: 'center' });
    curX += colW.total; doc.moveTo(curX, tableTop).lineTo(curX, tableTop + headerH).stroke('#000000');
    doc.text('Faculty Name', curX, tableTop + 7, { width: colW.faculty, align: 'center' });

    const rowH = 41;
    const periods = ['I', 'II', 'III', 'IV', 'V', 'VI'];
    const hourMap = { 'Hour 2': 'Hour 1', 'Hour 3': 'Hour 2', 'Hour 4': 'Hour 3', 'Hour 5': 'Hour 4', 'Hour 6': 'Hour 5' };

    periods.forEach((pRoman, idx) => {
        const slotName = `Hour ${idx + 1}`;
        const rowY = tableTop + headerH + (idx * rowH);
        const slotLogs = (allLogs || []).filter(l => l.hour_slot === slotName);
        const isConducted = slotLogs.length > 0;

        doc.rect(startX, rowY, tableWidth, rowH).lineWidth(0.8).stroke('#000000');
        let x = startX;
        x += colW.period; doc.moveTo(x, rowY).lineTo(x, rowY + rowH).stroke('#000000');
        x += colW.subject; doc.moveTo(x, rowY).lineTo(x, rowY + rowH).stroke('#000000');
        x += colW.absentees; doc.moveTo(x, rowY).lineTo(x, rowY + rowH).stroke('#000000');
        x += colW.total; doc.moveTo(x, rowY).lineTo(x, rowY + rowH).stroke('#000000');

        // Period & Time
        doc.font('Helvetica-Bold').fontSize(11).fillColor('#000000').text(pRoman, startX, rowY + 5, { width: colW.period, align: 'center' });
        if (isConducted && slotLogs[0].submission_time) {
            doc.font('Helvetica').fontSize(5.8).fillColor('#64748B').text('Submitted Time:', startX, rowY + 20, { width: colW.period, align: 'center' });
            doc.font('Helvetica-Bold').fontSize(7).fillColor('#1E293B').text(formatTimeHM(slotLogs[0].submission_time), startX, rowY + 28, { width: colW.period, align: 'center' });
        }

        // Subject
        if (isConducted) {
            doc.font('Helvetica-Bold').fontSize(9.5).fillColor('#000000').text(slotLogs[0].subject_name || '', startX + colW.period + 4, rowY + 14, { width: colW.subject - 8, align: 'center' });
        }

        // Absentees & Bunked (3 Digits)
        const absX = startX + colW.period + colW.subject;
        if (isConducted) {
            const absenteesFull = slotLogs.filter(l => l.status === 'Absent').map(l => l.roll_number);
            if (absenteesFull.length > 0) {
                const prevHour = hourMap[slotName];
                let bunkersFull = [];
                if (prevHour) {
                    const prevPresentSet = new Set((allLogs || []).filter(l => l.hour_slot === prevHour && l.status === 'Present').map(l => l.roll_number));
                    bunkersFull = absenteesFull.filter(r => prevPresentSet.has(r));
                }
                const absentees3D = absenteesFull.map(r => r.length > 3 ? r.slice(-3) : r);
                const bunkers3D = bunkersFull.map(r => r.length > 3 ? r.slice(-3) : r);

                if (bunkers3D.length > 0) {
                    doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#DC2626').text(`Absentees: `, absX + 8, rowY + 7, { continued: true });
                    doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#000000').text(absentees3D.join(', '), { width: colW.absentees - 16 });
                    doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#C2410C').text(`Bunked: `, absX + 8, rowY + 22, { continued: true });
                    doc.font('Helvetica-Bold').fontSize(8.5).fillColor('#7C2D12').text(bunkers3D.join(', '), { width: colW.absentees - 16 });
                } else {
                    doc.font('Helvetica-Bold').fontSize(9).fillColor('#DC2626').text(`Absentees: `, absX + 8, rowY + 14, { continued: true });
                    doc.font('Helvetica-Bold').fontSize(9).fillColor('#000000').text(absentees3D.join(', '), { width: colW.absentees - 16 });
                }
            } else {
                const label = slotLogs.every(l => l.status === 'Leisure') ? 'Leisure Period (No Attendance)' : '100% Present (No Absentees)';
                doc.font('Helvetica-Bold').fontSize(9).fillColor('#16A34A').text(label, absX + 8, rowY + 14);
            }
        }

        // Total
        const totalX = absX + colW.absentees;
        if (isConducted) {
            const absCount = slotLogs.filter(l => l.status === 'Absent').length;
            doc.font('Helvetica-Bold').fontSize(12).fillColor('#000000').text(String(absCount), totalX, rowY + 13, { width: colW.total, align: 'center' });
        }

        // Faculty
        const facX = totalX + colW.total;
        if (isConducted) {
            doc.font('Helvetica-Bold').fontSize(9.5).fillColor('#000000').text((slotLogs[0].faculty_name || '').toUpperCase(), facX + 4, rowY + 14, { width: colW.faculty - 8, align: 'center' });
        }
    });

    // Bottom Box: All Roll Numbers (Full Unabbreviated)
    const bottomBoxY = tableTop + headerH + (6 * rowH) + 10;
    const bottomBoxH = 82;
    doc.rect(startX, bottomBoxY, tableWidth, bottomBoxH).lineWidth(1).stroke('#000000');
    doc.font('Helvetica-Bold').fontSize(9.5).fillColor('#000000').text(`All Roll Numbers (Sec-${sectionInfo.sec_name || 'LE'})`, startX, bottomBoxY + 7, { width: tableWidth, align: 'center' });

    let studentRolls = (enrolledStudents && enrolledStudents.length > 0) ? enrolledStudents.map(s => s.roll_number) : [];
    doc.font('Helvetica').fontSize(8).fillColor('#0F172A').text(studentRolls.join(',  '), startX + 12, bottomBoxY + 23, { width: tableWidth - 24, lineGap: 3.5 });

    // Authority Signatures
    const footerY = bottomBoxY + bottomBoxH + 18;
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#000000');
    doc.text('Coordinator', startX + 15, footerY);
    doc.text('HOS', startX + 240, footerY);
    doc.text(`HoD - ${sectionInfo.dept_name || 'CSE'}`, startX + 475, footerY);
    doc.text('Principal', startX + 695, footerY);
}

function generateDoeSingleSlipPDF(sectionInfo, date, hourSlot, sessionType, slotLogs, enrolledStudents) {
    return new Promise((resolve) => {
        const doc = new PDFDocument({ margin: 0, size: [297, 210], layout: 'portrait' });
        let buffers = [];
        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', () => resolve(Buffer.concat(buffers)));
        drawSingleDoeSlip(doc, 6, 6, 285, 198, sectionInfo, date, hourSlot, sessionType, slotLogs, enrolledStudents);
        doc.end();
    });
}

function drawSingleDoeSlip(doc, x, y, w, h, sectionInfo, date, hourSlot, sessionType, slotLogs, enrolledStudents) {
    doc.roundedRect(x, y, w, h, 6).lineWidth(0.8).stroke('#000000');

    // Logos
    doc.circle(x + 18, y + 15, 8.5).lineWidth(0.7).stroke('#000000');
    doc.font('Helvetica-Bold').fontSize(4.5).fillColor('#000000').text('ACE', x + 13.5, y + 13.5);

    doc.font('Helvetica-Bold').fontSize(9).fillColor('#000000').text('ACE', x, y + 5, { width: w, align: 'center' });
    doc.font('Helvetica-Bold').fontSize(7.5).text('Engineering College', x, y + 15, { width: w, align: 'center' });
    doc.font('Helvetica').fontSize(4.2).fillColor('#333333').text('Ghatkesar (M), Medchal Dist., Hyderabad -501 301.', x, y + 24, { width: w, align: 'center' });
    doc.font('Helvetica-Bold').fontSize(5.2).fillColor('#000000').text(`Dept. of ${sectionInfo.dept_name || 'CSE'}`, x, y + 31, { width: w, align: 'center' });

    // Sub-header 1: A.Y., Date, [FN/AN] with Tick Mark (✓)
    const [yr, mo, da] = (date || '2026-09-18').split('-');
    const nextYrShort = String(Number(yr.slice(-2)) + 1).padStart(2, '0');
    const subY1 = y + 39;

    doc.font('Helvetica-Bold').fontSize(5.5).fillColor('#000000').text(`A.Y.: ${yr}-${nextYrShort}`, x + 9, subY1);
    doc.text('Date : ', x + 82, subY1);
    doc.font('Helvetica-Bold').fontSize(6).fillColor('#1D4ED8').text(` ${da}-${mo}-${yr.slice(-2)} `, x + 98, subY1, { underline: true });

    const fnX = x + w - 42;
    doc.font('Helvetica-Bold').fontSize(5.5).fillColor('#000000').text('[FN/AN]', fnX, subY1);

    if (sessionType === 'Morning') {
        const tx = fnX + 3, ty = subY1 + 3;
        doc.moveTo(tx, ty).lineTo(tx + 2.2, ty + 3).lineTo(tx + 6.5, ty - 3.5).lineWidth(1.4).stroke('#000000');
    } else {
        const tx = fnX + 14, ty = subY1 + 3;
        doc.moveTo(tx, ty).lineTo(tx + 2.2, ty + 3).lineTo(tx + 6.5, ty - 3.5).lineWidth(1.4).stroke('#000000');
    }

    // Sub-header 2: Class & Period + Submitted Time
    const totalStrength = (enrolledStudents || []).length;
    doc.font('Helvetica-Bold').fontSize(6.5).fillColor('#000000').text(`${sectionInfo.branch_name || 'B.Tech'}: ${sectionInfo.batch_year_name || 'II-I'} (${sectionInfo.sec_name || 'LE'})-(${totalStrength})`, x + 9, y + 48, { width: w - 18, align: 'center' });

    const pRoman = getSlotRoman(hourSlot);
    const subTimeStr = (slotLogs && slotLogs.length > 0 && slotLogs[0].submission_time) ? formatTimeHM(slotLogs[0].submission_time) : formatTimeHM(new Date().toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true }));
    doc.font('Helvetica-Bold').fontSize(5.5).fillColor('#1E3A8A').text(`Period : ${pRoman} (${hourSlot})    |    Submitted Time : ${subTimeStr}`, x + 9, y + 56, { width: w - 18, align: 'center' });

    doc.moveTo(x, y + 64).lineTo(x + w, y + 64).lineWidth(0.7).stroke('#000000');

    // Absentees Count
    const isConducted = slotLogs && slotLogs.length > 0;
    const absenteesFull = isConducted ? slotLogs.filter(l => l.status === 'Absent').map(l => l.roll_number) : [];
    doc.font('Helvetica-Bold').fontSize(5.5).fillColor('#000000').text('Absentees Nos.', x + 9, y + 68);
    doc.moveTo(x + 55, y + 74).lineTo(x + 92, y + 74).lineWidth(0.6).stroke('#000000');
    doc.font('Helvetica-Bold').fontSize(7.5).fillColor('#1D4ED8').text(String(absenteesFull.length), x + 68, y + 66.5);

    // 14x5 Grid with Blue Circles
    const gridTop = y + 78, gridW = w - 16, gridX = x + 8, numCols = 14, numRows = Math.max(5, Math.ceil(enrolledStudents.length / 14));
    const cellW = gridW / numCols, cellH = 75 / numRows;
    let rollNumbers = (enrolledStudents && enrolledStudents.length > 0) ? enrolledStudents.map(s => s.roll_number) : [];
    const absenteesSet = new Set(absenteesFull);

    for (let r = 0; r < numRows; r++) {
        for (let c = 0; c < numCols; c++) {
            const idx = (r * numCols) + c;
            const cX = gridX + (c * cellW);
            const cY = gridTop + (r * cellH);
            doc.rect(cX, cY, cellW, cellH).lineWidth(0.4).stroke('#000000');

            if (idx < rollNumbers.length) {
                const fullRoll = rollNumbers[idx];
                const roll2D = fullRoll.length > 2 ? fullRoll.slice(-2) : fullRoll;
                const isAbsent = absenteesSet.has(fullRoll) || absenteesSet.has(roll2D);
                doc.font('Helvetica').fontSize(Math.min(5.8, cellH * 0.55)).fillColor('#000000').text(roll2D, cX, cY + cellH * 0.25, { width: cellW, align: 'center' });

                if (isAbsent) {
                    doc.circle(cX + (cellW / 2), cY + (cellH / 2), Math.min(5.2, cellH * 0.42)).lineWidth(0.9).stroke('#1D4ED8');
                }
            }
        }
    }

    // Footer: Faculty Name ONLY
    const facName = isConducted ? (slotLogs[0].faculty_name || 'Faculty Name') : '________________';
    const footerY = gridTop + (numRows * cellH) + 8;
    doc.font('Helvetica-Bold').fontSize(5.8).fillColor('#000000').text('Faculty Name:', x + 9, footerY);
    doc.font('Helvetica-Bold').fontSize(6.5).fillColor('#1D4ED8').text(` ${facName} `, x + 54, footerY - 0.5, { underline: true });
}

// Clean Routes
app.get('/doe', (req, res) => res.sendFile(path.join(__dirname, 'public', 'doe.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    res.status(err.status || 400).json({ success: false, message: err.status === 413 ? 'Uploaded photo is too large.' : 'Invalid request. Check the supplied fields.' });
});

async function initialize() {
    // Upgrade existing accounts without changing their passwords.
    for (const [table, key] of [['admin_users', 'admin_id'], ['faculty', 'faculty_id']]) {
        const accounts = await all(db, `SELECT ${key} AS id, password FROM ${table}`);
        for (const account of accounts) {
            if (!account.password.startsWith('scrypt$')) await run(db, `UPDATE ${table} SET password=? WHERE ${key}=?`, [hashPassword(account.password), account.id]);
        }
    }
}
async function start() {
    await initialize();
    return app.listen(PORT, () => console.log(`Attendance System running on port ${PORT}`));
}
if (require.main === module) start().catch(err => { console.error(err); process.exit(1); });
module.exports = { app, db, start, initialize };
