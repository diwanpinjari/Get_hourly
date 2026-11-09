require('dotenv').config();
const express = require('express');
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');
const { hashPassword, verifyPassword } = require('./lib/auth');
const { createDatabase } = require('./lib/db');
const { saveAttendance, transaction, run, get, all } = require('./lib/data');
const { createSession, getSession, deleteSession, setOtp, takeOtp, hitRateLimit, cleanup } = require('./lib/store');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const dbPath = process.env.DATA_DIR
    ? path.join(process.env.DATA_DIR, 'attendance.db')
    : path.join(__dirname, 'attendance.db');
const db = createDatabase({
    url: process.env.TURSO_DATABASE_URL || process.env.LIBSQL_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
    filename: dbPath
});

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true, limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', async (req, res, next) => {
    if (/login$|request-otp$|verify-otp$|request-delete-otp$/.test(req.path)) {
        const key = `${req.ip}:${req.path}`;
        try {
            if (!(await hitRateLimit(db, key, 20, 10 * 60 * 1000))) {
                return res.status(429).json({ success: false, message: 'Too many attempts. Retry in ten minutes.' });
            }
        } catch (err) {
            console.error('Rate limit error:', err.message);
        }
    }
    next();
});

function validDate(value) {
    return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
}
app.use('/api', (req, res, next) => {
    if (['POST', 'PUT'].includes(req.method) && req.path !== '/logout' && (!req.body || typeof req.body !== 'object' || Array.isArray(req.body))) return res.status(400).json({ success: false, message: 'JSON object required.' });
    for (const field of ['name', 'email', 'password', 'username', 'faculty_id', 'admin_id', 'doe_name', 'doe_email', 'otp', 'subjectName']) {
        if (req.body?.[field] !== undefined && typeof req.body[field] !== 'string') return res.status(400).json({ success: false, message: `Invalid ${field}.` });
    }
    const { from_date, to_date } = req.query;
    if ((from_date && !validDate(from_date)) || (to_date && !validDate(to_date)) || (from_date && to_date && from_date > to_date)) return res.status(400).json({ success: false, message: 'Invalid date range.' });
    next();
});

async function issueSession(res, role, user) {
    const token = crypto.randomBytes(32).toString('hex');
    await createSession(db, token, role, user.id, Date.now() + 8 * 60 * 60 * 1000);
    res.cookie(`${role}_session`, token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 });
}
app.use('/api', async (req, res, next) => {
    const mentorProtected = req.path.startsWith('/mentor/')
        && !['/mentor/login', '/mentor/request-otp', '/mentor/verify-otp'].includes(req.path);
    const role = req.path.startsWith('/admin/') && req.path !== '/admin/login' ? 'admin'
        : (/^\/(faculty\/|attendance\/|students$)/.test(req.path) ? 'faculty'
        : (mentorProtected ? 'mentor' : null));
    if (!role) return next();
    const cookie = (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith(`${role}_session=`));
    const token = cookie?.slice(cookie.indexOf('=') + 1);
    try {
        const session = await getSession(db, token);
        if (!session || session.role !== role) {
            await deleteSession(db, token);
            return res.status(401).json({ success: false, message: 'Session expired. Please log in again.' });
        }
        const auth = { user: { id: session.user_id } };
        req.auth = auth;
        if (role === 'mentor') {
            const mentor = await get(db, 'SELECT mentor_id, name, email FROM mentors WHERE mentor_id = ?', [auth.user.id]);
            if (!mentor) return res.status(401).json({ success: false, message: 'Mentor account unavailable. Please log in again.' });
            auth.user.name = mentor.name;
            auth.user.email = mentor.email;
            return next();
        }
        if (role === 'faculty') {
            if (req.query.faculty_id && req.query.faculty_id !== auth.user.id) return res.status(403).json({ message: 'Faculty access denied.' });
            if (req.body) {
                req.body.facultyId = auth.user.id;
                req.body.faculty_id = auth.user.id;
            }
        }
        const table = role === 'admin' ? 'admin_users' : 'faculty';
        const key = role === 'admin' ? 'admin_id' : 'faculty_id';
        const account = await get(db, `SELECT ${key}, name${role === 'admin' ? ', email' : ''} FROM ${table} WHERE ${key}=?`, [auth.user.id]);
        if (!account) return res.status(401).json({ success: false, message: 'Account unavailable. Please log in again.' });
        auth.user.name = account.name;
        if (role === 'admin') {
            auth.user.email = account.email;
            req.headers['x-admin-email'] = account.email;
        } else if (req.body) req.body.facultyName = account.name;
        next();
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to verify session.' });
    }
});
app.post('/api/logout', async (req, res) => {
    for (const role of ['admin', 'faculty', 'mentor']) {
        const cookie = (req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith(`${role}_session=`));
        if (cookie) await deleteSession(db, cookie.slice(cookie.indexOf('=') + 1));
        res.clearCookie(`${role}_session`);
    }
    res.json({ success: true });
});
app.use('/api', (req, res, next) => {
    if (req.body && typeof req.body.password === 'string' && !['/login', '/admin/login', '/mentor/login'].includes(req.path)) {
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
const ATTENDANCE_THRESHOLD = Math.min(100, Math.max(1, Number(process.env.ATTENDANCE_THRESHOLD) || 75));

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
const { initializeSchema } = require("./lib/schema");

// Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

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

async function verifyAdminOtp(adminEmail, inputOtp) {
    if (!adminEmail || !inputOtp) return false;
    const email = adminEmail.toLowerCase().trim();
    const stored = await get(db, `SELECT otp, expires_at FROM otp_codes WHERE email = ? AND purpose = 'delete'`, [email]);
    if (!stored || Date.now() > stored.expires_at) {
        await run(db, `DELETE FROM otp_codes WHERE email = ? AND purpose = 'delete'`, [email]);
        return false;
    }
    if (stored.otp !== inputOtp.trim()) return false;
    await run(db, `DELETE FROM otp_codes WHERE email = ? AND purpose = 'delete'`, [email]);
    return true;
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

app.post('/api/login', async (req, res) => {
    const { faculty_id, password } = req.body;
    try {
        const row = await get(db, `SELECT faculty_id, name, password FROM faculty WHERE TRIM(UPPER(faculty_id)) = TRIM(UPPER(?))`, [faculty_id]);
        if (!row || !verifyPassword(password, row.password)) return res.status(401).json({ success: false, message: 'Invalid Faculty Credentials' });
        await issueSession(res, 'faculty', { id: row.faculty_id, name: row.name });
        res.json({ success: true, faculty: { id: row.faculty_id, name: row.name } });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Login unavailable. Please retry.' });
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Enter both Admin ID and Password.' });
    try {
        const row = await get(db, `SELECT admin_id, name, email, role, password FROM admin_users WHERE TRIM(UPPER(admin_id)) = TRIM(UPPER(?))`, [username.trim()]);
        if (!row || !verifyPassword(password.trim(), row.password)) return res.status(401).json({ success: false, message: 'Invalid Admin Credentials' });
        await issueSession(res, 'admin', { id: row.admin_id, email: row.email });
        res.json({ success: true, admin: { id: row.admin_id, name: row.name, email: row.email, role: row.role } });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Login unavailable. Please retry.' });
    }
});

// =========================================================================
// MENTOR AUTHENTICATION (password + email OTP fallback)
// =========================================================================

app.post('/api/mentor/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Enter your email and password.' });
    try {
        const mentor = await get(db, `SELECT mentor_id, name, email, password FROM mentors WHERE LOWER(email) = LOWER(?)`, [email.trim()]);
        if (!mentor || !mentor.password || !verifyPassword(password, mentor.password)) {
            return res.status(401).json({ success: false, message: 'Invalid mentor credentials. Use email OTP if you have not set a password.' });
        }
        await issueSession(res, 'mentor', { id: String(mentor.mentor_id), name: mentor.name });
        res.json({ success: true, mentor: { id: mentor.mentor_id, name: mentor.name, email: mentor.email } });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Login unavailable. Please retry.' });
    }
});

app.post('/api/mentor/request-otp', async (req, res) => {
    const email = (req.body.email || '').toLowerCase().trim();
    if (!email) return res.status(400).json({ success: false, message: 'Enter your registered email.' });
    try {
        const mentor = await get(db, `SELECT mentor_id, name, email FROM mentors WHERE LOWER(email) = ?`, [email]);
        if (mentor) {
            const otp = crypto.randomInt(100000, 1000000).toString();
            await setOtp(db, email, 'mentor', otp, Date.now() + 10 * 60 * 1000);
            try {
                await transporter.sendMail({
                    from: '"ACE Mentor Portal" <no-reply@college.edu>',
                    to: mentor.email,
                    subject: '[Mentor Portal] Login OTP',
                    text: `Dear ${mentor.name},\n\nYour one-time login code for the Mentor Attendance Portal is:\n\n${otp}\n\nThis code is valid for 10 minutes. Do not share it.`
                });
            } catch (mailErr) {
                await takeOtp(db, email, 'mentor').catch(() => {});
                return res.status(502).json({ success: false, message: 'Unable to send the OTP email. Please try again.' });
            }
        }
        // Do not reveal whether an email is registered.
        res.json({ success: true, message: 'If this email is registered as a mentor, an OTP has been sent.' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to request an OTP.' });
    }
});

app.post('/api/mentor/verify-otp', async (req, res) => {
    const email = (req.body.email || '').toLowerCase().trim();
    const otp = (req.body.otp || '').trim();
    if (!email || !otp) return res.status(400).json({ success: false, message: 'Enter your email and OTP.' });
    try {
        const mentor = await get(db, `SELECT mentor_id, name, email FROM mentors WHERE LOWER(email) = ?`, [email]);
        if (!mentor) return res.status(401).json({ success: false, message: 'Invalid or expired OTP.' });
        const record = await get(db, `SELECT otp, expires_at FROM otp_codes WHERE email = ? AND purpose = 'mentor'`, [email]);
        if (!record || Date.now() > record.expires_at || record.otp !== otp) {
            return res.status(401).json({ success: false, message: 'Invalid or expired OTP. Request a new code.' });
        }
        await takeOtp(db, email, 'mentor');
        await issueSession(res, 'mentor', { id: String(mentor.mentor_id), name: mentor.name });
        res.json({ success: true, mentor: { id: mentor.mentor_id, name: mentor.name, email: mentor.email } });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to verify the OTP.' });
    }
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
    await setOtp(db, admin_email.toLowerCase().trim(), 'delete', generatedOtp, expiresAt);

    try {
        await transporter.sendMail({
            from: '"College Admin Security" <no-reply@college.edu>',
            to: admin_email,
            subject: `[OTP Verification] Delete ${entity_type.toUpperCase()}`,
            text: `Your OTP to authorize deletion of this ${entity_type} is: ${generatedOtp}\nValid for 5 minutes.`
        });
        res.json({ success: true, message: `Deletion OTP sent to ${admin_email}` });
    } catch (err) {
        await takeOtp(db, admin_email.toLowerCase().trim(), 'delete').catch(() => {});
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
app.delete('/api/admin/branches/:id', async (req, res) => {
    if (!(await verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp']))) {
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
app.delete('/api/admin/departments/:id', async (req, res) => {
    if (!(await verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp']))) {
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
app.delete('/api/admin/batch-years/:id', async (req, res) => {
    if (!(await verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp']))) {
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
app.delete('/api/admin/sections/:id', async (req, res) => {
    if (!(await verifyAdminOtp(req.headers['x-admin-email'], req.headers['x-delete-otp']))) {
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
    db.all(`SELECT mentor_id, name, email,
                CASE WHEN password IS NOT NULL AND password != '' THEN 1 ELSE 0 END AS has_password
            FROM mentors ORDER BY name ASC`, [], (err, rows) => res.json(rows || []));
});
app.post('/api/admin/mentors', (req, res) => {
    const password = typeof req.body.password === 'string' ? req.body.password.trim() : '';
    db.run(`INSERT INTO mentors (name, email, password) VALUES (?, ?, ?)`,
        [req.body.name.trim(), req.body.email.trim(), password], function(err) {
        if (err) return res.status(400).json({ success: false, message: 'Email already registered.' });
        res.json({ success: true, message: password ? 'Mentor registered with a login password.' : 'Mentor registered. They can log in with an email OTP.' });
    });
});
app.put('/api/admin/mentors/:id', (req, res) => {
    const password = typeof req.body.password === 'string' ? req.body.password.trim() : '';
    let query = `UPDATE mentors SET name = ?, email = ?`;
    const params = [req.body.name.trim(), req.body.email.trim()];
    if (password) { query += `, password = ?`; params.push(password); }
    query += ` WHERE mentor_id = ?`;
    params.push(req.params.id);
    db.run(query, params, function(err) {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: password ? 'Mentor updated and password changed.' : 'Mentor updated.' });
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
    await transaction(db, async connection => {
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
// MENTOR PORTAL: ASSIGNED SECTIONS, STUDENT ATTENDANCE, CALL-LIST CSV
// =========================================================================

function csvCell(value) {
    let text = String(value ?? '');
    if (/^[=+@-]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
}

function buildCallListCsv(rows) {
    const lines = [
        ['Roll No', 'Student Name', 'Parent Number', 'Attendance %', 'Present', 'Absent', 'Total Sessions']
            .map(csvCell).join(',')
    ];
    for (const row of rows) {
        lines.push([
            row.roll_number,
            row.name,
            row.parent_number || '',
            row.percentage === null || row.percentage === undefined ? '' : Number(row.percentage).toFixed(1),
            row.present,
            row.absent,
            row.total
        ].map(csvCell).join(','));
    }
    return lines.join('\r\n');
}

async function getMentorSections(mentorId) {
    return all(db, `
        SELECT sm.section_id, sm.branch_id, sm.dept_id, sm.batch_year_id,
               b.name AS branch_name, d.name AS dept_name, by.name AS batch_year_name, s.name AS sec_name,
               (SELECT COUNT(*) FROM students st
                 WHERE st.branch_id = sm.branch_id AND st.dept_id = sm.dept_id
                   AND st.batch_year_id = sm.batch_year_id AND st.section_id = sm.section_id) AS student_count
        FROM section_mentors sm
        JOIN branches b ON b.id = sm.branch_id
        JOIN departments d ON d.id = sm.dept_id
        JOIN batch_years by ON by.id = sm.batch_year_id
        JOIN sections s ON s.id = sm.section_id
        WHERE sm.mentor_id = ?
        ORDER BY b.name ASC, d.name ASC, by.name ASC, s.name ASC
    `, [mentorId]);
}

async function getMentorSection(mentorId, sectionId) {
    const sections = await getMentorSections(mentorId);
    return sections.find(section => Number(section.section_id) === Number(sectionId)) || null;
}

async function buildSectionAttendance(section, options = {}) {
    const fromDate = validDate(options.fromDate) ? options.fromDate : '';
    const toDate = validDate(options.toDate) ? options.toDate : '';
    const threshold = Number.isFinite(Number(options.threshold))
        ? Math.min(100, Math.max(1, Number(options.threshold)))
        : ATTENDANCE_THRESHOLD;
    const scope = [section.branch_id, section.dept_id, section.batch_year_id, section.section_id];

    let logDateFilter = '';
    const logDateParams = [];
    if (fromDate) { logDateFilter += ' AND al.date >= ?'; logDateParams.push(fromDate); }
    if (toDate) { logDateFilter += ' AND al.date <= ?'; logDateParams.push(toDate); }

    const students = await all(db, `
        SELECT st.roll_number, st.name, st.phone_number, st.parent_number,
               COALESCE(SUM(CASE WHEN al.status = 'Present' THEN 1 ELSE 0 END), 0) AS present,
               COALESCE(SUM(CASE WHEN al.status = 'Absent' THEN 1 ELSE 0 END), 0) AS absent,
               COUNT(al.id) AS total
        FROM students st
        LEFT JOIN attendance_logs al
               ON al.roll_number = st.roll_number
              AND al.branch_id = st.branch_id
              AND al.dept_id = st.dept_id
              AND al.batch_year_id = st.batch_year_id
              AND al.section_id = st.section_id
              AND al.status != 'Leisure'
              ${logDateFilter}
        WHERE st.branch_id = ? AND st.dept_id = ? AND st.batch_year_id = ? AND st.section_id = ?
        GROUP BY st.roll_number, st.name, st.phone_number, st.parent_number
        ORDER BY st.roll_number ASC
    `, [...logDateParams, ...scope]);

    const rows = students.map(student => {
        const present = Number(student.present) || 0;
        const absent = Number(student.absent) || 0;
        const total = present + absent;
        const percentage = total ? Math.round((present / total) * 1000) / 10 : null;
        return {
            roll_number: student.roll_number,
            name: student.name,
            phone_number: student.phone_number || '',
            parent_number: student.parent_number || '',
            present,
            absent,
            total,
            percentage,
            below_threshold: total > 0 && percentage < threshold
        };
    });

    let sessionDateFilter = '';
    const sessionDateParams = [];
    if (fromDate) { sessionDateFilter += ' AND date >= ?'; sessionDateParams.push(fromDate); }
    if (toDate) { sessionDateFilter += ' AND date <= ?'; sessionDateParams.push(toDate); }

    const sessions = await all(db, `
        SELECT date, hour_slot, subject_name, faculty_name, submission_time,
               SUM(CASE WHEN status = 'Present' THEN 1 ELSE 0 END) AS present_count,
               SUM(CASE WHEN status = 'Absent' THEN 1 ELSE 0 END) AS absent_count,
               COUNT(*) AS total_count,
               CASE WHEN MIN(status) = 'Leisure' AND MAX(status) = 'Leisure' THEN 1 ELSE 0 END AS is_leisure
        FROM attendance_logs
        WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
          ${sessionDateFilter}
        GROUP BY date, hour_slot, subject_name, faculty_name, submission_time
        ORDER BY date DESC, hour_slot ASC
    `, [...scope, ...sessionDateParams]);

    const withData = rows.filter(row => row.total > 0);
    const averageAttendance = withData.length
        ? Math.round((withData.reduce((sum, row) => sum + row.percentage, 0) / withData.length) * 10) / 10
        : 0;

    return {
        section,
        students: rows,
        sessions: sessions.map(session => ({
            ...session,
            present_count: Number(session.present_count) || 0,
            absent_count: Number(session.absent_count) || 0,
            total_count: Number(session.total_count) || 0,
            is_leisure: Boolean(Number(session.is_leisure))
        })),
        summary: {
            total_students: rows.length,
            students_with_data: withData.length,
            average_attendance: averageAttendance,
            below_threshold: rows.filter(row => row.below_threshold).length,
            conducted_sessions: sessions.filter(session => !Number(session.is_leisure)).length,
            threshold
        }
    };
}

async function buildDailyCallList(section, targetDate, threshold = ATTENDANCE_THRESHOLD) {
    const scope = [section.branch_id, section.dept_id, section.batch_year_id, section.section_id];
    const logs = await all(db, `
        SELECT roll_number, date, hour_slot, status
        FROM attendance_logs
        WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
          AND status != 'Leisure' AND date <= ?
        ORDER BY date ASC, hour_slot ASC
    `, [...scope, targetDate]);

    const conductedHours = new Map();
    const studentStatus = new Map();
    for (const log of logs) {
        if (!conductedHours.has(log.date)) conductedHours.set(log.date, new Set());
        conductedHours.get(log.date).add(log.hour_slot);
        if (!studentStatus.has(log.roll_number)) studentStatus.set(log.roll_number, new Map());
        const byDate = studentStatus.get(log.roll_number);
        if (!byDate.has(log.date)) byDate.set(log.date, new Map());
        byDate.get(log.date).set(log.hour_slot, log.status);
    }

    const conductedDates = [...conductedHours.keys()].sort();
    const conductedDays = conductedDates.length;

    const students = await all(db, `
        SELECT roll_number, name, phone_number, parent_number
        FROM students
        WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
        ORDER BY roll_number ASC
    `, scope);

    const rows = students.map(student => {
        const byDate = studentStatus.get(student.roll_number) || new Map();
        let completeDays = 0;
        for (const day of conductedDates) {
            const hours = conductedHours.get(day);
            const statuses = byDate.get(day) || new Map();
            let complete = true;
            for (const hour of hours) {
                if (statuses.get(hour) !== 'Present') {
                    complete = false;
                    break;
                }
            }
            if (complete) completeDays += 1;
        }
        const dailyPercentage = conductedDays ? Math.round((completeDays / conductedDays) * 1000) / 10 : null;
        const todayStatuses = byDate.get(targetDate) || new Map();
        const absentHours = [...todayStatuses.entries()]
            .filter(([, status]) => status === 'Absent')
            .map(([hour]) => hour)
            .sort();
        return {
            roll_number: student.roll_number,
            name: student.name,
            phone_number: student.phone_number || '',
            parent_number: student.parent_number || '',
            complete_days: completeDays,
            conducted_days: conductedDays,
            daily_percentage: dailyPercentage,
            absent_hours: absentHours,
            today_absent: absentHours.length > 0,
            below_threshold: dailyPercentage !== null && dailyPercentage < threshold
        };
    });

    const absentees = rows.filter(row => row.today_absent).sort((a, b) => {
        if (a.below_threshold !== b.below_threshold) return a.below_threshold ? -1 : 1;
        const diff = (a.daily_percentage ?? 101) - (b.daily_percentage ?? 101);
        return diff || a.roll_number.localeCompare(b.roll_number);
    });

    return {
        section,
        date: targetDate,
        conducted_days: conductedDays,
        students: rows,
        absentees,
        high_priority: absentees.filter(row => row.below_threshold).length,
        threshold
    };
}

function buildDailyCallListCsv(absentees, threshold = ATTENDANCE_THRESHOLD) {
    const lines = [
        ['Roll No', 'Student Name', 'Parent Number', 'Daily Attendance %', 'Complete Days', 'Conducted Days', "Today's Absent Hours", `Priority (HIGH = below ${threshold}%)`]
            .map(csvCell).join(',')
    ];
    for (const row of absentees) {
        lines.push([
            row.roll_number,
            row.name,
            row.parent_number || '',
            row.daily_percentage === null || row.daily_percentage === undefined ? '' : Number(row.daily_percentage).toFixed(1),
            row.complete_days,
            row.conducted_days,
            (row.absent_hours || []).join('; '),
            row.below_threshold ? 'HIGH' : 'NORMAL'
        ].map(csvCell).join(','));
    }
    return lines.join('\r\n');
}

app.get('/api/mentor/sections', async (req, res) => {
    try {
        const sections = await getMentorSections(req.auth.user.id);
        res.json({
            success: true,
            mentor: { id: req.auth.user.id, name: req.auth.user.name, email: req.auth.user.email },
            sections
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to load your sections.' });
    }
});

app.get('/api/mentor/sections/:section_id/attendance', async (req, res) => {
    try {
        const section = await getMentorSection(req.auth.user.id, req.params.section_id);
        if (!section) return res.status(403).json({ success: false, message: 'This section is not assigned to you.' });
        const { from_date, to_date, threshold } = req.query;
        if ((from_date && !validDate(from_date)) || (to_date && !validDate(to_date)) || (from_date && to_date && from_date > to_date)) {
            return res.status(400).json({ success: false, message: 'Invalid date range.' });
        }
        const data = await buildSectionAttendance(section, { fromDate: from_date, toDate: to_date, threshold });
        res.json({ success: true, ...data });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to load attendance.' });
    }
});

app.get('/api/mentor/sections/:section_id/attendance.csv', async (req, res) => {
    try {
        const section = await getMentorSection(req.auth.user.id, req.params.section_id);
        if (!section) return res.status(403).json({ success: false, message: 'This section is not assigned to you.' });
        const { from_date, to_date, threshold } = req.query;
        if ((from_date && !validDate(from_date)) || (to_date && !validDate(to_date)) || (from_date && to_date && from_date > to_date)) {
            return res.status(400).json({ success: false, message: 'Invalid date range.' });
        }
        const data = await buildSectionAttendance(section, { fromDate: from_date, toDate: to_date, threshold });
        const below = data.students.filter(student => student.below_threshold);
        const safeSection = String(section.sec_name || 'section').replace(/[^A-Za-z0-9_-]+/g, '_');
        const stamp = new Date().toISOString().slice(0, 10);
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="Below_${data.summary.threshold}_Attendance_${safeSection}_${stamp}.csv"`);
        res.send('\uFEFF' + buildCallListCsv(below));
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to export attendance.' });
    }
});

// =========================================================================
// DAILY MENTOR CALL LIST (once per section per day)
// =========================================================================

app.get('/api/cron/daily-call-list', async (req, res) => {
    const cronSecret = process.env.CRON_SECRET;
    const providedSecret = req.query.secret || String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const isVercelCron = req.headers['x-vercel-cron'] === '1';
    const authorized = cronSecret ? providedSecret === cronSecret : isVercelCron;
    if (!authorized) {
        return res.status(401).json({ success: false, message: 'Unauthorized.' });
    }

    const targetDate = validDate(req.query.date)
        ? req.query.date
        : new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

    try {
        const sections = await all(db, `
            SELECT DISTINCT sm.section_id, sm.branch_id, sm.dept_id, sm.batch_year_id,
                   b.name AS branch_name, d.name AS dept_name, by.name AS batch_year_name, s.name AS sec_name,
                   m.mentor_id, m.name AS mentor_name, m.email AS mentor_email,
                   d.doe_name, d.doe_email
            FROM attendance_logs al
            JOIN section_mentors sm
              ON sm.branch_id = al.branch_id AND sm.dept_id = al.dept_id
             AND sm.batch_year_id = al.batch_year_id AND sm.section_id = al.section_id
            JOIN mentors m ON m.mentor_id = sm.mentor_id
            JOIN branches b ON b.id = al.branch_id
            JOIN departments d ON d.id = al.dept_id
            JOIN batch_years by ON by.id = al.batch_year_id
            JOIN sections s ON s.id = al.section_id
            WHERE al.date = ? AND al.status != 'Leisure'
        `, [targetDate]);

        let sent = 0;
        let skipped = 0;
        let failed = 0;
        for (const section of sections) {
            try {
                const alreadySent = await get(db,
                    'SELECT sent_at FROM daily_call_list_log WHERE section_id = ? AND date = ?',
                    [section.section_id, targetDate]);
                if (alreadySent || !section.mentor_email) {
                    skipped += 1;
                    continue;
                }

                const data = await buildDailyCallList(section, targetDate, ATTENDANCE_THRESHOLD);
                const logs = await all(db, `
                    SELECT hour_slot, subject_name, faculty_name, roll_number, status, submission_time
                    FROM attendance_logs
                    WHERE date = ? AND branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
                    ORDER BY hour_slot ASC, roll_number ASC
                `, [targetDate, section.branch_id, section.dept_id, section.batch_year_id, section.section_id]);
                const enrolled = await all(db, `
                    SELECT roll_number FROM students
                    WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ?
                    ORDER BY roll_number ASC
                `, [section.branch_id, section.dept_id, section.batch_year_id, section.section_id]);

                const attachments = [];
                try {
                    const pdf = await generateSinglePageHorizontalPDF(section, targetDate, logs, enrolled);
                    attachments.push({ filename: `Attendance_Statement_${targetDate}.pdf`, content: pdf });
                } catch (pdfError) {
                    console.error('Daily attendance PDF failed:', pdfError.message);
                }

                const photoRow = await get(db,
                    'SELECT photo FROM attendance_photos WHERE section_id = ? AND date = ?',
                    [section.section_id, targetDate]);
                if (photoRow?.photo) {
                    const base64 = String(photoRow.photo).replace(/^data:image\/\w+;base64,/, '');
                    attachments.push({
                        filename: `Classroom_Proof_${targetDate}.jpg`,
                        content: Buffer.from(base64, 'base64')
                    });
                }

                if (data.absentees.length) {
                    attachments.push({
                        filename: `Daily_Call_List_${targetDate}.csv`,
                        content: Buffer.from('\uFEFF' + buildDailyCallListCsv(data.absentees, ATTENDANCE_THRESHOLD), 'utf8')
                    });
                }

                const body = data.absentees.length
                    ? `Respected Mentor (${section.mentor_name}),\n\nDaily attendance summary for ${targetDate}.\n\nAbsentees today: ${data.absentees.length}\nHigh priority (daily attendance below ${ATTENDANCE_THRESHOLD}%): ${data.high_priority}\n\nAttendance % is calculated from complete days (present in all conducted hours), not hourly.\nHigh-priority absentees are listed first and marked HIGH in the CSV.\n\nAttached: attendance statement, classroom photo, and daily call-list CSV.`
                    : `Respected Mentor (${section.mentor_name}),\n\nDaily attendance summary for ${targetDate}.\n\nNo students were absent today.\n\nAttached: attendance statement and classroom photo.`;

                await transporter.sendMail({
                    from: '"ACE College Attendance" <no-reply@college.edu>',
                    to: section.mentor_email,
                    subject: `[Daily Call List] ${section.branch_name} ${section.dept_name} Sec-${section.sec_name} — ${targetDate}`,
                    text: body,
                    attachments
                });
                await run(db,
                    'INSERT OR IGNORE INTO daily_call_list_log (section_id, date, sent_at) VALUES (?, ?, ?)',
                    [section.section_id, targetDate, Date.now()]);
                sent += 1;
            } catch (sectionError) {
                failed += 1;
                console.error(`Daily call list failed for section ${section.section_id}:`, sectionError.message);
            }
        }

        res.json({ success: true, date: targetDate, sections: sections.length, sent, skipped, failed });
    } catch (err) {
        console.error('Daily call list job failed:', err.message);
        res.status(500).json({ success: false, message: 'Unable to send daily call lists.' });
    }
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

app.post('/api/attendance/submit', async (req, res) => {
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

    try {
        const existingLock = await get(db, lockCheckQuery, [classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id, hourSlot, date]);
        if (existingLock && existingLock.faculty_id !== facultyId) {
            return res.status(403).json({
                success: false,
                message: `Access Denied: ${hourSlot} was already submitted by ${existingLock.faculty_name} (${existingLock.faculty_id}).`
            });
        }

        const sectionInfo = await get(db, sectionQuery, [classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id]);
        if (!sectionInfo) {
            return res.status(400).json({ success: false, message: "No mentor assigned to this section. Contact administrator." });
        }

        try {
            await saveAttendance(db, req.body, submissionTime);
        } catch (writeError) {
            return res.status(409).json({ success: false, message: writeError.message });
        }

        // Keep the latest classroom photo per section/day so the once-a-day
        // call-list email can attach it after the college day is over.
        try {
            await run(db, `
                INSERT INTO attendance_photos (section_id, date, hour_slot, photo, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(section_id, date) DO UPDATE SET
                    hour_slot = excluded.hour_slot,
                    photo = excluded.photo,
                    created_at = excluded.created_at
            `, [classDetails.section_id, date, hourSlot, classroomPhoto, Date.now()]);
        } catch (photoError) {
            console.error('Classroom photo storage failed:', photoError.message);
        }

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
        const allTodayLogs = await all(db, logsQuery, [date, classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id]);
        const enrolledStudents = await all(db, `SELECT roll_number FROM students WHERE branch_id = ? AND dept_id = ? AND batch_year_id = ? AND section_id = ? ORDER BY roll_number ASC`,
            [classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id]);

        // Dispatch reports after the database write, but before responding so serverless
        // runtimes do not freeze the function mid-email.
        try {
            const mentorPdfBuffer = await generateSinglePageHorizontalPDF(sectionInfo, date, allTodayLogs, enrolledStudents || []);
            const mentorAttachments = [{ filename: `Attendance_Statement_${date}.pdf`, content: mentorPdfBuffer }];
            if (photoBuffer) {
                mentorAttachments.push({
                    filename: `Classroom_Proof_${date}_${hourSlot.replace(/\s+/g, '_')}.jpg`,
                    content: photoBuffer
                });
            }

            // The call-list CSV is sent once per day by the daily summary job,
            // not on every hourly submission.
            await transporter.sendMail({
                from: '"ACE College Attendance" <no-reply@college.edu>',
                to: sectionInfo.mentor_email,
                subject: `[Attendance Statement + Photo] ${sectionInfo.branch_name} ${sectionInfo.dept_name} Sec-${sectionInfo.sec_name} (${hourSlot})`,
                text: `Respected Mentor (${sectionInfo.mentor_name}),\n\nAttendance for ${hourSlot} was recorded at ${submissionTime} by ${facultyName}.\n\nAttached is the official statement and watermarked classroom photo.`,
                attachments: mentorAttachments
            });

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
        } catch (emailError) {
            console.error("Email dispatch failed:", emailError.message);
        }

        res.json({ success: true, message: `Attendance for ${hourSlot} recorded successfully!` });
    } catch (err) {
        console.error('Attendance submission error:', err.message);
        if (!res.headersSent) res.status(500).json({ success: false, message: 'Unable to record attendance. Please retry.' });
    }
});

// =========================================================================
// 6. DOE OTP AUTHENTICATION & BATCH 8-UP SLIP ROUTES
// =========================================================================

// 1. Send OTP to Respective Department DOE
app.post('/api/doe/request-otp', async (req, res) => {
    const { dept_id, email } = req.body;

    try {
        const dept = await get(db, `SELECT id, name, doe_name, doe_email FROM departments WHERE id = ?`, [dept_id]);
        if (!dept || !dept.doe_email) {
            return res.status(404).json({ success: false, message: 'Department or registered DOE email not found.' });
        }

        const registeredEmail = dept.doe_email.toLowerCase().trim();
        const inputEmail = (email || '').toLowerCase().trim();

        if (inputEmail && inputEmail !== registeredEmail) {
            return res.status(403).json({ success: false, message: 'Entered email does not match the official DOE on record for this department.' });
        }

        const otp = crypto.randomInt(100000, 1000000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes validity

        await setOtp(db, registeredEmail, 'doe', otp, expiresAt, dept.id);

        try {
            await transporter.sendMail({
                from: '"ACE Examination Authority" <no-reply@college.edu>',
                to: registeredEmail,
                subject: `[DOE Access Code] Login OTP for ${dept.name}`,
                text: `Dear ${dept.doe_name || 'Director of Evaluation'},\n\nYour one-time security passkey to access and print official attendance slips for Department of ${dept.name} is:\n\n${otp}\n\nThis OTP is valid for 10 minutes. Do not share this passkey.`
            });
            res.json({ success: true, message: `Access OTP sent to registered DOE email (${registeredEmail.replace(/(.{2})(.*)(@.*)/, "$1***$3")})` });
        } catch (mailErr) {
            await takeOtp(db, registeredEmail, 'doe').catch(() => {});
            res.status(500).json({ success: false, message: 'Failed to send OTP email: ' + mailErr.message });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to request OTP.' });
    }
});

// 2. Verify OTP & Issue Department-Restricted Access Token
app.post('/api/doe/verify-otp', async (req, res) => {
    const { dept_id, otp } = req.body;

    try {
        const dept = await get(db, `SELECT id, name, doe_email FROM departments WHERE id = ?`, [dept_id]);
        if (!dept || !dept.doe_email) return res.status(404).json({ success: false, message: 'Department not found.' });

        const registeredEmail = dept.doe_email.toLowerCase().trim();
        const record = await get(db, `SELECT otp, dept_id, expires_at FROM otp_codes WHERE email = ? AND purpose = 'doe'`, [registeredEmail]);

        if (!record || record.dept_id !== dept.id || Date.now() > record.expires_at) {
            return res.status(401).json({ success: false, message: 'OTP has expired. Please request a new code.' });
        }

        if (record.otp !== (otp || '').trim()) {
            return res.status(401).json({ success: false, message: 'Invalid verification code.' });
        }

        // Clean up OTP and issue short-lived session token (valid 2 hours)
        await takeOtp(db, registeredEmail, 'doe');
        const token = crypto.randomBytes(32).toString('hex');
        await createSession(db, token, 'doe', registeredEmail, Date.now() + 2 * 60 * 60 * 1000, {
            deptId: dept.id,
            meta: dept.name
        });

        res.json({ success: true, token, dept_id: dept.id, dept_name: dept.name });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Unable to verify OTP.' });
    }
});

// 3. Batch PDF Route (Restricted Strictly to Token's Authorized Department)
app.get('/api/doe/reports/batch-slips-pdf', async (req, res) => {
    const { token, from_date, to_date, session } = req.query;

    const auth = await getSession(db, token);
    if (!auth || auth.role !== 'doe') {
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
            return res.status(404).send(`No attendance slips recorded for Department of ${auth.meta} in this date range.`);
        }

        const doc = new PDFDocument({ margin: 0, size: 'A4', layout: 'portrait' });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename=DOE_${auth.meta}_Slips_${targetFrom}.pdf`);
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
app.get('/mentor', (req, res) => res.sendFile(path.join(__dirname, 'public', 'mentor.html')));

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    res.status(err.status || 400).json({ success: false, message: err.status === 413 ? 'Uploaded photo is too large.' : 'Invalid request. Check the supplied fields.' });
});

async function initialize() {
    if (process.env.VERCEL && !process.env.TURSO_DATABASE_URL && !process.env.LIBSQL_URL) {
        throw new Error('TURSO_DATABASE_URL is required on Vercel. SQLite files do not persist in serverless hosting.');
    }
    await initializeSchema(db);
    // Upgrade existing accounts without changing their passwords.
    for (const [table, key] of [['admin_users', 'admin_id'], ['faculty', 'faculty_id']]) {
        const accounts = await all(db, `SELECT ${key} AS id, password FROM ${table}`);
        for (const account of accounts) {
            if (!account.password.startsWith('scrypt$')) await run(db, `UPDATE ${table} SET password=? WHERE ${key}=?`, [hashPassword(account.password), account.id]);
        }
    }
    await cleanup(db);
}
async function start() {
    await initialize();
    return app.listen(PORT, () => console.log(`Attendance System running on port ${PORT}`));
}
if (require.main === module) start().catch(err => { console.error(err); process.exit(1); });
module.exports = { app, db, start, initialize };
