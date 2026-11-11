const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { once } = require('node:events');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'attendance-test-'));
process.env.DATA_DIR = temporary;
process.env.TURSO_DATABASE_URL = 'file:' + path.join(temporary, 'attendance.db');
process.env.PORT = '0';
process.env.ADMIN_PASSWORD = 'test-password';
process.env.ADMIN_EMAIL = 'admin@example.test';
process.env.CAMPUS_LAT = '17.4725';
process.env.CAMPUS_LNG = '78.6888';
process.env.CAMPUS_RADIUS_METERS = '1000';
const messages = [];
let failMail = false;
require('nodemailer').createTransport = () => ({ sendMail: async message => { if (failMail) throw new Error('Mock SMTP failure'); messages.push(message); return {}; } });
const { start, initialize, db } = require('../server');
const { all, run } = require('../lib/data');
let server, base, adminCookie, facultyCookie;
let classDetails;
async function request(url, method = 'GET', body, cookie = adminCookie) {
    const response = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const type = response.headers.get('content-type') || '';
    return { status: response.status, cookie: response.headers.get('set-cookie')?.split(';')[0], data: type.includes('json') ? await response.json() : Buffer.from(await response.arrayBuffer()) };
}
before(async () => {
    server = await start();
    if (!server.listening) await once(server, 'listening');
    await run(db, "INSERT INTO faculty (faculty_id,name,password) VALUES ('LEGACY','Legacy','old-password')");
    await initialize();
    base = `http://127.0.0.1:${server.address().port}`;
    const login = await request('/api/admin/login', 'POST', { username: 'ADMIN01', password: 'test-password' }, null);
    assert.equal(login.status, 200);
    adminCookie = login.cookie;
    for (const id of ['F1', 'F2']) assert.equal((await request('/api/admin/faculty', 'POST', { faculty_id: id, name: id, password: 'faculty-pass' })).status, 200);
    facultyCookie = (await request('/api/login', 'POST', { faculty_id: 'F1', password: 'faculty-pass' }, null)).cookie;
    const branch_id = (await request('/api/admin/branches', 'POST', { name: 'B.Tech' })).data.id;
    const dept_id = (await request('/api/admin/departments', 'POST', { name: 'CSE', branch_id })).data.id;
    const batch_year_id = (await request('/api/admin/batch-years', 'POST', { name: '2026', branch_id })).data.id;
    const section_id = (await request('/api/admin/sections', 'POST', { name: 'A', branch_id, dept_id, batch_year_id })).data.id;
    classDetails = { branch_id, dept_id, batch_year_id, section_id };
    await request(`/api/admin/departments/${dept_id}/doe`, 'PUT', { doe_name: 'DOE', doe_email: 'doe@example.test' });
    await request('/api/admin/mentors', 'POST', { name: 'Mentor', email: 'mentor@example.test', password: 'mentor-pass' });
    const mentors = (await request('/api/admin/mentors')).data;
    assert.equal((await request('/api/admin/section-mentors', 'POST', { ...classDetails, mentor_id: mentors[0].mentor_id })).status, 200);
    assert.equal((await request('/api/admin/students/bulk', 'POST', { ...classDetails, students: [{ roll_number: 'S001', name: 'One' }, { roll_number: 'S002', name: 'Two' }] })).status, 200);
});
after(async () => {
    if (server) await new Promise(resolve => server.close(resolve));
    await new Promise(resolve => db.close(resolve));
    try {
        fs.rmSync(temporary, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    } catch {
        // Windows may keep the temporary SQLite file locked briefly.
    }
});

function payload(hourSlot = 'Hour 1') {
    return { classDetails, facultyId: 'SPOOFED', facultyName: 'Spoofed', subjectName: 'Maths', hourSlot, date: '2026-10-31',
        attendance: [{ roll_number: 'S001', status: 'Present' }, { roll_number: 'S002', status: 'Absent' }],
        classroomPhoto: 'data:image/jpeg;base64,YQ==', location: { latitude: 17.4725, longitude: 78.6888 } };
}
test('protected APIs reject unauthenticated callers; stored passwords are hashed', async () => {
    assert.equal((await request('/api/login', 'POST', { faculty_id: 'LEGACY', password: 'old-password' }, null)).status, 200);
    assert.equal((await request('/api/admin/admins', 'GET', undefined, null)).status, 401);
    assert.equal((await request('/api/attendance/submit', 'POST', payload(), null)).status, 401);
    assert.equal((await request('/api/admin/admins', 'GET', undefined, facultyCookie)).status, 401);
    const rows = await all(db, 'SELECT password FROM faculty UNION ALL SELECT password FROM admin_users');
    assert.ok(rows.every(r => r.password.startsWith('scrypt$')));
});
test('invalid and incomplete attendance cannot report success or write rows', async () => {
    for (const override of [{ attendance: [] }, { subjectName: '' }, { date: '2026-02-30' }, { location: { latitude: 500, longitude: 1 } }, { classroomPhoto: 'bad' }]) {
        assert.equal((await request('/api/attendance/submit', 'POST', { ...payload(), ...override }, facultyCookie)).status, 400);
    }
    assert.equal((await request('/api/attendance/submit', 'POST', { ...payload(), location: { latitude: 0, longitude: 0 } }, facultyCookie)).status, 403);
    assert.equal((await request('/api/attendance/submit', 'POST', { ...payload(), attendance: [payload().attendance[0]] }, facultyCookie)).status, 409);
    assert.equal((await all(db, 'SELECT * FROM attendance_logs')).length, 0);
});
test('attendance persists before success and editing restores saved statuses', async () => {
    assert.equal((await request('/api/attendance/submit', 'POST', payload(), facultyCookie)).status, 200);
    const query = new URLSearchParams({ ...classDetails, date: '2026-10-31', hour_slot: 'Hour 1' });
    const result = await request(`/api/students?${query}`, 'GET', undefined, facultyCookie);
    assert.equal(result.data.alreadySubmitted, true);
    assert.deepEqual(result.data.students.map(s => s.status), ['Present', 'Absent']);
    assert.equal(result.data.existingDetails.faculty_id, 'F1');
    const edited = payload();
    edited.attendance[0].status = 'Absent';
    assert.equal((await request('/api/attendance/submit', 'POST', edited, facultyCookie)).status, 200);
    assert.equal((await all(db, 'SELECT * FROM attendance_logs')).length, 2);
    const otherCookie = (await request('/api/login', 'POST', { faculty_id: 'F2', password: 'faculty-pass' }, null)).cookie;
    assert.equal((await request('/api/attendance/submit', 'POST', payload(), otherCookie)).status, 403);
});
test('concurrent faculty submissions cannot overwrite each other', async () => {
    const otherCookie = (await request('/api/login', 'POST', { faculty_id: 'F2', password: 'faculty-pass' }, null)).cookie;
    const responses = await Promise.all([facultyCookie, otherCookie].map(cookie => request('/api/attendance/submit', 'POST', payload('Hour 2'), cookie)));
    assert.equal(responses.filter(r => r.status === 200).length, 1);
    assert.equal((await all(db, "SELECT DISTINCT faculty_id FROM attendance_logs WHERE hour_slot='Hour 2'")).length, 1);
});
test('corrections validate status and ownership; bulk import rejects invalid class', async () => {
    const correction = { ...classDetails, date: '2026-10-31', hour_slot: 'Hour 1', roll_number: 'S001', new_status: 'Present' };
    assert.equal((await request('/api/faculty/update-student-status', 'PUT', correction, facultyCookie)).status, 200);
    assert.equal((await request('/api/faculty/update-student-status', 'PUT', { ...correction, new_status: 'bogus' }, facultyCookie)).status, 400);
    assert.equal((await request('/api/faculty/update-student-status', 'PUT', { ...correction, roll_number: 'missing' }, facultyCookie)).status, 404);
    assert.equal((await request('/api/admin/students/bulk', 'POST', { ...classDetails, section_id: 999, students: [{ roll_number: 'BAD', name: 'Invalid' }] })).status, 400);
    assert.equal((await all(db, "SELECT * FROM students WHERE roll_number='BAD'")).length, 0);
});
test('a database failure rolls back the whole attendance submission', async () => {
    await run(db, `CREATE TRIGGER reject_test_row BEFORE INSERT ON attendance_logs WHEN NEW.hour_slot='Hour 3' AND NEW.roll_number='S002' BEGIN SELECT RAISE(ABORT, 'Simulated write failure'); END`);
    try {
        assert.equal((await request('/api/attendance/submit', 'POST', payload('Hour 3'), facultyCookie)).status, 409);
        assert.equal((await all(db, "SELECT * FROM attendance_logs WHERE hour_slot='Hour 3'")).length, 0);
    } finally { await run(db, 'DROP TRIGGER reject_test_row'); }
});
test('failed deletion OTP delivery fails closed without exposing the code', async () => {
    failMail = true;
    try {
        const result = await request('/api/admin/request-delete-otp', 'POST', { entity_type: 'branch', admin_email: 'attacker@example.test' });
        assert.equal(result.status, 502);
        assert.equal(result.data.success, false);
        assert.doesNotMatch(result.data.message, /\d{6}/);
    } finally { failMail = false; }
});
test('faculty PDF and authenticated DOE batch PDFs are generated', async () => {
    const query = new URLSearchParams({ ...classDetails, date: '2026-10-31', hour_slot: 'Hour 1' });
    const pdf = await request(`/api/faculty/reports/hourly-pdf?${query}`, 'GET', undefined, facultyCookie);
    assert.equal(pdf.status, 200);
    assert.equal(pdf.data.subarray(0, 4).toString(), '%PDF');
    assert.equal((await request('/api/doe/reports/batch-slips-pdf', 'GET', undefined, null)).status, 401);
    assert.equal((await request('/api/doe/request-otp', 'POST', { dept_id: classDetails.dept_id }, null)).status, 200);
    const mail = messages.findLast(m => m.subject.includes('DOE Access Code'));
    const otp = mail.text.match(/\b\d{6}\b/)[0];
    const verified = await request('/api/doe/verify-otp', 'POST', { dept_id: classDetails.dept_id, otp }, null);
    assert.equal(verified.status, 200);
    const doe = await request(`/api/doe/reports/batch-slips-pdf?token=${verified.data.token}&from_date=2026-10-31&to_date=2026-10-31`, 'GET', undefined, null);
    assert.equal(doe.status, 200);
    assert.equal(doe.data.subarray(0, 4).toString(), '%PDF');
    assert.equal((await request('/api/doe/verify-otp', 'POST', { dept_id: classDetails.dept_id, otp }, null)).status, 401);
});
test('all frontend scripts parse, and submission uses actual roster and leisure status', async () => {
    for (const filename of ['admin.html', 'doe.html', 'index.html', 'mentor.html']) {
        const html = fs.readFileSync(path.join(__dirname, '../public', filename), 'utf8');
        for (const match of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)) new vm.Script(match[1], { filename });
    }
    const nodes = new Map();
    const getNode = id => {
        if (!nodes.has(id)) nodes.set(id, { value: '1', checked: false, classList: { add() {}, remove() {}, toggle() {} } });
        return nodes.get(id);
    };
    let submitted;
    const context = vm.createContext({ window: {}, document: { getElementById: getNode }, console, alert() {}, attendanceDate: () => '2026-10-31',
        fetch: async (url, options) => { submitted = JSON.parse(options.body); return { json: async () => ({ success: true }) }; } });
    const script = [...fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8').matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
    vm.runInContext(script, context);
    vm.runInContext(`loggedInFaculty={id:'F1',name:'Faculty'}; currentStudents=[{roll_number:'S001',status:'Absent'}]; activeSelectedSlot='Hour 1'; activeClassDetails={branch_id:1,dept_id:1,batch_year_id:1,section_id:1}; activeAttendanceDate='2026-10-31'; capturedClassroomPhotoBase64='data:image/jpeg;base64,YQ=='; getDeviceCoordinates=async()=>({latitude:17,longitude:78}); loadDailyProgress=async()=>{};`, context);
    await vm.runInContext('submitAttendance()', context);
    assert.deepEqual(submitted.attendance, [{ roll_number: 'S001', status: 'Absent' }]);
    getNode('leisureCheck').checked = true;
    await vm.runInContext('submitAttendance()', context);
    assert.deepEqual(submitted.attendance, [{ roll_number: 'S001', status: 'Leisure' }]);
});
test('logout invalidates server session', async () => {
    assert.equal((await request('/api/logout', 'POST', undefined, facultyCookie)).status, 200);
    assert.equal((await request('/api/faculty/daily-progress', 'GET', undefined, facultyCookie)).status, 401);
});
test('mentor password login exposes only assigned sections and attendance exports', async () => {
    const login = await request('/api/mentor/login', 'POST', { email: 'mentor@example.test', password: 'mentor-pass' }, null);
    assert.equal(login.status, 200);
    assert.ok(login.cookie);

    const sections = await request('/api/mentor/sections', 'GET', undefined, login.cookie);
    assert.equal(sections.status, 200);
    assert.equal(sections.data.sections.length, 1);
    assert.equal(Number(sections.data.sections[0].section_id), Number(classDetails.section_id));

    const attendance = await request(`/api/mentor/sections/${classDetails.section_id}/attendance`, 'GET', undefined, login.cookie);
    assert.equal(attendance.status, 200);
    assert.equal(attendance.data.students.length, 2);
    const below = attendance.data.students.find(student => student.roll_number === 'S002');
    assert.ok(below.percentage < 75);
    assert.equal(below.below_threshold, true);

    const csv = await request(`/api/mentor/sections/${classDetails.section_id}/attendance.csv`, 'GET', undefined, login.cookie);
    assert.equal(csv.status, 200);
    assert.match(csv.data.toString(), /S002/);

    assert.equal((await request('/api/mentor/sections/999/attendance', 'GET', undefined, login.cookie)).status, 403);
    assert.equal((await request('/api/mentor/sections', 'GET', undefined, null)).status, 401);
    assert.equal((await request('/api/mentor/login', 'POST', { email: 'mentor@example.test', password: 'wrong' }, null)).status, 401);
});

test('mentor can sign in with an email OTP', async () => {
    const requestOtp = await request('/api/mentor/request-otp', 'POST', { email: 'mentor@example.test' }, null);
    assert.equal(requestOtp.status, 200);
    const mail = messages.findLast(message => message.subject.includes('Mentor Portal'));
    assert.ok(mail);
    const otp = mail.text.match(/\b\d{6}\b/)[0];
    const verified = await request('/api/mentor/verify-otp', 'POST', { email: 'mentor@example.test', otp }, null);
    assert.equal(verified.status, 200);
    assert.ok(verified.cookie);
    assert.equal((await request('/api/mentor/sections', 'GET', undefined, verified.cookie)).status, 200);
    assert.equal((await request('/api/mentor/verify-otp', 'POST', { email: 'mentor@example.test', otp }, null)).status, 401);
});

test('hourly attendance emails include the statement and photo but not the call-list CSV', async () => {
    const freshCookie = (await request('/api/login', 'POST', { faculty_id: 'F1', password: 'faculty-pass' }, null)).cookie;
    assert.equal((await request('/api/attendance/submit', 'POST', payload('Hour 4'), freshCookie)).status, 200);
    const mail = messages.findLast(message => message.subject.includes('Attendance Statement + Photo'));
    assert.ok(mail);
    assert.ok(mail.attachments.some(attachment => attachment.filename.endsWith('.pdf')));
    assert.ok(mail.attachments.some(attachment => attachment.filename.endsWith('.jpg')));
    assert.equal(mail.attachments.some(attachment => attachment.filename.endsWith('.csv')), false);
});

test('daily call list is sent once with today absentees and complete-day percentages', async () => {
    process.env.CRON_SECRET = 'test-cron-secret';
    const first = await request('/api/cron/daily-call-list?date=2026-10-31&secret=test-cron-secret');
    assert.equal(first.status, 200);
    assert.equal(first.data.sent, 1);
    const mail = messages.findLast(message => message.subject.includes('[Daily Call List]'));
    assert.ok(mail);
    assert.ok(mail.attachments.some(attachment => attachment.filename.endsWith('.pdf')));
    assert.ok(mail.attachments.some(attachment => attachment.filename.endsWith('.jpg')));
    const csvAttachment = mail.attachments.find(attachment => attachment.filename.endsWith('.csv'));
    assert.ok(csvAttachment);
    const csv = csvAttachment.content.toString();
    assert.match(csv, /S002/);
    assert.doesNotMatch(csv, /S001/);
    assert.match(csv, /HIGH/);
    assert.match(csv, /0\.0/);
    assert.match(mail.text, /Absentees today: 1/);
    assert.match(mail.text, /days present/i);

    const second = await request('/api/cron/daily-call-list?date=2026-10-31&secret=test-cron-secret');
    assert.equal(second.status, 200);
    assert.equal(second.data.sent, 0);
    assert.equal(second.data.skipped, 1);
    const logs = await all(db, "SELECT * FROM daily_call_list_log WHERE date='2026-10-31'");
    assert.equal(logs.length, 1);
});

test('daily call list uses complete-day attendance, not hourly percentage', async () => {
    const insertLog = (roll, hour, status) => run(db, `
        INSERT INTO attendance_logs
            (roll_number, date, hour_slot, subject_name, status, faculty_id, faculty_name, submission_time, branch_id, dept_id, batch_year_id, section_id)
        VALUES (?, '2026-11-01', ?, 'Maths', ?, 'F1', 'F1', '10:00:00 AM', ?, ?, ?, ?)
    `, [roll, hour, status, classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id]);
    await insertLog('S001', 'Hour 1', 'Present');
    await insertLog('S001', 'Hour 2', 'Present');
    await insertLog('S002', 'Hour 1', 'Present');
    await insertLog('S002', 'Hour 2', 'Absent');

    const result = await request('/api/cron/daily-call-list?date=2026-11-01&secret=test-cron-secret');
    assert.equal(result.status, 200);
    assert.equal(result.data.sent, 1);
    const mail = messages.findLast(message => message.subject.includes('2026-11-01'));
    assert.ok(mail);
    const csvAttachment = mail.attachments.find(attachment => attachment.filename.endsWith('.csv'));
    assert.ok(csvAttachment);
    const csv = csvAttachment.content.toString();
    // S002 attended 1 of 2 hours on 2026-11-01 (exactly 50% -> half day) and was
    // fully absent on 2026-10-31, so daily attendance is 0.5 of 2 days = 25%.
    assert.match(csv, /S002/);
    assert.match(csv, /25\.0/);
    assert.match(csv, /0\.5/);
    assert.match(csv, /HIGH/);
    assert.doesNotMatch(csv, /S001/);
    assert.match(mail.text, /Absentees today: 1/);
});

test('daily call list email still sends when nobody is absent', async () => {
    const insertPresent = roll => run(db, `
        INSERT INTO attendance_logs
            (roll_number, date, hour_slot, subject_name, status, faculty_id, faculty_name, submission_time, branch_id, dept_id, batch_year_id, section_id)
        VALUES (?, '2026-11-02', 'Hour 1', 'Maths', 'Present', 'F1', 'F1', '10:00:00 AM', ?, ?, ?, ?)
    `, [roll, classDetails.branch_id, classDetails.dept_id, classDetails.batch_year_id, classDetails.section_id]);
    await insertPresent('S001');
    await insertPresent('S002');

    const result = await request('/api/cron/daily-call-list?date=2026-11-02&secret=test-cron-secret');
    assert.equal(result.status, 200);
    assert.equal(result.data.sent, 1);
    const mail = messages.findLast(message => message.subject.includes('2026-11-02'));
    assert.ok(mail);
    assert.equal(mail.attachments.some(attachment => attachment.filename.endsWith('.csv')), false);
    assert.match(mail.text, /No students were absent today/);
});

test('daily call list endpoint rejects callers without the cron secret', async () => {
    assert.equal((await request('/api/cron/daily-call-list?date=2026-10-31')).status, 401);
});

test('admin can set and change a mentor login password', async () => {
    const mentors = (await request('/api/admin/mentors')).data;
    const mentor = mentors.find(item => item.email === 'mentor@example.test');
    assert.equal(mentor.has_password, 1);
    assert.equal((await request(`/api/admin/mentors/${mentor.mentor_id}`, 'PUT', { name: 'Mentor', email: 'mentor@example.test', password: 'new-mentor-pass' })).status, 200);
    const login = await request('/api/mentor/login', 'POST', { email: 'mentor@example.test', password: 'new-mentor-pass' }, null);
    assert.equal(login.status, 200);
    assert.equal((await request('/api/mentor/login', 'POST', { email: 'mentor@example.test', password: 'mentor-pass' }, null)).status, 401);
});

test('CSV quoting and names containing apostrophes round-trip safely', () => {
    const context = vm.createContext({ window: { fetch() {}, addEventListener() {} }, Intl, Date });
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../public/common.js'), 'utf8'), context);
    assert.equal(vm.runInContext(`parseCsv('001,"Smith, John",123,456')[0][1]`, context), 'Smith, John');
    assert.equal(vm.runInContext(`parseCsv('001,"A ""quoted"" name"')[0][1]`, context), 'A "quoted" name');
    assert.throws(() => vm.runInContext(`parseCsv('001,"broken')`, context));
    assert.equal(vm.runInContext(`csvCell('A "quote"')`, context), '"A ""quote"""');
    assert.equal(vm.runInContext(`jsArg("O'Brien")`, context), '&quot;O&#39;Brien&quot;');
    assert.equal(vm.runInContext(`escapeHtml('<img src=x>')`, context), '&lt;img src=x&gt;');
});
