const sqlite3 = require('sqlite3').verbose();

function run(db, sql, params = []) {
    return new Promise((resolve, reject) => db.run(sql, params, function(err) {
        if (err) reject(err); else resolve({ changes: this.changes, lastID: this.lastID });
    }));
}
function all(db, sql, params = []) {
    return new Promise((resolve, reject) => db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));
}
async function transaction(filename, work) {
    const db = new sqlite3.Database(filename);
    db.configure('busyTimeout', 5000);
    try {
        await run(db, 'PRAGMA foreign_keys = ON');
        await run(db, 'BEGIN IMMEDIATE');
        const result = await work(db);
        await run(db, 'COMMIT');
        return result;
    } catch (err) {
        await run(db, 'ROLLBACK').catch(() => {});
        throw err;
    } finally {
        await new Promise(resolve => db.close(resolve));
    }
}
async function saveAttendance(filename, payload, submissionTime) {
    const { classDetails: c, attendance, facultyId, facultyName, date, hourSlot, subjectName } = payload;
    return transaction(filename, async db => {
        const scope = [c.branch_id, c.dept_id, c.batch_year_id, c.section_id];
        const roster = await all(db, 'SELECT roll_number FROM students WHERE branch_id=? AND dept_id=? AND batch_year_id=? AND section_id=?', scope);
        const rolls = new Set(attendance.map(s => s.roll_number));
        if (!roster.length || roster.length !== attendance.length || rolls.size !== attendance.length || roster.some(s => !rolls.has(s.roll_number))) {
            throw new Error('Attendance must include every enrolled student exactly once. Reload the class.');
        }
        const locks = await all(db, 'SELECT faculty_id FROM attendance_logs WHERE branch_id=? AND dept_id=? AND batch_year_id=? AND section_id=? AND date=? AND hour_slot=?', [...scope, date, hourSlot]);
        if (locks.some(row => row.faculty_id !== facultyId)) throw new Error('This period was already submitted by another faculty member.');
        for (const item of attendance) {
            await run(db, `INSERT INTO attendance_logs (roll_number,date,hour_slot,subject_name,status,faculty_id,faculty_name,submission_time,branch_id,dept_id,batch_year_id,section_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(roll_number,date,hour_slot) DO UPDATE SET
                status=excluded.status, subject_name=excluded.subject_name, faculty_id=excluded.faculty_id,
                faculty_name=excluded.faculty_name, submission_time=excluded.submission_time,
                branch_id=excluded.branch_id, dept_id=excluded.dept_id, batch_year_id=excluded.batch_year_id, section_id=excluded.section_id`,
                [item.roll_number, date, hourSlot, subjectName, item.status, facultyId, facultyName, submissionTime, ...scope]);
        }
    });
}
module.exports = { run, all, transaction, saveAttendance };
