# Hourly Attendance System

Node.js/Express and SQLite application for ACE faculty attendance, administration, mentor reports, and DOE slips.

**Live deployment:** https://hourly-attendance-system.vercel.app

## Run locally

1. Install Node.js 22 or newer and run `npm ci`.
2. Copy `.env.example` to `.env` and configure campus coordinates/radius and Gmail SMTP credentials (an app password).
3. For a new database, set `ADMIN_PASSWORD` and `ADMIN_EMAIL` to bootstrap `ADMIN01`.
4. Run `npm start` and open `http://localhost:3000`.

Portals: `/` (faculty), `/admin` (administration), `/mentor` (section mentors), `/doe` (DOE).
Configure courses, departments, batch years, sections, faculty, students and section mentors in the admin portal before taking attendance.

Mentors can sign in at `/mentor` with a password set by an administrator, or with a one-time code sent to their registered email. They see only the sections allotted to them, can filter students by roll number, name, date range and attendance threshold, and can download a CSV call list containing roll number, student name, parent number and attendance percentage.

Every attendance submission emails the section mentor the attendance statement PDF and classroom photo. Once per day, a scheduled job at 7:00 PM IST emails the mentor of each section that had attendance a daily call list. The call list contains that day's absentees, with students whose **daily** attendance is below `ATTENDANCE_THRESHOLD` (default 75%) listed first and marked `HIGH` in the CSV. Daily attendance counts a day as present when the student attended more than 50% of that day's conducted hours (full day); attending up to 50% of the day's hours counts as half a day. The percentage is days present out of conducted days, not hourly sessions. The daily email also attaches the day's attendance statement and the latest classroom photo. The job is idempotent per section/date and will not resend.

Existing plaintext account passwords are upgraded to hashes at startup; users retain their passwords. Sessions are stored in the database and expire after eight hours; DOE sessions last two hours. Production deployments require HTTPS (including for camera/location access); set `NODE_ENV=production` for secure session cookies. Attendance dates use Asia/Kolkata.

`npm run setup` initializes the same schema used by the server. To create/update another administrator, set `ADMIN_PASSWORD`, then run `npm run add-admin -- ADMIN02 "Admin Name" admin@example.com`.

## Deploy online (Vercel + Turso)

Vercel functions have no persistent filesystem, so production data lives in [Turso](https://turso.tech), a hosted SQLite-compatible database. Sessions, OTPs, and rate limits are also stored there, so the app works across multiple serverless instances and devices.

1. Create a free Turso database and copy its URL and auth token.
2. Push this repository to GitHub.
3. Import the repository in Vercel. No build command is needed; `vercel.json` routes requests to `api/index.js`.
4. Add these Vercel environment variables:
   - `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` (required)
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD` (bootstraps `ADMIN01` on the first request)
   - `EMAIL_USER` and `EMAIL_PASS` (Gmail app password for reports and OTPs)
   - `APP_URL` (your Vercel URL, e.g. `https://your-project.vercel.app`)
   - `CAMPUS_LAT`, `CAMPUS_LNG`, `CAMPUS_RADIUS_METERS`
   - `ATTENDANCE_THRESHOLD` (optional, default `75`)
   - `CRON_SECRET` (recommended; protects `/api/cron/daily-call-list`; Vercel Cron sends it automatically as a Bearer token)
   - `NODE_ENV=production`
5. Deploy. The first request creates the schema in Turso automatically. The `crons` entry in `vercel.json` runs the daily call-list job at 13:30 UTC (7:00 PM IST). Vercel Hobby runs cron jobs once per day; adjust the schedule if needed.

`npm start` uses a local `attendance.db` when `TURSO_DATABASE_URL` is not set. If `TURSO_DATABASE_URL` is present in `.env`, the local server connects to the same hosted database as production, so changes are shared across devices. Vercel requests are capped at roughly 4.5 MB; the faculty portal compresses classroom photos before upload.

## Verification

Run `npm test`. Tests use temporary databases and mocked mail delivery; they do not modify your local attendance data or send email.

## Repository contents

Credentials (`.env`), SQLite databases, and dependencies are excluded from Git. Keep a backup of `attendance.db` before deployment. Configure secrets separately on the deployment host. The frontend currently loads Tailwind through its CDN.
