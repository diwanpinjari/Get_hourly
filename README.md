# Hourly Attendance System

Node.js/Express and SQLite application for ACE faculty attendance, administration, mentor reports, and DOE slips.

## Run locally

1. Install Node.js 22 or newer and run `npm ci`.
2. Copy `.env.example` to `.env` and configure campus coordinates/radius and Gmail SMTP credentials (an app password).
3. For a new database, set `ADMIN_PASSWORD` and `ADMIN_EMAIL` to bootstrap `ADMIN01`.
4. Run `npm start` and open `http://localhost:3000`.

Portals: `/` (faculty), `/admin` (administration), `/doe` (DOE).
Configure courses, departments, batch years, sections, faculty, students and section mentors in the admin portal before taking attendance.

Existing plaintext account passwords are upgraded to hashes at startup; users retain their passwords. Sessions expire after eight hours and on server restart. DOE sessions last two hours. Production deployments require HTTPS (including for camera/location access); set `NODE_ENV=production` for secure session cookies. Attendance dates use Asia/Kolkata.

`npm run setup` initializes the same schema used by the server. To create/update another administrator, set `ADMIN_PASSWORD`, then run `npm run add-admin -- ADMIN02 "Admin Name" admin@example.com`.

## Verification

Run `npm test`. Tests use temporary databases and mocked mail delivery; they do not modify your local attendance data or send email.

## Repository contents

Credentials (`.env`), SQLite databases, and dependencies are excluded from Git. Keep a backup of `attendance.db` before deployment. Configure secrets separately on the deployment host. The frontend currently loads Tailwind through its CDN.
