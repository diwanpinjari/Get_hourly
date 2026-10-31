# Hourly Attendance System

Node.js/Express and SQLite application for ACE faculty attendance, administration, mentor reports, and DOE slips.

## Run locally

1. Install Node.js 22 or newer and run `npm ci`.
2. Copy `.env.example` to `.env` and configure campus coordinates/radius and Gmail SMTP credentials (an app password).
3. For a new database, set `ADMIN_PASSWORD` and `ADMIN_EMAIL` to bootstrap `ADMIN01`.
4. Run `npm start` and open `http://localhost:3000`.

Portals: `/` (faculty), `/admin` (administration), `/doe` (DOE).
Configure courses, departments, batch years, sections, faculty, students and section mentors in the admin portal before taking attendance.

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
   - `NODE_ENV=production`
5. Deploy. The first request creates the schema in Turso automatically.

`npm start` still uses a local `attendance.db` when `TURSO_DATABASE_URL` is not set. Vercel requests are capped at roughly 4.5 MB; the faculty portal compresses classroom photos before upload.

## Verification

Run `npm test`. Tests use temporary databases and mocked mail delivery; they do not modify your local attendance data or send email.

## Repository contents

Credentials (`.env`), SQLite databases, and dependencies are excluded from Git. Keep a backup of `attendance.db` before deployment. Configure secrets separately on the deployment host. The frontend currently loads Tailwind through its CDN.
