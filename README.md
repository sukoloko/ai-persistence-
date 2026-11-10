# AI Persistence Study — Cloud Edition

This is your original interactive Day 0 + 7-day experiment, with a PostgreSQL-backed cloud database and participant PINs.

## Deploy
1. Create a **private GitHub repository** and upload `server.js`, `package.json`, and the `public` folder.
2. Create a managed PostgreSQL database (e.g., Render Postgres or Neon) and copy its connection string.
3. Create a **Node web service** on Render from the GitHub repository, with build command `npm install` and start command `npm start`.
4. Set environment variables in the hosting dashboard:
   - `DATABASE_URL`: the PostgreSQL connection string
   - `SESSION_SECRET`: a long random string (at least 32 characters)
   - `OPERATOR_PASSWORD`: a unique strong researcher password
5. Deploy, then open the generated HTTPS website URL in Safari.

## Usage
- Researcher: log in, create `P001`, select Group 1–4. The app generates a **private PIN** for that participant. Record it securely; it is only displayed once.
- Participant: use the same website, enter code and PIN, and complete baseline and Days 1–7.
- Researcher: log in on any device to view centrally stored participants and export CSV/JSON.

## IMPORTANT — pilot, not production-ready for sensitive human-subject research
- Get institutional ethics approval and a data-management plan before real recruitment.
- This version stores age, major, GPA (optional), and psychological questionnaire answers on your database. Use an approved hosting region, retention policy, access policy, and encryption/backup strategy.
- Participant PINs should be shared privately. A forgotten PIN currently requires an administrator/database reset.
- Participant updates use last-write-wins; **do not open the same participant session on multiple devices at once**. Avoid simultaneous tabs.
- Researcher login is token-based and lasts eight hours; refresh requires login again.
- There is no account lockout/rate limiting yet; add it before public recruitment.
- Built-in assistance is scripted (prewritten hints and solutions), not an actual live AI service. The original task logic and questionnaire are preserved.
- Test the full Day 0–7 flow, exports, timers, and cloud synchronization with fake participants before recruitment.
