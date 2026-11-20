# LoveConnect — live chat starter

This is a deployable **single-server starter**, not a hosted public URL yet.

## Included
- Registration/login with username + password only (no phone number/email field)
- Random invite IDs (`LC-...`)
- Mutual contact creation by invite ID
- Persistent SQLite users, sessions, contacts and messages
- Real-time one-to-one messages with Socket.IO
- HTTP-only session cookie, password hashing, basic rate limits and security headers
- Responsive dark UI

## Run locally
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env` and set `SESSION_SECRET` to a long random string (at least 32 characters).
3. Run `npm install`
4. Run `npm start`
5. Open `http://localhost:3000`

## Deploy to Render
1. Create a private GitHub repository and upload this project.
2. In Render, choose **New → Blueprint**, then select that repository. Render reads `render.yaml`.
3. Wait for deployment and open the generated `onrender.com` URL.
4. Keep the persistent disk attached. Do not remove it; it stores the database and sessions.

## Important security/product limits
- This starter uses HTTPS when deployed on Render and server-side session cookies. Use a strong `SESSION_SECRET`.
- Messages are stored as readable text in the server database. **This is not end-to-end encrypted yet.** Do not use it for highly sensitive conversations until audited end-to-end encryption is implemented.
- The server can technically access stored messages. E2EE requires client-side key generation, secure key backup/recovery design, encrypted message payloads, and careful verification.
- No voice/video calls, file uploads, push notifications, password reset or moderation tools yet.
- A single Node instance with SQLite is suitable for an early prototype. For larger scale, move to managed PostgreSQL and add backups, monitoring, abuse prevention and a security review.
- Username-only login means a lost password cannot currently be recovered. Add a recovery method that does not require a phone number before production use.
- Invite IDs are identifiers, not passwords. Keep them private, but never treat them as authentication secrets.
