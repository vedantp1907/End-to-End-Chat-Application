import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';

export const NAME_RE = /^[A-Za-z0-9_]{2,20}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

/** Signup / login routes plus token helpers. `User` is injected so it can be swapped in tests. */
export function createAuth({ User, secret }) {
  const sign = (u) => jwt.sign({ sub: String(u._id), u: u.username }, secret, { expiresIn: '7d' });
  const verify = (t) => { try { return jwt.verify(t, secret); } catch { return null; } };
  const DUMMY_HASH = bcrypt.hashSync('not-a-real-password', 12); // keeps login timing the same for unknown users
  const publicUser = (u) => ({ username: u.username, email: u.email });
  const limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a few minutes.' } });

  const router = express.Router();
  router.use(express.json({ limit: '4kb' }));

  router.post('/signup', limiter, async (req, res) => {
    // everything is coerced to a string, so objects like {"$ne": ""} can never reach a query
    const username = String(req.body?.username ?? '').trim(); // keeps the capitalization the user typed
    const email = String(req.body?.email ?? '').trim().toLowerCase();
    const password = String(req.body?.password ?? '');
    const fields = {};
    if (!NAME_RE.test(username)) fields.username = 'Use 2–20 letters, numbers or underscores.';
    if (!EMAIL_RE.test(email) || email.length > 254) fields.email = 'Enter a valid email address.';
    if (password.length < 8) fields.password = 'Use at least 8 characters.';
    else if (Buffer.byteLength(password) > 72) fields.password = 'Use 72 characters or fewer.';
    if (Object.keys(fields).length) return res.status(400).json({ error: 'Please fix the highlighted fields.', fields });
    try {
      const passwordHash = await bcrypt.hash(password, 12);
      const user = await User.create({ username, email, passwordHash });
      res.status(201).json({ token: sign(user), user: publicUser(user) });
    } catch (e) {
      if (e?.code === 11000) {
        const dup = Object.keys(e.keyPattern || e.keyValue || {})[0];
        const f = dup === 'email' ? { email: 'An account with this email already exists.' } : { username: 'That username is taken.' };
        return res.status(409).json({ error: 'Account already exists.', fields: f });
      }
      console.error('signup failed:', e.message);
      res.status(500).json({ error: 'Something went wrong. Try again.' });
    }
  });

  router.post('/login', limiter, async (req, res) => {
    const id = String(req.body?.identifier ?? '').trim(); // usernames are case-sensitive; emails are matched in lowercase
    const password = String(req.body?.password ?? '');
    if (!id || !password || id.length > 254 || password.length > 200)
      return res.status(400).json({ error: 'Enter your username or email, and your password.' });
    try {
      const user = await User.findOne({ $or: [{ username: id }, { email: id.toLowerCase() }] });
      const ok = await bcrypt.compare(password, user?.passwordHash ?? DUMMY_HASH);
      if (!user || !ok) return res.status(401).json({ error: 'Incorrect username/email or password.' });
      res.json({ token: sign(user), user: publicUser(user) });
    } catch (e) {
      console.error('login failed:', e.message);
      res.status(500).json({ error: 'Something went wrong. Try again.' });
    }
  });

  router.get('/me', async (req, res) => {
    const payload = verify((req.headers.authorization || '').replace(/^Bearer /, ''));
    if (!payload) return res.status(401).json({ error: 'Session expired.' });
    try {
      const user = await User.findById(payload.sub);
      if (!user) return res.status(401).json({ error: 'Session expired.' });
      res.json({ user: publicUser(user) });
    } catch { res.status(500).json({ error: 'Something went wrong.' }); }
  });

  return { router, verify };
}
