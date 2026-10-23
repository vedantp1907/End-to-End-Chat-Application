import path from 'path';
import crypto from 'crypto';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { User } from './models/User.js';
import { createRelay } from './relay.js';
import { migrate } from './migrate.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
dotenv.config({ path: path.join(root, '.env') });

const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('\nMONGODB_URI is not set. Copy .env.example to .env and paste your MongoDB Atlas connection string into it.\n');
  process.exit(1);
}
let secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  secret = crypto.randomBytes(48).toString('hex');
  console.warn('! JWT_SECRET is not set (or shorter than 32 characters). Using a random one: everyone is logged out on every restart.');
}

try {
  await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
  await migrate(User);          // remove the leftover usernameLower field from the previous version
  await User.syncIndexes();     // unique indexes on username and email; drops the old usernameLower index
  console.log('Connected to MongoDB:', mongoose.connection.host + '/' + mongoose.connection.name);
} catch (e) {
  console.error(`\nCould not connect to MongoDB at ${MONGODB_URI.replace(/\/\/.*@/, '//***@')}\n  ${e.message}\n`);
  console.error('Check in Atlas: (1) the username and password in the connection string, (2) Network Access allows your IP address, (3) the cluster is running.\n');
  process.exit(1);
}

const relay = await createRelay({
  User, secret,
  keyFile: process.env.SSL_KEY || path.join(root, 'certs/key.pem'),
  certFile: process.env.SSL_CERT || path.join(root, 'certs/cert.pem'),
  allowTamper: process.env.ALLOW_TAMPER_DEMO !== 'false',
});
const port = await relay.listen(PORT);
console.log(`Relay listening on ${relay.useTLS ? 'https/wss' : 'http/ws (no TLS — run "npm run gen-cert")'}://localhost:${port}`);
