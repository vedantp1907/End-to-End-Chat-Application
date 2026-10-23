# Vault Chat — End-to-End Encrypted Chat with a Static Session Key

React + Tailwind + daisyUI client, Node/Express + `ws` relay. Microproject for Cryptography and Security (Sem V).

## Run it
You need Node.js 20+ and a free MongoDB Atlas cluster. The database stores **user accounts only** (username, email, bcrypt password hash and the
user's *public* keys). Messages and private keys never reach it.

```bash
npm install
cp .env.example .env      # then paste your Atlas connection string into MONGODB_URI and set JWT_SECRET
npm run gen-cert          # self-signed TLS cert -> certs/
npm run build
npm start                 # https://localhost:3001  (wss for the socket)
```
Accept the browser's self-signed certificate warning once. Sign up in one window, then open a **private window** (it gets its
own key store and its own login) and sign up a second user.

Development with hot reload (no TLS): `npm run dev`, then open http://localhost:5173.
Tests: `npm run test:crypto` and `npm run test:e2e`. Both run without a database (the e2e test uses an in-memory stand-in for the users collection).

## Atlas setup (once)
1. In Atlas, create a database user (Database Access) and note its password. Avoid special characters in it, or URL-encode them.
2. Under Network Access, allow your current IP address.
3. Database -> Connect -> Drivers, copy the connection string into `MONGODB_URI` in `.env`, with `vaultchat` as the database name.
   The `users` collection and its unique indexes are created automatically on first start.

## Accounts
- **Sign up:** username, email, password (8+ characters). **Log in:** username *or* email, plus password.
- Passwords are hashed with bcrypt (cost 12). Login errors never reveal whether the account exists. Auth routes are rate limited.
- Login returns a 7-day token kept in `sessionStorage` (one login per browser tab). The WebSocket refuses connections without a valid token,
  and the username comes from the token, not from the client.
- The account's password never touches message encryption. Message keys are created in the browser at signup.
- Logging in from a **different browser** creates a new key pair there (the old chat history stays in the old browser). The server
  saves the new public key, and contacts see a "keys changed" warning until they review it. This is by design for the static-key model.

## How it maps to the objectives
| Objective | Where |
|---|---|
| End-to-end encryption, relay never sees plaintext | `client/src/lib/crypto.js`; the server only forwards `iv/ct/tag` (`server/relay.js`) |
| Shared session key via public-key exchange (RSA) | `createSession` / `acceptSession`: random 256-bit key wrapped with RSA-OAEP-3072 |
| AES for content | AES-256-CBC, `encryptMessage` |
| Integrity | HMAC-SHA256 over sender, recipient, id, time, IV, ciphertext; verified *before* decrypting |
| Key management | One static key per pair, HKDF-split into AES + HMAC keys, stored as non-extractable `CryptoKey`s in IndexedDB; manual re-key |
| TLS transport | `server/index.js` serves https/wss when `certs/` exists |
| Trade-off evaluation | "Limits" tab in the Security panel |

## Design decisions worth citing in the report
- **Public-key trust (lit. review 4.2):** each user has an RSA-OAEP key (key exchange) and an RSA-PSS key (signing).
  Handshakes are signed, so a relay cannot forge one. The server vouches for nothing, so users compare a **safety number**;
  keys are pinned on first sight (TOFU) and a change blocks sending until reviewed.
- **Encrypt-then-MAC (4.1):** separate HMAC key, tag checked first, constant-time verify.
- **Unique IVs (4.5):** fresh random 16-byte IV for every message.
- **Replay / reflection:** message ids are de-duplicated; sender and recipient are inside the MAC input; handshakes carry a timestamp and are rejected if stale or not newer than the last one seen.
- **Login proof of key ownership:** the server encrypts a nonce to the claimed public key; only the real owner can answer.
- **Deliberate limitations (4.3, 4.4):** no forward secrecy, no post-compromise security, metadata visible to the relay,
  server directory kept in memory, CBC chosen to match the syllabus (AES-GCM is the modern single-primitive choice).
  Chat history is kept in the browser's IndexedDB as plaintext.

## Demo tips
- *Show what was sent* under any bubble reveals the exact IV / ciphertext / tag.
- Security panel -> *Server's view* shows the relay's log, with no plaintext.
- Security panel -> *Server's view* -> *Try an attack* makes the relay act as an active attacker on the next message you send:
  *Corrupt* (receiver shows an integrity error), *Drop* (silently discarded, neither side is told) or *Delay* (held 15 s, then delivered unchanged).
  Drop and delay show what E2EE cannot prevent: availability. Disable all three with `ALLOW_TAMPER_DEMO=false`.
- Security panel -> *This chat* -> *Try an attack: steal the session key* gives an attacker a copy of the key plus the recorded ciphertext.
  It reads every past message and every new one (no forward secrecy). *Create a new session key* then locks it out of later messages only.
  The relay-log and tamper endpoints require a valid login token; the log shows only the caller's own traffic, and the tamper switch
  only affects the next message sent by the user who armed it.
