import mongoose from 'mongoose';

/**
 * The only collection in the database. Messages, session keys and private keys are never stored.
 * username is case-sensitive and kept exactly as typed: "Sam" and "sam" are two different accounts.
 * publicKey / signKey are PUBLIC keys (safe to store); they let the user directory survive restarts.
 */
const schema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true, match: /^[A-Za-z0-9_]{2,20}$/ },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
    passwordHash: { type: String, required: true },
    publicKey: { type: String, default: null },
    signKey: { type: String, default: null },
  },
  { timestamps: true, autoIndex: false }, // indexes are synced in start.js
);

export const User = mongoose.models.User || mongoose.model('User', schema);
