/** Clean-up for the short-lived case-insensitive version: remove its leftover usernameLower field (idempotent). */
export async function migrate(User) {
  await User.collection.updateMany({ usernameLower: { $exists: true } }, { $unset: { usernameLower: '' } });
}
