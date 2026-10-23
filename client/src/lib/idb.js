// Minimal IndexedDB key-value store. It can hold CryptoKey objects, so private keys stay non-extractable.
const open = () => new Promise((res, rej) => {
  const r = indexedDB.open('vault-chat', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('kv');
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});
const run = async (mode, fn) => {
  const db = await open();
  return new Promise((res, rej) => {
    const tx = db.transaction('kv', mode);
    const req = fn(tx.objectStore('kv'));
    tx.oncomplete = () => res(req.result);
    tx.onerror = () => rej(tx.error);
  });
};
export const kvGet = (k) => run('readonly', (s) => s.get(k));
export const kvSet = (k, v) => run('readwrite', (s) => s.put(v, k));
export const kvDel = (k) => run('readwrite', (s) => s.delete(k));
