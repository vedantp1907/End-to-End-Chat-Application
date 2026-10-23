// Generates a self-signed TLS certificate for local use (certs/key.pem + certs/cert.pem).
import selfsigned from 'selfsigned';
import fs from 'fs';
const pems = await selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
  days: 365, keySize: 2048, algorithm: 'sha256',
  extensions: [{ name: 'subjectAltName', altNames: [{ type: 2, value: 'localhost' }, { type: 7, ip: '127.0.0.1' }] }],
});
fs.mkdirSync('certs', { recursive: true });
fs.writeFileSync('certs/key.pem', pems.private);
fs.writeFileSync('certs/cert.pem', pems.cert);
console.log('Wrote certs/key.pem and certs/cert.pem — run "npm run build && npm start" and open https://localhost:3001');
