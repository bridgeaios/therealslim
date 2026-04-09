import crypto from 'crypto';

const ENIGMA_SOCKET = process.env.ENIGMA_SOCKET || "http://localhost:7070/keys";

export async function initIPC() {
  const res = await fetch(ENIGMA_SOCKET);
  const payload = await res.json();

  const decrypted = {};
  for (const key in payload) {
    decrypted[key] = decrypt(payload[key]);
  }

  return decrypted;
}

function decrypt(data) {
  const key = process.env.ENIGMA_SHARED_SECRET;
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    Buffer.from(key, 'hex'),
    Buffer.alloc(16, 0)
  );
  let decrypted = decipher.update(data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}
