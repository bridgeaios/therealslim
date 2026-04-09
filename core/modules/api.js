import express from 'express';
import { v4 as uuid } from 'uuid';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import fs from './fs.js';

const fsReadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" }
});

// Collect all VFS paths into a flat Set for path validation
function buildAllowedPaths(vfs) {
  const allowed = new Set();
  for (const drive in vfs) {
    for (const file of vfs[drive]) {
      allowed.add(file);
    }
  }
  return allowed;
}

export async function initAPI({ vfs, secrets }) {
  const app = express();
  app.use(express.json());

  const allowedPaths = buildAllowedPaths(vfs);

  // AUTH MIDDLEWARE
  app.use((req, res, next) => {
    const token = req.headers['x-auth'];
    if (!validate(token, secrets)) {
      return res.status(403).json({ error: "Unauthorized" });
    }
    next();
  });

  // FILE INDEX
  app.get('/fs', (req, res) => {
    res.json(vfs);
  });

  // FILE READ
  app.post('/fs/read', fsReadLimiter, async (req, res) => {
    const { path } = req.body;
    if (!path || !allowedPaths.has(path)) {
      return res.status(403).json({ error: "Path not allowed" });
    }
    try {
      const data = await fs.readFile(path, 'utf-8');
      res.json({ data });
    } catch (err) {
      const msg = err.code === 'ENOENT' ? "File not found" : "Read failed";
      res.status(500).json({ error: msg });
    }
  });

  // CRYPTO PIPE (ENIGMA STYLE)
  app.post('/crypto', (req, res) => {
    if (!secrets.CRYPTO_KEY) {
      return res.status(500).json({ error: "Crypto key unavailable" });
    }
    const { payload } = req.body;
    const encrypted = encrypt(payload, secrets.CRYPTO_KEY);
    res.json({ encrypted });
  });

  // SITEMAP (AUTO GENERATED)
  app.get('/sitemap', (req, res) => {
    res.json({
      routes: [
        "/fs",
        "/fs/read",
        "/crypto",
        "/sitemap"
      ]
    });
  });

  app.listen(8080, () => {
    console.log("API RUNNING :8080");
  });
}

function validate(token, secrets) {
  if (!token) return false;
  return token === hmac(secrets.API_KEY);
}

function hmac(val) {
  // Use HMAC-SHA256 for token validation to prevent length-extension attacks
  const secret = process.env.ENIGMA_SHARED_SECRET || '';
  return crypto.createHmac('sha256', secret).update(val).digest('hex');
}

function encrypt(data, key) {
  const cipher = crypto.createCipheriv(
    'aes-256-cbc',
    Buffer.from(key, 'hex'),
    Buffer.alloc(16, 0)
  );
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}
