import crypto from 'node:crypto';
import db from './db.js';

const TOKEN_SECRET = process.env.SESSION_SECRET || process.env.JWT_SECRET || 'BEM_DEL_INVENTORY_SECRET_KEY_2026';

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, key] = stored.split(':');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return hash === key;
}

export function timingSafeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function signHmac(data) {
  return crypto.createHmac('sha256', TOKEN_SECRET).update(data).digest('base64url');
}

export function createSession(userId) {
  const user = getUserById(userId);
  const expiresAtMs = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const expiresAt = new Date(expiresAtMs).toISOString();

  // Create HMAC-signed stateless token so every serverless instance can verify it
  const payload = {
    uid: user ? user.id : userId,
    un: user ? user.username : '',
    em: user ? user.email : '',
    fn: user ? user.full_name : '',
    id: user ? user.identifier : '',
    ro: user ? user.role : 'mahasiswa',
    di: user ? user.department_id : null,
    dn: user ? user.department_name : null,
    ph: (user && user.contact_phone) ? user.contact_phone : '',
    exp: expiresAtMs
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = signHmac(payloadB64);
  const token = `v1.${payloadB64}.${sig}`;

  try {
    db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expiresAt);
  } catch {
    // ignore
  }

  return { token, user, expiresAt };
}

export function deleteSession(token) {
  if (!token) return;
  try {
    db.prepare('DELETE FROM sessions WHERE token=?').run(token);
  } catch {
    // ignore
  }
}

export function getUserById(userId) {
  try {
    const user = db.prepare(`
      SELECT u.id, u.username, u.email, u.full_name, u.identifier, u.role, u.department_id, u.contact_phone, u.created_at,
             d.name AS department_name
      FROM users u
      LEFT JOIN departments d ON d.id = u.department_id
      WHERE u.id = ?
    `).get(userId);
    return user || null;
  } catch {
    return null;
  }
}

export function getUserByToken(token) {
  if (!token || typeof token !== 'string') return null;

  // 1. Check if token is an HMAC-signed stateless token (v1.payload.sig)
  if (token.startsWith('v1.')) {
    const parts = token.split('.');
    if (parts.length === 3) {
      const [, payloadB64, providedSig] = parts;
      const expectedSig = signHmac(payloadB64);
      if (timingSafeCompare(providedSig, expectedSig)) {
        try {
          const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8'));
          if (payload && payload.exp && payload.exp > Date.now()) {
            // Check if user exists in the local database instance
            let user = getUserById(payload.uid);
            if (!user) {
              // Ensure user exists locally so foreign key checks on loans/etc succeed
              try {
                db.prepare(`
                  INSERT OR IGNORE INTO users (id, username, email, password_hash, full_name, identifier, role, department_id, contact_phone)
                  VALUES (?, ?, ?, 'EXTERNAL_SYNCED', ?, ?, ?, ?, ?)
                `).run(
                  payload.uid,
                  payload.un,
                  payload.em,
                  payload.fn,
                  payload.id,
                  payload.ro,
                  payload.di,
                  payload.ph || ''
                );
                user = getUserById(payload.uid);
              } catch {
                // Ignore conflict
              }
            }

            if (!user) {
              user = {
                id: payload.uid,
                username: payload.un,
                email: payload.em,
                full_name: payload.fn,
                identifier: payload.id,
                role: payload.ro,
                department_id: payload.di,
                department_name: payload.dn,
                contact_phone: payload.ph || '',
                created_at: new Date().toISOString()
              };
            }
            return user;
          }
        } catch {
          // JSON parse failed
        }
      }
    }
    return null;
  }

  // 2. Fallback to sessions table for legacy hex tokens
  try {
    const session = db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
    if (!session) return null;
    if (new Date(session.expires_at) < new Date()) {
      try { db.prepare('DELETE FROM sessions WHERE token=?').run(token); } catch {}
      return null;
    }
    return getUserById(session.user_id);
  } catch {
    return null;
  }
}

export function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    req.user = null;
    return next();
  }
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  req.user = getUserByToken(token);
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Sesi tidak valid atau telah berakhir. Silakan login kembali.' });
  }
  next();
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: `Akses ditolak. Fitur ini khusus untuk peran: ${roles.join(', ')}.` });
    }
    next();
  };
}
