import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cors from 'cors';
import db from './db.js';
import {
  hashPassword,
  verifyPassword,
  timingSafeCompare,
  createSession,
  deleteSession,
  authMiddleware,
  requireAuth,
  requireRole,
  getUserByToken
} from './auth.js';

// Load .env jika tersedia di backend
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../.env');

if (typeof process.loadEnvFile === 'function' && fs.existsSync(envPath)) {
  try {
    process.loadEnvFile(envPath);
  } catch (err) {
    console.warn('Peringatan: Gagal memuat file .env:', err.message);
  }
}

const app = express();
const PORT = process.env.PORT || 4000;

const allowedOrigins = (process.env.FRONTEND_ORIGIN || 'http://localhost:3000,http://127.0.0.1:3000')
  .split(',')
  .map((o) => o.trim());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(authMiddleware);

const asyncRoute = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (e) {
    console.error(e);
    res.status(e.status || 500).json({ error: e.message || 'Terjadi kesalahan server.' });
  }
};

const bad = (message, status = 400) => Object.assign(new Error(message), { status });

// Health Check
app.get('/api/health', (_req, res) => res.json({ status: 'ok', service: 'BEM IT Del Inventory API' }));

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

// Register
app.post('/api/auth/register', asyncRoute((req, res) => {
  if (!req.body || typeof req.body !== 'object') {
    throw bad('Format data registrasi tidak valid (harus berupa JSON object).', 400);
  }

  const {
    username,
    email,
    password,
    full_name,
    identifier,
    role = 'mahasiswa',
    department_id,
    contact_phone = '',
    admin_secret = ''
  } = req.body;

  // 1. Validasi Keberadaan Field Wajib Dasar
  if (
    typeof username !== 'string' || !username.trim() ||
    typeof email !== 'string' || !email.trim() ||
    typeof password !== 'string' || !password ||
    typeof full_name !== 'string' || !full_name.trim() ||
    typeof identifier !== 'string' || !identifier.trim()
  ) {
    throw bad('Mohon lengkapi seluruh field wajib: Username, Email, Password, Nama Lengkap, dan NIM/NIP.', 400);
  }

  const cleanUsername = username.trim();
  const cleanEmail = email.trim().toLowerCase();
  const cleanFullName = full_name.trim();
  const cleanIdentifier = identifier.trim();
  const cleanPhone = typeof contact_phone === 'string' ? contact_phone.trim() : '';

  // 2. Validasi Format Username
  if (cleanUsername.length < 3 || cleanUsername.length > 30) {
    throw bad('Username harus memiliki panjang antara 3 hingga 30 karakter.', 400);
  }
  if (!/^[a-zA-Z0-9_.-]+$/.test(cleanUsername)) {
    throw bad('Username hanya boleh mengandung huruf, angka, titik (.), strip (-), atau garis bawah (_).', 400);
  }

  // 3. Validasi Format Email
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (cleanEmail.length > 100 || !emailRegex.test(cleanEmail)) {
    throw bad('Format alamat email tidak valid (contoh: user@del.ac.id atau user@gmail.com).', 400);
  }

  // 4. Validasi Password
  if (password.length < 6) {
    throw bad('Password minimal 6 karakter.', 400);
  }
  if (password.length > 128) {
    throw bad('Password maksimal 128 karakter.', 400);
  }

  // 5. Validasi Nama Lengkap
  if (cleanFullName.length < 2 || cleanFullName.length > 100) {
    throw bad('Nama lengkap harus memiliki panjang antara 2 hingga 100 karakter.', 400);
  }

  // 6. Validasi NIM/NIP (Identifier)
  if (cleanIdentifier.length < 3 || cleanIdentifier.length > 30) {
    throw bad('NIM/NIP harus memiliki panjang antara 3 hingga 30 karakter.', 400);
  }
  if (!/^[a-zA-Z0-9_\-\.\/ ]+$/.test(cleanIdentifier)) {
    throw bad('Format NIM/NIP tidak valid (hanya alfanumerik, strip, garis miring, atau titik).', 400);
  }

  // 7. Validasi Nomor Kontak / WhatsApp (Opsional)
  if (cleanPhone) {
    if (cleanPhone.length > 25 || !/^[0-9+()\- ]{7,25}$/.test(cleanPhone)) {
      throw bad('Format nomor kontak tidak valid (contoh: 08123456789 atau +628123456789).', 400);
    }
  }

  // 8. Validasi Peran (Role)
  const allowedRoles = ['mahasiswa', 'admin_departemen'];
  if (!allowedRoles.includes(role)) {
    throw bad(`Peran '${role}' tidak diizinkan untuk registrasi mandiri. Pilihan: mahasiswa atau admin_departemen.`, 400);
  }

  // 9. Validasi Khusus Berdasarkan Role & Secret Verifikasi (Tanpa Hardcoded Secret)
  let finalDeptId = null;
  if (role === 'admin_departemen') {
    if (!department_id) {
      throw bad('Admin departemen wajib memilih departemen yang akan dikelola.', 400);
    }
    const deptIdNum = Number(department_id);
    if (!Number.isInteger(deptIdNum) || deptIdNum <= 0) {
      throw bad('ID departemen yang dipilih tidak valid.', 400);
    }

    const dept = db.prepare('SELECT id, name FROM departments WHERE id=?').get(deptIdNum);
    if (!dept) {
      throw bad('Departemen yang dipilih tidak ditemukan dalam sistem.', 404);
    }
    finalDeptId = dept.id;

    // Membaca kode verifikasi admin dari environment variable (BUKAN hardcoded string)
    const serverAdminSecret = process.env.ADMIN_REGISTRATION_SECRET || process.env.ADMIN_SECRET;
    if (!serverAdminSecret) {
      throw bad('Pendaftaran admin departemen dinonaktifkan: secret verifikasi server belum dikonfigurasi.', 500);
    }

    const providedSecret = typeof admin_secret === 'string' ? admin_secret.trim() : '';
    if (!providedSecret) {
      throw bad('Kode verifikasi admin departemen (admin_secret) wajib diisi.', 400);
    }

    // Perbandingan string secara timing-safe untuk mencegah timing attacks
    if (!timingSafeCompare(providedSecret, serverAdminSecret)) {
      throw bad('Kode verifikasi admin departemen salah. Hubungi pengurus BEM IT Del.', 403);
    }
  }

  // 10. Pemeriksaan Duplikasi Username & Email
  const existingUser = db.prepare(`
    SELECT id, username, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?
  `).get(cleanUsername.toLowerCase(), cleanEmail.toLowerCase());

  if (existingUser) {
    if (existingUser.username.toLowerCase() === cleanUsername.toLowerCase()) {
      throw bad('Username sudah digunakan oleh akun lain.', 409);
    }
    throw bad('Alamat email sudah terdaftar dalam sistem.', 409);
  }

  // 11. Simpan Pengguna Baru
  const password_hash = hashPassword(password);
  const result = db.prepare(`
    INSERT INTO users (username, email, password_hash, full_name, identifier, role, department_id, contact_phone)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    cleanUsername.toLowerCase(),
    cleanEmail.toLowerCase(),
    password_hash,
    cleanFullName,
    cleanIdentifier,
    role,
    finalDeptId,
    cleanPhone
  );

  const session = createSession(result.lastInsertRowid);
  res.status(201).json({
    message: 'Pendaftaran berhasil.',
    token: session.token,
    user: session.user
  });
}));

// Login
app.post('/api/auth/login', asyncRoute((req, res) => {
  const { username_or_email, password } = req.body;
  if (!username_or_email?.trim() || !password) {
    throw bad('Username/Email dan Password wajib diisi.');
  }

  const query = username_or_email.trim().toLowerCase();
  const user = db.prepare(`
    SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?
  `).get(query, query);

  if (!user || !verifyPassword(password, user.password_hash)) {
    throw bad('Username/Email atau Password salah.', 401);
  }

  const session = createSession(user.id);
  res.json({
    message: 'Login berhasil.',
    token: session.token,
    user: session.user
  });
}));

// Get Current User
app.get('/api/auth/me', requireAuth, asyncRoute((req, res) => {
  res.json({ user: req.user });
}));

// Logout
app.post('/api/auth/logout', asyncRoute((req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.replace(/^Bearer\s+/i, '').trim();
    deleteSession(token);
  }
  res.json({ success: true, message: 'Logout berhasil.' });
}));

// Demo Accounts List for quick switch / ease of testing
app.get('/api/auth/demo-accounts', asyncRoute((_req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.full_name, u.identifier, u.role, u.department_id, d.name AS department_name
    FROM users u
    LEFT JOIN departments d ON d.id = u.department_id
    ORDER BY u.role DESC, u.username ASC
  `).all();
  res.json(users);
}));

// ==========================================
// DEPARTMENTS
// ==========================================

app.get('/api/departments', asyncRoute((_req, res) => {
  res.json(db.prepare(`
    SELECT d.*, COUNT(i.id) AS inventory_count
    FROM departments d
    LEFT JOIN inventory i ON i.department_id = d.id
    GROUP BY d.id
    ORDER BY d.name
  `).all());
}));

app.patch('/api/departments/:id/contact', requireRole('admin_departemen'), asyncRoute((req, res) => {
  // Department admin can only update their own department contact
  if (req.user.department_id !== Number(req.params.id)) {
    throw bad('Anda hanya berhak memperbarui kontak departemen Anda sendiri.', 403);
  }

  const { contact_name = '', contact_email = '', contact_phone = '' } = req.body;
  const result = db.prepare('UPDATE departments SET contact_name=?, contact_email=?, contact_phone=? WHERE id=?')
    .run(contact_name, contact_email, contact_phone, req.params.id);
  if (!result.changes) throw bad('Departemen tidak ditemukan.', 404);
  res.json(db.prepare('SELECT * FROM departments WHERE id=?').get(req.params.id));
}));

// ==========================================
// INVENTORY
// ==========================================

app.get('/api/inventory', asyncRoute((req, res) => {
  const { departmentId, search } = req.query;
  let sql = `SELECT i.*, d.name AS department_name FROM inventory i JOIN departments d ON d.id=i.department_id WHERE 1=1`;
  const params = [];
  if (departmentId) {
    sql += ' AND i.department_id=?';
    params.push(Number(departmentId));
  }
  if (search) {
    sql += ' AND (i.name LIKE ? OR i.category LIKE ? OR d.name LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  sql += ' ORDER BY d.name, i.name';
  res.json(db.prepare(sql).all(...params));
}));

// Add item (Only admin of that department)
app.post('/api/inventory', requireRole('admin_departemen'), asyncRoute((req, res) => {
  const { department_id, name, category = 'Umum', description = '', total_stock = 1, condition_status = 'Baik', image_url = '' } = req.body;

  // Admin departemen can only add items to their own department
  const targetDeptId = Number(department_id || req.user.department_id);
  if (targetDeptId !== req.user.department_id) {
    throw bad(`Anda hanya diizinkan menambahkan inventori untuk departemen Anda (${req.user.department_name}).`, 403);
  }

  if (!String(name || '').trim()) throw bad('Nama barang wajib diisi.');
  const stock = Number(total_stock);
  if (!Number.isInteger(stock) || stock < 0) throw bad('Stok harus berupa bilangan bulat non-negatif.');

  const result = db.prepare(`
    INSERT INTO inventory (department_id, name, category, description, total_stock, available_stock, condition_status, image_url)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(targetDeptId, String(name).trim(), category, description, stock, stock, condition_status, image_url || '');

  res.status(201).json(db.prepare(`
    SELECT i.*, d.name AS department_name
    FROM inventory i
    JOIN departments d ON d.id = i.department_id
    WHERE i.id = ?
  `).get(result.lastInsertRowid));
}));

// Edit item (Only admin of that department)
app.patch('/api/inventory/:id', requireRole('admin_departemen'), asyncRoute((req, res) => {
  const old = db.prepare('SELECT * FROM inventory WHERE id=?').get(req.params.id);
  if (!old) throw bad('Barang tidak ditemukan.', 404);

  if (old.department_id !== req.user.department_id) {
    throw bad(`Akses ditolak. Barang ini milik departemen lain dan hanya dapat diedit oleh pengelola departemen tersebut.`, 403);
  }

  const name = req.body.name ?? old.name;
  const category = req.body.category ?? old.category;
  const description = req.body.description ?? old.description;
  const condition = req.body.condition_status ?? old.condition_status;
  const image_url = req.body.image_url !== undefined ? req.body.image_url : (old.image_url || '');
  const total = req.body.total_stock === undefined ? old.total_stock : Number(req.body.total_stock);
  const borrowed = old.total_stock - old.available_stock;
  if (!Number.isInteger(total) || total < borrowed) throw bad('Stok total tidak boleh kurang dari jumlah barang yang sedang dipinjam.');

  db.prepare(`
    UPDATE inventory
    SET name=?, category=?, description=?, condition_status=?, total_stock=?, available_stock=?, image_url=?
    WHERE id=?
  `).run(name, category, description, condition, total, total - borrowed, image_url, req.params.id);

  res.json(db.prepare('SELECT * FROM inventory WHERE id=?').get(req.params.id));
}));

// Delete item (Only admin of that department)
app.delete('/api/inventory/:id', requireRole('admin_departemen'), asyncRoute((req, res) => {
  const item = db.prepare('SELECT * FROM inventory WHERE id=?').get(req.params.id);
  if (!item) throw bad('Barang tidak ditemukan.', 404);

  if (item.department_id !== req.user.department_id) {
    throw bad('Akses ditolak. Anda hanya berhak menghapus inventori milik departemen Anda.', 403);
  }

  const active = db.prepare(`
    SELECT COUNT(*) AS n
    FROM loans
    WHERE inventory_id=? AND status IN ('Menunggu Approval','Disetujui','Menunggu Konfirmasi Pengembalian')
  `).get(req.params.id).n;
  if (active) throw bad('Barang memiliki transaksi peminjaman aktif dan tidak dapat dihapus.', 409);

  db.prepare('DELETE FROM inventory WHERE id=?').run(req.params.id);
  res.json({ success: true, message: 'Barang berhasil dihapus.' });
}));

// ==========================================
// LOANS & TRANSACTIONS
// ==========================================

// Get loans with role-based filtering
app.get('/api/loans', asyncRoute((req, res) => {
  const { status, departmentId } = req.query;
  let sql = `
    SELECT l.*, i.name AS inventory_name, i.category, d.name AS department_name
    FROM loans l
    JOIN inventory i ON i.id = l.inventory_id
    JOIN departments d ON d.id = i.department_id
    WHERE 1=1
  `;
  const params = [];

  // If user is admin_departemen: only see loans for items belonging to their department
  if (req.user && req.user.role === 'admin_departemen') {
    sql += ' AND d.id = ?';
    params.push(req.user.department_id);
  }
  // If user is mahasiswa: only see their own loans
  else if (req.user && req.user.role === 'mahasiswa') {
    sql += ' AND (l.user_id = ? OR l.borrower_id = ?)';
    params.push(req.user.id, req.user.identifier);
  } else if (departmentId) {
    sql += ' AND d.id = ?';
    params.push(Number(departmentId));
  }

  if (status) {
    sql += ' AND l.status = ?';
    params.push(status);
  }

  sql += ' ORDER BY l.created_at DESC';
  res.json(db.prepare(sql).all(...params));
}));

// Submit Loan Request (Mahasiswa)
app.post('/api/loans', requireAuth, asyncRoute((req, res) => {
  if (req.user.role === 'admin_departemen') {
    throw bad('Akun Admin Departemen tidak dapat mengajukan peminjaman. Gunakan akun Mahasiswa.', 403);
  }

  const {
    inventory_id,
    borrower_name = req.user.full_name,
    borrower_id = req.user.identifier,
    borrower_contact = req.user.contact_phone || '',
    organization = 'Mahasiswa',
    purpose,
    quantity = 1,
    start_date,
    due_date
  } = req.body;

  const qty = Number(quantity);
  if (!inventory_id || !purpose?.trim() || !start_date || !due_date) {
    throw bad('Lengkapi seluruh informasi wajib peminjaman.');
  }
  if (due_date < start_date) throw bad('Tanggal pengembalian harus sama atau setelah tanggal pinjam.');
  if (!Number.isInteger(qty) || qty < 1) throw bad('Jumlah pinjam minimal 1 unit.');

  const item = db.prepare('SELECT * FROM inventory WHERE id=?').get(inventory_id);
  if (!item) throw bad('Barang tidak ditemukan.', 404);
  if (item.available_stock < qty) throw bad(`Stok tersedia hanya ${item.available_stock}.`, 409);

  const result = db.prepare(`
    INSERT INTO loans (inventory_id, borrower_name, borrower_id, borrower_contact, organization, purpose, quantity, start_date, due_date, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    inventory_id,
    borrower_name.trim(),
    borrower_id.trim(),
    borrower_contact.trim(),
    organization,
    purpose.trim(),
    qty,
    start_date,
    due_date,
    req.user.id
  );

  res.status(201).json({
    id: result.lastInsertRowid,
    status: 'Menunggu Approval',
    message: 'Pengajuan peminjaman berhasil dikirim ke penanggung jawab departemen.'
  });
}));

// Approve Loan (Only admin of that department)
app.patch('/api/loans/:id/approve', requireRole('admin_departemen'), asyncRoute((req, res) => {
  const approve = db.transaction(() => {
    const loan = db.prepare(`
      SELECT l.*, i.department_id, d.name AS department_name
      FROM loans l
      JOIN inventory i ON i.id = l.inventory_id
      JOIN departments d ON d.id = i.department_id
      WHERE l.id = ?
    `).get(req.params.id);

    if (!loan) throw bad('Pengajuan tidak ditemukan.', 404);
    if (loan.department_id !== req.user.department_id) {
      throw bad(`Akses ditolak. Pengajuan ini untuk barang departemen ${loan.department_name}, bukan departemen Anda.`, 403);
    }
    if (loan.status !== 'Menunggu Approval') throw bad('Pengajuan ini sudah diproses.', 409);

    const item = db.prepare('SELECT * FROM inventory WHERE id=?').get(loan.inventory_id);
    if (item.available_stock < loan.quantity) throw bad('Stok tidak lagi mencukupi.', 409);

    db.prepare('UPDATE inventory SET available_stock = available_stock - ? WHERE id=?').run(loan.quantity, loan.inventory_id);
    const approvedBy = `${req.user.full_name} (${req.user.department_name})`;
    db.prepare(`UPDATE loans SET status='Disetujui', approved_by=? WHERE id=?`).run(approvedBy, loan.id);

    return db.prepare('SELECT * FROM loans WHERE id=?').get(loan.id);
  });
  res.json(approve());
}));

// Reject Loan (Only admin of that department)
app.patch('/api/loans/:id/reject', requireRole('admin_departemen'), asyncRoute((req, res) => {
  const loan = db.prepare(`
    SELECT l.*, i.department_id, d.name AS department_name
    FROM loans l
    JOIN inventory i ON i.id = l.inventory_id
    JOIN departments d ON d.id = i.department_id
    WHERE l.id = ?
  `).get(req.params.id);

  if (!loan) throw bad('Pengajuan tidak ditemukan.', 404);
  if (loan.department_id !== req.user.department_id) {
    throw bad(`Akses ditolak. Pengajuan ini milik departemen ${loan.department_name}.`, 403);
  }
  if (loan.status !== 'Menunggu Approval') throw bad('Hanya pengajuan menunggu yang dapat ditolak.', 409);

  db.prepare(`UPDATE loans SET status='Ditolak', return_note=? WHERE id=?`).run(req.body.reason || 'Ditolak oleh pengelola departemen.', loan.id);
  res.json({ success: true, message: 'Pengajuan peminjaman ditolak.' });
}));

// Submit Return Proof (Mahasiswa who borrowed)
app.patch('/api/loans/:id/return', requireAuth, asyncRoute((req, res) => {
  const loan = db.prepare('SELECT * FROM loans WHERE id=?').get(req.params.id);
  if (!loan) throw bad('Peminjaman tidak ditemukan.', 404);

  // If mahasiswa, verify it is their own loan
  if (req.user.role === 'mahasiswa' && loan.user_id && loan.user_id !== req.user.id && loan.borrower_id !== req.user.identifier) {
    throw bad('Anda hanya dapat mengirim bukti untuk peminjaman Anda sendiri.', 403);
  }

  if (!['Disetujui', 'Menunggu Konfirmasi Pengembalian'].includes(loan.status)) {
    throw bad('Status peminjaman ini tidak dapat dikembalikan.', 409);
  }
  if (!req.body.return_proof_url?.trim()) {
    throw bad('Bukti foto pengembalian wajib disertakan.');
  }

  db.prepare(`UPDATE loans SET status='Menunggu Konfirmasi Pengembalian', return_proof_url=?, return_note=? WHERE id=?`)
    .run(req.body.return_proof_url.trim(), req.body.return_note || '', loan.id);

  res.json({ success: true, status: 'Menunggu Konfirmasi Pengembalian', message: 'Bukti pengembalian telah dikirim.' });
}));

// Confirm Return (Only admin of that department)
app.patch('/api/loans/:id/confirm-return', requireRole('admin_departemen'), asyncRoute((req, res) => {
  const confirm = db.transaction(() => {
    const loan = db.prepare(`
      SELECT l.*, i.department_id, d.name AS department_name
      FROM loans l
      JOIN inventory i ON i.id = l.inventory_id
      JOIN departments d ON d.id = i.department_id
      WHERE l.id = ?
    `).get(req.params.id);

    if (!loan) throw bad('Peminjaman tidak ditemukan.', 404);
    if (loan.department_id !== req.user.department_id) {
      throw bad(`Akses ditolak. Pengembalian ini untuk barang milik departemen ${loan.department_name}.`, 403);
    }
    if (loan.status !== 'Menunggu Konfirmasi Pengembalian') {
      throw bad('Belum ada bukti pengembalian yang menunggu konfirmasi.', 409);
    }

    db.prepare(`UPDATE loans SET status='Dikembalikan' WHERE id=?`).run(loan.id);
    db.prepare('UPDATE inventory SET available_stock = available_stock + ? WHERE id=?').run(loan.quantity, loan.inventory_id);
    return { success: true, message: 'Pengembalian barang telah dikonfirmasi dan stok telah dipulihkan.' };
  });
  res.json(confirm());
}));

// Calendar
app.get('/api/loans/calendar', asyncRoute((req, res) => {
  let sql = `
    SELECT l.id, l.start_date, l.due_date, l.quantity, l.status, l.borrower_name, i.name AS inventory_name, d.name AS department_name
    FROM loans l
    JOIN inventory i ON i.id = l.inventory_id
    JOIN departments d ON d.id = i.department_id
    WHERE l.status IN ('Disetujui', 'Menunggu Konfirmasi Pengembalian')
  `;
  const params = [];
  if (req.user && req.user.role === 'admin_departemen') {
    sql += ' AND d.id = ?';
    params.push(req.user.department_id);
  }
  sql += ' ORDER BY l.start_date';
  res.json(db.prepare(sql).all(...params));
}));

// Notifications
app.get('/api/notifications', asyncRoute((req, res) => {
  let deptFilter = '';
  const params = [];
  if (req.user && req.user.role === 'admin_departemen') {
    deptFilter = ' AND d.id = ?';
    params.push(req.user.department_id);
  }

  const due = db.prepare(`
    SELECT l.id, l.borrower_name, l.due_date, i.name AS inventory_name, d.name AS department_name
    FROM loans l
    JOIN inventory i ON i.id = l.inventory_id
    JOIN departments d ON d.id = i.department_id
    WHERE l.status='Disetujui' AND date(l.due_date) <= date('now','+2 days') ${deptFilter}
    ORDER BY l.due_date
  `).all(...params);

  const pending = db.prepare(`
    SELECT l.id, l.borrower_name, i.name AS inventory_name, d.name AS department_name, l.created_at
    FROM loans l
    JOIN inventory i ON i.id = l.inventory_id
    JOIN departments d ON d.id = i.department_id
    WHERE l.status IN ('Menunggu Approval','Menunggu Konfirmasi Pengembalian') ${deptFilter}
    ORDER BY l.created_at DESC
  `).all(...params);

  res.json({ due_returns: due, pending });
}));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Kesalahan server' });
});

export { app };

const isTest =
  process.env.NODE_ENV === 'test' ||
  process.execArgv.some((arg) => arg.includes('test')) ||
  process.argv.some((arg) => typeof arg === 'string' && arg.includes('test'));

if (!isTest) {
  app.listen(PORT, () => console.log(`Inventory API listening at http://localhost:${PORT}`));
}
