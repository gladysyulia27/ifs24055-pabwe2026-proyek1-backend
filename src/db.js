let Database;
try {
  const { DatabaseSync } = await import('node:sqlite');
  Database = class extends DatabaseSync {
    pragma(sql) {
      return this.exec(`PRAGMA ${sql};`);
    }
    transaction(fn) {
      return (...args) => {
        this.exec('BEGIN');
        try {
          const res = fn(...args);
          this.exec('COMMIT');
          return res;
        } catch (e) {
          this.exec('ROLLBACK');
          throw e;
        }
      };
    }
  };
} catch {
  const mod = await import('better-sqlite3');
  Database = mod.default || mod;
}
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(here, '../data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'inventory.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS departments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  contact_name TEXT DEFAULT '',
  contact_email TEXT DEFAULT '',
  contact_phone TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  department_id INTEGER NOT NULL REFERENCES departments(id),
  name TEXT NOT NULL,
  category TEXT DEFAULT 'Umum',
  description TEXT DEFAULT '',
  total_stock INTEGER NOT NULL DEFAULT 1 CHECK(total_stock >= 0),
  available_stock INTEGER NOT NULL DEFAULT 1 CHECK(available_stock >= 0),
  condition_status TEXT NOT NULL DEFAULT 'Baik',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS loans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  inventory_id INTEGER NOT NULL REFERENCES inventory(id),
  borrower_name TEXT NOT NULL,
  borrower_id TEXT NOT NULL,
  borrower_contact TEXT DEFAULT '',
  organization TEXT DEFAULT 'Mahasiswa',
  purpose TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity > 0),
  start_date TEXT NOT NULL,
  due_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Menunggu Approval',
  return_proof_url TEXT DEFAULT '',
  return_note TEXT DEFAULT '',
  approved_by TEXT DEFAULT '',
  user_id INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  full_name TEXT NOT NULL,
  identifier TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('mahasiswa','admin_departemen')),
  department_id INTEGER REFERENCES departments(id),
  contact_phone TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL
);
`);

try {
  db.exec('ALTER TABLE loans ADD COLUMN user_id INTEGER REFERENCES users(id);');
} catch {
  // column already exists
}

try {
  db.exec('ALTER TABLE inventory ADD COLUMN image_url TEXT DEFAULT "";');
} catch {
  // column already exists
}

const count = db.prepare('SELECT COUNT(*) AS n FROM departments').get().n;
if (count === 0) {
  const insertDept = db.prepare('INSERT INTO departments (name, contact_name, contact_email) VALUES (?, ?, ?)');
  const depts = [
    ['DEPKOMINFO','Penanggung Jawab DEPKOMINFO','depkominfo@bem.itdel.ac.id'],
    ['DIPTEK','Penanggung Jawab DIPTEK','diptek@bem.itdel.ac.id'],
    ['DEPAGSOS','Penanggung Jawab DEPAGSOS','depagsos@bem.itdel.ac.id'],
    ['DPDK','Penanggung Jawab DPDK','dpdk@bem.itdel.ac.id'],
    ['DHPM','Penanggung Jawab DHPM','dhpm@bem.itdel.ac.id'],
    ['DESARPRAS','Penanggung Jawab DESARPRAS','desarpras@bem.itdel.ac.id'],
    ['DEPOL','Penanggung Jawab DEPOL','depol@bem.itdel.ac.id'],
    ['DEPSENBUD','Penanggung Jawab DEPSENBUD','depsenbud@bem.itdel.ac.id']
  ];
  const insertItem = db.prepare(`INSERT INTO inventory (department_id,name,category,description,total_stock,available_stock,condition_status)
    VALUES (?,?,?,?,?,?,?)`);
  const seeds = {
    DEPKOMINFO: [['Kamera','Dokumentasi','Kamera untuk dokumentasi kegiatan',2],['Microphone rekam','Audio','Microphone untuk perekaman',2],['Lightning','Pencahayaan','Perlengkapan lighting',3]],
    DIPTEK: [['Proyektor','Elektronik','Proyektor kegiatan',2],['Kabel HDMI','Aksesori','Kabel penghubung proyektor',4]],
    DEPAGSOS: [['Vas bunga','Dekorasi','Vas untuk kegiatan',4],['Alkitab','Perlengkapan','Alkitab inventaris',5],['Lilin','Perlengkapan','Lilin untuk kegiatan',20]],
    DPDK: [['Perlengkapan kegiatan','Umum','Inventaris DPDK',3]],
    DHPM: [['Perlengkapan acara','Umum','Inventaris DHPM',3]],
    DESARPRAS: [['Microphone','Audio','Microphone kegiatan',4],['Speaker','Audio','Speaker kegiatan',2],['Kabel','Aksesori','Kabel audio dan listrik',8]],
    DEPOL: [['Bola basket','Olahraga','Bola basket',4],['Bola futsal','Olahraga','Bola futsal',4],['Raket','Olahraga','Raket badminton',6],['Kok badminton','Olahraga','Shuttlecock',12],['Net','Olahraga','Net olahraga',2]],
    DEPSENBUD: [['Gitar','Musik','Gitar akustik',2],['Bass','Musik','Bass elektrik',1],['Pita tali','Kerajinan','Pita dan tali dekorasi',10],['Kuas','Seni','Kuas lukis',12]]
  };
  const seed = db.transaction(() => {
    for (const [name, contact, email] of depts) {
      const info = insertDept.run(name, contact, email);
      for (const [item, category, description, stock] of (seeds[name] || [])) {
        insertItem.run(info.lastInsertRowid, item, category, description, stock, stock, 'Baik');
      }
    }
  });
  seed();
}

// Ensure DEKEBDIS department exists
const existingDekebdis = db.prepare('SELECT id FROM departments WHERE name = ?').get('DEKEBDIS');
if (!existingDekebdis) {
  const info = db.prepare('INSERT INTO departments (name, contact_name, contact_email) VALUES (?, ?, ?)')
    .run('DEKEBDIS', 'Departemen Ketertiban dan Kedisiplinan', 'dekebdisitdel@gmail.com');
  const insertItem = db.prepare(`INSERT INTO inventory (department_id,name,category,description,total_stock,available_stock,condition_status)
    VALUES (?,?,?,?,?,?,?)`);
  insertItem.run(info.lastInsertRowid, 'Rompi Ketertiban Kampus', 'Perlengkapan', 'Rompi resmi petugas ketertiban BEM', 10, 10, 'Baik');
  insertItem.run(info.lastInsertRowid, 'Megaphone Komando', 'Audio', 'Megaphone pengarah apel dan ketertiban', 2, 2, 'Baik');
  insertItem.run(info.lastInsertRowid, 'Papan Rekapitulasi Pelanggaran', 'Administrasi', 'Papan penjagaan pos ketertiban', 3, 3, 'Baik');
}

// Seed or update admin accounts for each department with exact user-requested credentials
import crypto from 'node:crypto';

function makePasswordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

const defaultAdminPasswordHash = makePasswordHash('bemitdel123!');

// Ensure demo mahasiswa exists
const existingMahasiswa = db.prepare('SELECT id FROM users WHERE username = ?').get('mahasiswa');
if (!existingMahasiswa) {
  db.prepare(`
    INSERT INTO users (username, email, password_hash, full_name, identifier, role, department_id, contact_phone)
    VALUES (?, ?, ?, ?, ?, 'mahasiswa', null, ?)
  `).run('mahasiswa', 'mahasiswa@del.ac.id', defaultAdminPasswordHash, 'Andi Pratama Simanjuntak', '11S21001', '081234567890');
} else {
  db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(defaultAdminPasswordHash, 'mahasiswa');
}

const departmentAdmins = [
  {
    dept: 'DEPAGSOS',
    email: 'depagsositdel@gmail.com',
    username: 'Departemen Agama dan Sosial',
    fullName: 'Departemen Agama dan Sosial'
  },
  {
    dept: 'DPDK',
    email: 'dpdkitdel@gmail.com',
    username: 'Departemen Dalam Kampus',
    fullName: 'Departemen Dalam Kampus'
  },
  {
    dept: 'DIPTEK',
    email: 'diptekitdel@gmail.com',
    username: 'Departemen Ilmu Pengetahuan dan Teknologi',
    fullName: 'Departemen Ilmu Pengetahuan dan Teknologi'
  },
  {
    dept: 'DEPSENBUD',
    email: 'depsenbuditdel@gmail.com',
    username: 'Departemen Seni dan Budaya',
    fullName: 'Departemen Seni dan Budaya'
  },
  {
    dept: 'DHPM',
    email: 'dhpmitdel@gmail.com',
    username: 'Departemen Hubungan Pengabdian Masyarakat',
    fullName: 'Departemen Hubungan Pengabdian Masyarakat'
  },
  {
    dept: 'DEPOL',
    email: 'depolitdel@gmail.com',
    username: 'Departemen Olahraga',
    fullName: 'Departemen Olahraga'
  },
  {
    dept: 'DESARPRAS',
    email: 'desarprasitdel@gmail.com',
    username: 'Departemen Sarana dan Prasarana',
    fullName: 'Departemen Sarana dan Prasarana'
  },
  {
    dept: 'DEKEBDIS',
    email: 'dekebdisitdel@gmail.com',
    username: 'Departemen Ketertiban dan Kedisiplinan',
    fullName: 'Departemen Ketertiban dan Kedisiplinan'
  },
  {
    dept: 'DEPKOMINFO',
    email: 'depkomitdel@gmail.com',
    username: 'Departemen Komunikasi dan Informasi',
    fullName: 'Departemen Komunikasi dan Informasi'
  }
];

for (const admin of departmentAdmins) {
  const deptRow = db.prepare('SELECT id, name FROM departments WHERE name = ?').get(admin.dept);
  if (!deptRow) continue;

  // Check if account exists by email, username, or department_id
  const existing = db.prepare(`
    SELECT id FROM users
    WHERE email = ? OR username = ? OR (department_id = ? AND role = 'admin_departemen')
  `).get(admin.email, admin.username, deptRow.id);

  if (existing) {
    db.prepare(`
      UPDATE users
      SET username = ?, email = ?, password_hash = ?, full_name = ?, identifier = ?, role = 'admin_departemen', department_id = ?
      WHERE id = ?
    `).run(admin.username, admin.email, defaultAdminPasswordHash, admin.fullName, `PJ-${admin.dept}`, deptRow.id, existing.id);
  } else {
    db.prepare(`
      INSERT INTO users (username, email, password_hash, full_name, identifier, role, department_id, contact_phone)
      VALUES (?, ?, ?, ?, ?, 'admin_departemen', ?, '082198765432')
    `).run(admin.username, admin.email, defaultAdminPasswordHash, admin.fullName, `PJ-${admin.dept}`, deptRow.id);
  }
}

export default db;
