import test from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../src/server.js';
import db from '../src/db.js';

let server;
let baseUrl;

test.before(async () => {
  // Set secret untuk testing
  process.env.ADMIN_REGISTRATION_SECRET = 'TEST_ADMIN_SECRET_KEY';

  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}/api`;
      resolve();
    });
  });
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('POST /api/auth/register: berhasil mendaftar sebagai mahasiswa dengan input valid', async () => {
  const timestamp = Date.now();
  const payload = {
    username: `mhs_${timestamp}`,
    email: `mhs_${timestamp}@del.ac.id`,
    password: 'password123',
    full_name: 'Budi Santoso',
    identifier: `11S21${String(timestamp).slice(-3)}`,
    contact_phone: '081234567890'
  };

  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  assert.equal(res.status, 201);
  assert.ok(data.token);
  assert.equal(data.user.username, payload.username.toLowerCase());
  assert.equal(data.user.role, 'mahasiswa');
  assert.equal(data.user.department_id, null);
});

test('POST /api/auth/register: gagal jika field wajib tidak lengkap', async () => {
  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'user_kurang',
      email: 'user_kurang@del.ac.id'
      // password, full_name, identifier tidak dikirim
    })
  });

  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /Mohon lengkapi seluruh field wajib/i);
});

test('POST /api/auth/register: validasi format username & panjang', async () => {
  const resShort = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'ab',
      email: 'valid@del.ac.id',
      password: 'password123',
      full_name: 'Testing User',
      identifier: '11S21099'
    })
  });
  const dataShort = await resShort.json();
  assert.equal(resShort.status, 400);
  assert.match(dataShort.error, /Username harus memiliki panjang/i);

  const resInvalidChar = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'user space!@#',
      email: 'valid@del.ac.id',
      password: 'password123',
      full_name: 'Testing User',
      identifier: '11S21099'
    })
  });
  const dataInvalid = await resInvalidChar.json();
  assert.equal(resInvalidChar.status, 400);
  assert.match(dataInvalid.error, /Username hanya boleh mengandung huruf/i);
});

test('POST /api/auth/register: validasi format email', async () => {
  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `user_${Date.now()}`,
      email: 'bukan-email-valid',
      password: 'password123',
      full_name: 'Testing Email',
      identifier: '11S21099'
    })
  });

  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /Format alamat email tidak valid/i);
});

test('POST /api/auth/register: validasi password minimal 6 karakter', async () => {
  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `user_${Date.now()}`,
      email: 'pwd@del.ac.id',
      password: '123',
      full_name: 'Testing Pwd',
      identifier: '11S21099'
    })
  });

  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /Password minimal 6 karakter/i);
});

test('POST /api/auth/register: mencegah duplikasi username dan email', async () => {
  const uniqueName = `dup_${Date.now()}`;
  const uniqueEmail = `${uniqueName}@del.ac.id`;

  // Register pertama
  const res1 = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: uniqueName,
      email: uniqueEmail,
      password: 'password123',
      full_name: 'First Registrant',
      identifier: '11S21001'
    })
  });
  assert.equal(res1.status, 201);

  // Coba daftar lagi dengan username yang sama
  const resDupUser = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: uniqueName,
      email: `other_${Date.now()}@del.ac.id`,
      password: 'password123',
      full_name: 'Another User',
      identifier: '11S21002'
    })
  });
  const dataDupUser = await resDupUser.json();
  assert.equal(resDupUser.status, 409);
  assert.match(dataDupUser.error, /Username sudah digunakan/i);

  // Coba daftar lagi dengan email yang sama
  const resDupEmail = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `different_${Date.now()}`,
      email: uniqueEmail,
      password: 'password123',
      full_name: 'Another User',
      identifier: '11S21003'
    })
  });
  const dataDupEmail = await resDupEmail.json();
  assert.equal(resDupEmail.status, 409);
  assert.match(dataDupEmail.error, /email sudah terdaftar/i);
});

test('POST /api/auth/register: peran tidak valid atau unauthorized diblokir', async () => {
  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `admin_${Date.now()}`,
      email: `fakeadmin_${Date.now()}@del.ac.id`,
      password: 'password123',
      full_name: 'Hacker Admin',
      identifier: '999999',
      role: 'admin' // role superadmin tidak boleh didaftarkan lewat register mandiri
    })
  });

  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /tidak diizinkan untuk registrasi mandiri/i);
});

test('POST /api/auth/register: admin_departemen wajib menyertakan departemen', async () => {
  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `adm_${Date.now()}`,
      email: `adm_${Date.now()}@del.ac.id`,
      password: 'password123',
      full_name: 'Admin Tanpa Dept',
      identifier: 'ADM001',
      role: 'admin_departemen'
    })
  });

  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /wajib memilih departemen/i);
});

test('POST /api/auth/register: admin_departemen wajib menyertakan admin_secret (tidak boleh bypass)', async () => {
  const dept = db.prepare('SELECT id FROM departments LIMIT 1').get();
  assert.ok(dept, 'Harus ada departemen di database');

  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `adm_nosecret_${Date.now()}`,
      email: `adm_nosecret_${Date.now()}@del.ac.id`,
      password: 'password123',
      full_name: 'Admin Departemen',
      identifier: 'ADM002',
      role: 'admin_departemen',
      department_id: dept.id
      // admin_secret dikosongkan
    })
  });

  const data = await res.json();
  assert.equal(res.status, 400);
  assert.match(data.error, /Kode verifikasi admin departemen.*wajib diisi/i);
});

test('POST /api/auth/register: admin_departemen ditolak bila secret salah (403)', async () => {
  const dept = db.prepare('SELECT id FROM departments LIMIT 1').get();

  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `adm_wrong_${Date.now()}`,
      email: `adm_wrong_${Date.now()}@del.ac.id`,
      password: 'password123',
      full_name: 'Admin Salah Secret',
      identifier: 'ADM003',
      role: 'admin_departemen',
      department_id: dept.id,
      admin_secret: 'KODE_RAHASIA_SALAH'
    })
  });

  const data = await res.json();
  assert.equal(res.status, 403);
  assert.match(data.error, /Kode verifikasi admin departemen salah/i);
});

test('POST /api/auth/register: admin_departemen berhasil bila secret env valid (201)', async () => {
  const dept = db.prepare('SELECT id FROM departments LIMIT 1').get();

  const res = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: `adm_valid_${Date.now()}`,
      email: `adm_valid_${Date.now()}@del.ac.id`,
      password: 'password123',
      full_name: 'Admin Departemen Sah',
      identifier: 'ADM004',
      role: 'admin_departemen',
      department_id: dept.id,
      admin_secret: process.env.ADMIN_REGISTRATION_SECRET
    })
  });

  const data = await res.json();
  assert.equal(res.status, 201);
  assert.equal(data.user.role, 'admin_departemen');
  assert.equal(data.user.department_id, dept.id);
});
