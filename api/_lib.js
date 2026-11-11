import crypto from 'node:crypto';
import { neon } from '@neondatabase/serverless';

const COOKIE = 'cdd_session';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 días

function secret() {
  return process.env.AUTH_SECRET || ('cdd:' + (process.env.APP_PASSWORD || ''));
}
function sign(payload) {
  return crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
}
// role: 'admin' (usuario de las variables de entorno) o 'editor' (usuarios creados por el admin).
// v: huella de la contraseña del editor; si el admin la cambia, la sesión anterior deja de servir.
export function makeToken(u, role = 'admin', v = '') {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
  const payload = JSON.stringify({ u, r: role, v, exp });
  return `${Buffer.from(payload).toString('base64url')}.${sign(payload)}`;
}
function readSession(req) {
  const raw = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  if (!raw) return null;
  const [p64, sig] = raw.slice(COOKIE.length + 1).split('.');
  if (!p64 || !sig) return null;
  const payload = Buffer.from(p64, 'base64url').toString();
  const good = sign(payload);
  if (good.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(good), Buffer.from(sig))) return null;
  let s;
  if (payload.startsWith('{')) {
    try { s = JSON.parse(payload); } catch { return null; }
  } else {
    // formato anterior (solo existía el admin): "usuario.exp"
    s = { u: payload.slice(0, payload.lastIndexOf('.')), r: 'admin', v: '', exp: Number(payload.split('.').pop()) };
  }
  if (!(s.exp > Date.now() / 1000)) return null;
  return s;
}
// Devuelve { user, role, nombre, programas } o null. programas = null para el admin (ve todo).
export async function auth(req, sql) {
  const s = readSession(req);
  if (!s) return null;
  if (s.r === 'admin') {
    if (s.u !== process.env.APP_USER) return null;
    return { user: s.u, role: 'admin', nombre: '', programas: null };
  }
  const rows = await sql`SELECT username, nombre, pass_hash, programas FROM app_users WHERE username = ${s.u}`;
  if (!rows.length || passVersion(rows[0].pass_hash) !== s.v) return null;
  return { user: rows[0].username, role: 'editor', nombre: rows[0].nombre, programas: rows[0].programas || [] };
}
export function sessionCookie(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${token ? MAX_AGE : 0}`;
}
export function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
export function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `scrypt$${salt}$${crypto.scryptSync(String(pw), salt, 32).toString('hex')}`;
}
export function checkPassword(pw, stored) {
  const [, salt, hash] = String(stored).split('$');
  if (!salt || !hash) return false;
  return safeEqual(crypto.scryptSync(String(pw), salt, 32).toString('hex'), hash);
}
export function passVersion(stored) { return String(stored).slice(-10); }
export function newId() { return 'p_' + crypto.randomBytes(5).toString('hex'); }
// Cada programa necesita un id estable para poder asignarle permisos. Devuelve true si tuvo que crear alguno.
export function ensureIds(data) {
  let changed = false; const seen = new Set();
  for (const p of data.programas) {
    if (!p.id || seen.has(p.id)) { p.id = newId(); changed = true; }
    seen.add(p.id);
  }
  return changed;
}
export function db() {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) throw new Error('Falta DATABASE_URL');
  return neon(url);
}
export async function ensureTable(sql) {
  await sql`CREATE TABLE IF NOT EXISTS app_state (id INT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
  await sql`CREATE TABLE IF NOT EXISTS app_users (username TEXT PRIMARY KEY, nombre TEXT NOT NULL DEFAULT '', pass_hash TEXT NOT NULL, programas JSONB NOT NULL DEFAULT '[]'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
}
