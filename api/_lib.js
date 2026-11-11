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
// role: 'admin' (APP_USER / APP_PASSWORD) o 'editor' (personas definidas en Vercel con variables CLAVE_NOMBRE).
// v: huella de la contraseña del editor; si se cambia en Vercel, la sesión anterior deja de servir.
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
  const pw = envUsers()[s.u];
  if (!pw || passVersion(pw) !== s.v) return null;
  const rows = await sql`SELECT programas FROM app_permisos WHERE username = ${s.u}`;
  return { user: s.u, role: 'editor', nombre: displayName(s.u), programas: rows.length ? (rows[0].programas || []) : [] };
}
// Personas con acceso: una variable de entorno por persona, CLAVE_NOMBRE = su contraseña.
// El usuario es el nombre en minúsculas (CLAVE_PATRICIA -> "patricia"). Solo se administran en Vercel.
export function envUsers() {
  const out = {}; const admin = String(process.env.APP_USER || '').toLowerCase();
  for (const [k, v] of Object.entries(process.env)) {
    const m = /^CLAVE_([A-Z0-9_]+)$/.exec(k);
    if (!m || !v) continue;
    const u = m[1].toLowerCase();
    if (u !== admin) out[u] = v;
  }
  return out;
}
export function displayName(u) { return u.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '); }
export function passVersion(pw) { return sign('pv:' + pw).slice(0, 12); }
export function sessionCookie(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${token ? MAX_AGE : 0}`;
}
export function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
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
  await sql`CREATE TABLE IF NOT EXISTS app_permisos (username TEXT PRIMARY KEY, programas JSONB NOT NULL DEFAULT '[]'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
}
