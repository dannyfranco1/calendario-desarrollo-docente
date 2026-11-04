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
export function makeToken() {
  const exp = Math.floor(Date.now() / 1000) + MAX_AGE;
  const payload = `${process.env.APP_USER}.${exp}`;
  return `${Buffer.from(payload).toString('base64url')}.${sign(payload)}`;
}
export function isAuthed(req) {
  const raw = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  if (!raw) return false;
  const [p64, sig] = raw.slice(COOKIE.length + 1).split('.');
  if (!p64 || !sig) return false;
  const payload = Buffer.from(p64, 'base64url').toString();
  const good = sign(payload);
  if (good.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(good), Buffer.from(sig))) return false;
  const exp = Number(payload.split('.').pop());
  return exp > Date.now() / 1000;
}
export function sessionCookie(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${token ? MAX_AGE : 0}`;
}
export function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
export function db() {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) throw new Error('Falta DATABASE_URL');
  return neon(url);
}
export async function ensureTable(sql) {
  await sql`CREATE TABLE IF NOT EXISTS app_state (id INT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())`;
}
