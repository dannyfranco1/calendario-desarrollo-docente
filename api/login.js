import { makeToken, sessionCookie, safeEqual, checkPassword, passVersion, db, ensureTable } from './_lib.js';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  const { user, password } = req.body || {};
  const U = process.env.APP_USER, P = process.env.APP_PASSWORD;
  if (!U || !P) return res.status(500).json({ error: 'Faltan APP_USER / APP_PASSWORD en Vercel' });
  if (safeEqual(user || '', U) && safeEqual(password || '', P)) {
    res.setHeader('Set-Cookie', sessionCookie(makeToken(U, 'admin')));
    return res.status(200).json({ ok: true });
  }
  try {
    const sql = db();
    await ensureTable(sql);
    const name = String(user || '').trim().toLowerCase();
    const rows = await sql`SELECT username, pass_hash FROM app_users WHERE username = ${name}`;
    if (rows.length && checkPassword(password || '', rows[0].pass_hash)) {
      res.setHeader('Set-Cookie', sessionCookie(makeToken(rows[0].username, 'editor', passVersion(rows[0].pass_hash))));
      return res.status(200).json({ ok: true });
    }
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
  return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
}
