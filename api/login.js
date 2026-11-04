import { makeToken, sessionCookie, safeEqual } from './_lib.js';

export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  const { user, password } = req.body || {};
  const U = process.env.APP_USER, P = process.env.APP_PASSWORD;
  if (!U || !P) return res.status(500).json({ error: 'Faltan APP_USER / APP_PASSWORD en Vercel' });
  if (safeEqual(user || '', U) && safeEqual(password || '', P)) {
    res.setHeader('Set-Cookie', sessionCookie(makeToken()));
    return res.status(200).json({ ok: true });
  }
  return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
}
