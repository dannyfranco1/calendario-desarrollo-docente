import { sessionCookie } from './_lib.js';
export default function handler(req, res) {
  res.setHeader('Set-Cookie', sessionCookie(''));
  res.status(200).json({ ok: true });
}
