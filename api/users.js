import { auth, db, ensureTable, envUsers, displayName } from './_lib.js';

// Solo el admin decide qué programas ve cada persona. Las personas y sus contraseñas
// no se crean aquí: se definen en Vercel con variables CLAVE_NOMBRE.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const sql = db();
    await ensureTable(sql);
    const me = await auth(req, sql);
    if (!me) return res.status(401).json({ error: 'No autorizado' });
    if (me.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede hacer esto' });
    const people = Object.keys(envUsers()).sort();

    if (req.method === 'GET') {
      const rows = await sql`SELECT username, programas FROM app_permisos`;
      const perms = Object.fromEntries(rows.map(r => [r.username, r.programas || []]));
      return res.status(200).json({ users: people.map(u => ({ username: u, nombre: displayName(u), programas: perms[u] || [] })) });
    }
    if (req.method === 'POST') {
      const b = req.body || {};
      const username = String(b.username || '').trim().toLowerCase();
      if (!people.includes(username)) return res.status(400).json({ error: 'Esa persona no está definida en Vercel' });
      const programas = Array.isArray(b.programas) ? [...new Set(b.programas.map(String))] : [];
      await sql`INSERT INTO app_permisos (username, programas, updated_at) VALUES (${username}, ${JSON.stringify(programas)}::jsonb, now())
        ON CONFLICT (username) DO UPDATE SET programas = EXCLUDED.programas, updated_at = now()`;
      return res.status(200).json({ ok: true });
    }
    return res.status(405).end();
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
