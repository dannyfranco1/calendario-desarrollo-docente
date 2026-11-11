import { auth, db, ensureTable, hashPassword } from './_lib.js';

// Solo el admin administra personas y sus permisos.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const sql = db();
    await ensureTable(sql);
    const me = await auth(req, sql);
    if (!me) return res.status(401).json({ error: 'No autorizado' });
    if (me.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede hacer esto' });

    if (req.method === 'GET') {
      const rows = await sql`SELECT username, nombre, programas FROM app_users ORDER BY nombre, username`;
      return res.status(200).json({ users: rows });
    }
    if (req.method === 'POST') {
      const b = req.body || {};
      const username = String(b.username || '').trim().toLowerCase();
      const nombre = String(b.nombre || '').trim().slice(0, 80);
      const password = b.password ? String(b.password) : '';
      const programas = Array.isArray(b.programas) ? [...new Set(b.programas.map(String))] : [];
      if (!/^[a-z0-9._-]{3,30}$/.test(username)) return res.status(400).json({ error: 'El usuario debe tener entre 3 y 30 caracteres: letras, números, punto o guion, sin espacios' });
      if (username === String(process.env.APP_USER || '').toLowerCase()) return res.status(400).json({ error: 'Ese usuario es el del administrador' });
      if (password && password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
      const exists = (await sql`SELECT 1 FROM app_users WHERE username = ${username}`).length > 0;
      if (b.nuevo && exists) return res.status(400).json({ error: 'Ya existe una persona con ese usuario' });
      if (!exists && !password) return res.status(400).json({ error: 'Falta la contraseña' });
      if (!exists) {
        await sql`INSERT INTO app_users (username, nombre, pass_hash, programas) VALUES (${username}, ${nombre}, ${hashPassword(password)}, ${JSON.stringify(programas)}::jsonb)`;
      } else if (password) {
        await sql`UPDATE app_users SET nombre = ${nombre}, pass_hash = ${hashPassword(password)}, programas = ${JSON.stringify(programas)}::jsonb, updated_at = now() WHERE username = ${username}`;
      } else {
        await sql`UPDATE app_users SET nombre = ${nombre}, programas = ${JSON.stringify(programas)}::jsonb, updated_at = now() WHERE username = ${username}`;
      }
      return res.status(200).json({ ok: true });
    }
    if (req.method === 'DELETE') {
      const username = String((req.query && req.query.username) || '').trim().toLowerCase();
      await sql`DELETE FROM app_users WHERE username = ${username}`;
      return res.status(200).json({ ok: true });
    }
    return res.status(405).end();
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
