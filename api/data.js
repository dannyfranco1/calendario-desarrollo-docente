import { readFileSync } from 'node:fs';
import { auth, db, ensureTable, ensureIds } from './_lib.js';

const seed = JSON.parse(readFileSync(new URL('./_seed.json', import.meta.url), 'utf8'));

async function loadState(sql) {
  let rows = await sql`SELECT data FROM app_state WHERE id = 1`;
  if (!rows.length) {
    await sql`INSERT INTO app_state (id, data) VALUES (1, ${JSON.stringify(seed)}::jsonb) ON CONFLICT (id) DO NOTHING`;
    rows = await sql`SELECT data FROM app_state WHERE id = 1`;
  }
  const data = rows[0].data;
  if (ensureIds(data)) await sql`UPDATE app_state SET data = ${JSON.stringify(data)}::jsonb WHERE id = 1`;
  return data;
}
// Lo que ve cada quien: el admin todo; un editor solo los programas que el admin le asignó.
function viewFor(me, data) {
  const { _rev, ...rest } = data;
  if (me.role === 'admin') return rest;
  const allowed = new Set(me.programas);
  return { ...rest, programas: data.programas.filter(p => allowed.has(p.id)).map(p => ({ ...p, visible: true })) };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const sql = db();
    await ensureTable(sql);
    const me = await auth(req, sql);
    if (!me) return res.status(401).json({ error: 'No autorizado' });
    const stored = await loadState(sql);
    const rev = stored._rev || 0;
    if (req.method === 'GET') {
      return res.status(200).json({ data: viewFor(me, stored), rev, me: { user: me.user, nombre: me.nombre, role: me.role } });
    }
    if (req.method === 'PUT') {
      const data = req.body && req.body.data;
      if (!data || !Array.isArray(data.programas)) return res.status(400).json({ error: 'Datos inválidos' });
      const base = req.body.rev;
      if (base !== undefined && base !== null && Number(base) !== rev)
        return res.status(409).json({ error: 'Otra persona guardó cambios mientras tanto' });
      let next;
      if (me.role === 'admin') {
        next = { ...data };
        ensureIds(next);
      } else {
        // Un editor solo puede modificar sus programas asignados: no crea, no elimina, no toca el resto.
        const allowed = new Set(me.programas);
        const incoming = new Map(data.programas.filter(p => p && allowed.has(p.id)).map(p => [p.id, p]));
        next = { ...stored, programas: stored.programas.map(p => incoming.has(p.id) ? { ...incoming.get(p.id), id: p.id, visible: p.visible } : p) };
      }
      next._rev = rev + 1;
      await sql`INSERT INTO app_state (id, data, updated_at) VALUES (1, ${JSON.stringify(next)}::jsonb, now())
        ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`;
      return res.status(200).json({ ok: true, rev: next._rev, ids: me.role === 'admin' ? next.programas.map(p => p.id) : undefined });
    }
    return res.status(405).end();
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
