import { readFileSync } from 'node:fs';
import { isAuthed, db, ensureTable } from './_lib.js';

const seed = JSON.parse(readFileSync(new URL('./_seed.json', import.meta.url), 'utf8'));

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!isAuthed(req)) return res.status(401).json({ error: 'No autorizado' });
  try {
    const sql = db();
    await ensureTable(sql);
    if (req.method === 'GET') {
      let rows = await sql`SELECT data, updated_at FROM app_state WHERE id = 1`;
      if (!rows.length) {
        await sql`INSERT INTO app_state (id, data) VALUES (1, ${JSON.stringify(seed)}::jsonb) ON CONFLICT (id) DO NOTHING`;
        rows = await sql`SELECT data, updated_at FROM app_state WHERE id = 1`;
      }
      return res.status(200).json({ data: rows[0].data, updated_at: rows[0].updated_at });
    }
    if (req.method === 'PUT') {
      const data = req.body && req.body.data;
      if (!data || !Array.isArray(data.programas)) return res.status(400).json({ error: 'Datos inválidos' });
      const rows = await sql`INSERT INTO app_state (id, data, updated_at) VALUES (1, ${JSON.stringify(data)}::jsonb, now())
        ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now() RETURNING updated_at`;
      return res.status(200).json({ ok: true, updated_at: rows[0].updated_at });
    }
    return res.status(405).end();
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
