# Calendario Desarrollo Docente

Pizarra personal de planificación (no es un sitio oficial). Página estática + funciones de Vercel (`/api`) + Neon Postgres.

Variables de entorno en Vercel: `DATABASE_URL` (Neon), `APP_USER`, `APP_PASSWORD` (administrador), `AUTH_SECRET` (opcional). Las demás personas y los programas que cada una ve y edita se administran desde el botón "Personas" (modo edición, solo administrador) y se guardan en la tabla `app_users`.
