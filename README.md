# Calendario Desarrollo Docente

Pizarra personal de planificación (no es un sitio oficial). Página estática + funciones de Vercel (`/api`) + Neon Postgres.

Variables de entorno en Vercel: `DATABASE_URL` (Neon), `APP_USER`, `APP_PASSWORD` (administrador), `AUTH_SECRET` (opcional).

Otras personas: una variable por persona, `CLAVE_NOMBRE` = su contraseña (por ejemplo `CLAVE_PATRICIA`). El usuario es el nombre en minúsculas (`patricia`). Las contraseñas solo se administran en Vercel; tras agregar o cambiar una hay que volver a desplegar. Qué programas ve y edita cada persona se marca desde el botón "Personas" (modo edición, solo administrador) y se guarda en la tabla `app_permisos`.
