# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

## [0.2.0] — 2026-11-16 · Fase 3: endurecimiento técnico

### Añadido
- **Migraciones Alembic** incluidas en el paquete (`ngfs/migraciones`, revisión `0001` = esquema completo v0.2) y
  comando `ngfs migrar` (`--sql` para ver el SQL, `--estampar` para BD creadas con `create_all`). Nueva opción
  `NGFS_CREAR_TABLAS_AL_INICIAR` (ponerla en `false` en producción). Test que falla si modelos y migraciones divergen.
- **Bitácora inmutable a nivel de base de datos**: triggers que rechazan `UPDATE`/`DELETE` en SQLite y
  `UPDATE`/`DELETE`/`TRUNCATE` en PostgreSQL, incluso con SQL directo. En PostgreSQL, bloqueo consultivo
  (`pg_advisory_xact_lock`) para serializar la secuencia de eventos con escrituras concurrentes.
- **Concurrencia optimista** en expedientes: campo `version` (gestionado por SQLAlchemy) y `version_esperada`
  opcional en `PATCH /expedientes/{id}` y en transiciones; conflicto → `409`.
- **Revocación y rotación de tokens**: cada JWT lleva `jti` y `ses`; `POST /auth/logout` revoca el token actual y
  `POST /auth/renovar` lo rota sin superar `NGFS_JWT_HORAS_SESION_MAXIMA` (12 h por defecto). Ambos quedan auditados.
- **Limitación de peticiones** por IP (global y específica para `/auth/login`) con `429` y `Retry-After`.
- **Registro estructurado JSON** por petición y cabecera **`X-Request-ID`** (se respeta la recibida si es válida).
- Pruebas opcionales contra PostgreSQL real (`NGFS_TEST_PG_URL`).

### Cambiado
- Expiración por defecto del token: 60 → 30 minutos (renovable).
- Los tokens emitidos por v0.1 (sin `jti`/`ses`) dejan de ser válidos: hay que volver a iniciar sesión.
- La imagen Docker ejecuta `ngfs migrar` antes de arrancar.
- Nueva dependencia: `alembic`.

### Corregido
- Restaurada la estructura del repositorio (`src/ngfs/`, `src/ngfs/api/`, `tests/`, `docs/`); la subida web la había
  aplanado y el paquete `ngfs` no podía importarse.
- README sustituido por el de NGFSystem (el anterior describía otro proyecto).
- Añadidos los archivos que faltaban: `pyproject.toml`, `LICENSE`, `NOTICE`, `.gitignore`, `.env.example`,
  `Dockerfile`, `docker-compose.yml`, `docs/ci.yml.example` y `src/ngfs/__init__.py`.
- Eliminado el ZIP duplicado del repositorio.

### Cambiado
- Nombre oficial unificado: **NGFSystem** (paquete de distribución `ngfsystem`; el módulo Python sigue siendo `ngfs`).

## [0.1.0] — 2026-11-16

### Añadido
- Prototipo funcional NGFS v0.1.
- Expedientes con máquina de estados de 8 etapas y transiciones explícitas (`ngfs.estados`).
- Decisiones (aprobar/rechazar) con supervisión humana obligatoria: rol Comité, `confirmacion_humana`, justificación
  y segregación de funciones.
- RBAC con matriz rol × etapa × acción (6 roles) y acciones globales (`ngfs.rbac`, `docs/rbac.md`).
- Autenticación usuario/contraseña con bcrypt y JWT; bloqueo temporal por intentos fallidos; invalidación de tokens
  al cambiar rol o desactivar usuario; script `crear-admin`.
- Bitácora de auditoría encadenada por SHA-256 con verificación de integridad (`GET /auditoria/verificar`).
- Registro y verificación de documentos por huella SHA-256.
- Adaptador UASI v5 opcional, aislado y consultivo (desactivado por defecto).
- Documentación: arquitectura, máquina de estados (Mermaid), RBAC, criterios AC-01…AC-15 (borrador), hoja de ruta de 7 fases.
- Dockerfile, docker-compose con PostgreSQL, workflow de CI de ejemplo, 39 tests.
