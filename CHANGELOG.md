# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

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
