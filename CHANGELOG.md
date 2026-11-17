# Registro de cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado [SemVer](https://semver.org/lang/es/).

## [Sin publicar]

## [0.3.0-dev] — 2026-11-16 · Fase 4: decisiones colegiadas, firma de votos y cifrado de documentos

### Añadido
- **Decisiones colegiadas con quórum** (AC-16): modelos `VotacionDecision` y `VotoIndividual`; endpoints
  `POST /expedientes/{id}/votaciones`, `GET /expedientes/{id}/votaciones`, `GET /votaciones/{id}`,
  `POST /votaciones/{id}/votar` y `POST /votaciones/{id}/cerrar`. Al alcanzar el quórum de votos `FAVOR` la
  transición se ejecuta automáticamente y se registra `VOTACION_APROBADA` (votantes + huella de cada voto). Nuevas
  acciones RBAC globales `abrir_votacion`, `votar` y `cerrar_votacion`.
- **Firma HMAC-SHA256 de votos** (AC-17): módulo `ngfs.crypto.firmas` (`firmar_voto`, `verificar_voto`), clave
  `NGFS_FIRMA_KEY`; `verified` por voto en la consulta de la votación.
- **Cifrado de documentos en reposo** (AC-18): módulo `ngfs.crypto.documentos` (`cifrar_documento`,
  `descifrar_documento`, `generar_clave_documento`) con Fernet; clave `NGFS_DOC_ENCRYPTION_KEY`; nuevas columnas
  `contenido`, `cifrado` y `clave_doc_id`; nuevo endpoint `GET /documentos/{id}/contenido` (descifra y verifica la huella).
- **JWT RS256 + JWKS** (AC-19): módulo `ngfs.crypto.claves_jwt`; `NGFS_JWT_PRIVATE_KEY_PATH` /
  `NGFS_JWT_PUBLIC_KEY_PATH` (par RSA-2048 generado al arrancar si no existe); endpoint público `GET /auth/jwks`.
- Migraciones Alembic `0002_votaciones_colegiadas` y `0003_cifrado_documentos`.
- 18 tests nuevos (`test_votaciones.py`, `test_cifrado_documentos.py`, `test_jwks.py`): 73 en total con SQLite.

### Cambiado
- Mientras un expediente tenga una votación abierta, las transiciones directas devuelven `409`.
- Desde esta versión el contenido de los documentos nuevos se conserva en la base de datos (cifrado si hay clave;
  en claro con advertencia si no). Los documentos anteriores siguen registrados solo por huella.
- Con RS256 activo, los tokens HS256 emitidos antes dejan de ser válidos (hay que volver a iniciar sesión).
- Nueva dependencia: `cryptography>=42.0`. Versión del paquete: `0.3.0.dev0`.

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
