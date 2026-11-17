# Criterios de aceptación — NGFS v0.1 (BORRADOR)

> **Estado: borrador v0.1.** Estos criterios se han reconstruido a partir de los requisitos funcionales del
> prototipo (expedientes de 8 etapas, RBAC, decisión humana, bitácora encadenada, documentos por hash y adaptador
> UASI opcional). Deben ser revisados y validados por el equipo de NESGESFinance antes de considerarse definitivos.

Leyenda de cobertura: ✅ cubierto por tests automatizados · 🟡 cubierto parcialmente · ⏳ pendiente.

| ID | Tipo | Criterio | Cobertura | Tests |
|---|---|---|---|---|
| AC-01 | Funcional | Un usuario con rol Solicitante puede crear un expediente; nace en estado `borrador` (etapa 1) con código único `NGFS-AAAA-NNNNN`. Ningún otro rol puede crear expedientes. | ✅ | `test_ac01_*` |
| AC-02 | Funcional | Un expediente puede recorrer las 8 etapas por las transiciones definidas (incluidas las vías de rechazo/archivo y de devolución para subsanar), y cada paso queda en el historial. | ✅ | `test_ac02_*` |
| AC-03 | Funcional | Toda transición no definida para el estado actual (saltos, repeticiones, acciones inexistentes, salidas desde `cerrado`) se rechaza con `409` y el estado no cambia. | ✅ | `test_ac03_*` |
| AC-04 | Gobernanza | Las decisiones `aprobar`/`rechazar` exigen confirmación humana explícita (`confirmacion_humana=true`) y justificación (≥10 caracteres); sin ellas se rechazan con `422`. No existe ruta automática que las ejecute. | ✅ | `test_ac04_*`, `test_ocho_etapas_y_decisiones_humanas` |
| AC-05 | Gobernanza | Solo el rol Comité decide; se aplica segregación de funciones (quien presentó el expediente no puede decidirlo). | ✅ | `test_ac05_*` |
| AC-06 | Seguridad | Cada acción se autoriza según la matriz rol × etapa × acción documentada en `docs/rbac.md`; las acciones no permitidas devuelven `403`. La matriz del documento coincide con el código. | ✅ | `test_ac06_*`, `test_docs_sincronizadas_con_codigo` |
| AC-07 | Seguridad | Un Solicitante solo ve y lista sus propios expedientes; los borradores no son visibles para roles revisores (`404`). | ✅ | `test_ac07_*` |
| AC-08 | Seguridad | El Auditor tiene acceso de solo lectura (expedientes, historial, bitácora) y no puede editar, adjuntar, transicionar ni gestionar usuarios. | ✅ | `test_ac08_*` |
| AC-09 | Seguridad | Autenticación por usuario/contraseña: contraseñas almacenadas con bcrypt, política mínima de contraseña, JWT firmado con expiración; tokens inválidos, falsificados o expirados → `401`; cambio de rol o desactivación invalida el token; en producción se exige un secreto JWT fuerte. | ✅ | `test_ac09_*` |
| AC-10 | Seguridad | Tras N intentos fallidos de inicio de sesión (configurable) la cuenta se bloquea temporalmente (`423`) y los intentos quedan auditados. | ✅ | `test_ac10_*` |
| AC-11 | Integridad | Cada acción relevante (login, alta/cambio de usuario, creación/edición de expediente, transición, documento, consulta UASI) genera un evento en la bitácora, encadenado al anterior mediante SHA-256 (`hash_anterior`) y con secuencia continua. | ✅ | `test_ac11_*` |
| AC-12 | Integridad | El endpoint `GET /auditoria/verificar` recalcula la cadena y detecta cualquier alteración, borrado o reordenamiento, indicando la primera secuencia afectada. Solo Auditor, Cumplimiento y Administrador pueden usarlo. | ✅ | `test_ac12_*` |
| AC-13 | Integridad | La bitácora es de solo inserción: la aplicación (ORM) y la base de datos (triggers en SQLite y PostgreSQL) rechazan actualizar o borrar eventos, incluso con SQL directo. | ✅ | `test_ac13_*`, `test_pg_bitacora_inmutable` (opcional, PostgreSQL) |
| AC-14 | Integridad | Los documentos adjuntos se registran por huella SHA-256, tamaño y metadatos; se puede verificar un archivo contra la huella registrada; se respeta el límite de tamaño y los permisos por etapa. | ✅ | `test_ac14_*` |
| AC-15 | Gobernanza IA | El adaptador UASI v5 está desactivado por defecto; cuando se activa solo produce resultados marcados como consultivos, nunca cambia estados, respeta RBAC, no envía datos personales del solicitante y cualquier fallo (red, HTTP, formato) se degrada a `disponible=false` sin afectar a NGFS. | ✅ | `test_ac15_*` |

## Fase 4 — gobernanza avanzada (v0.3.0-dev)

| ID | Tipo | Criterio | Cobertura | Tests |
|---|---|---|---|---|
| AC-16 | Gobernanza | Decisiones colegiadas: analista, cumplimiento, comité o administrador abren una votación sobre una transición de decisión (`aprobar`/`rechazar`), una sola abierta por expediente y con quórum alcanzable (≥2). Votan solo comité y administrador, con confirmación humana y justificación ≥10 caracteres; nunca el solicitante del expediente; doble voto → `409`. Al alcanzar `quorum_requerido` votos `FAVOR` la transición se ejecuta automáticamente y se registran `transicion` y `VOTACION_APROBADA` (votantes + huella SHA-256 de cada voto) en la bitácora; las abstenciones no cuentan; `CONTRA` ≥ quórum → `RECHAZADA`; plazo vencido → `EXPIRADA`; cierre manual solo por administrador y solo si está `ABIERTA`. Con votación abierta no hay transiciones directas (`409`). | ✅ | `test_crear_votacion`, `test_votar_a_favor`, `test_quorum_dispara_transicion`, `test_doble_voto_rechazado`, `test_voto_sin_rol_rechazado`, `test_votos_en_contra_*`, `test_votacion_expira` |
| AC-17 | Integridad | Cada voto lleva `firma_voto = HMAC-SHA256(NGFS_FIRMA_KEY, "votacion_id:votante_id:decision:timestamp")` (clave ≥32 bytes hex o derivada de `NGFS_JWT_SECRETO` con prefijo `firma:`). `GET /votaciones/{id}` muestra `verified` por voto; cualquier alteración del voto en BD → `verified=false`. | ✅ | `test_firma_voto_correcta`, `test_verificacion_firma`, `test_clave_firma_configurable` |
| AC-18 | Seguridad | Con `NGFS_DOC_ENCRYPTION_KEY` los documentos se almacenan cifrados con Fernet (AES-128-CBC + HMAC-SHA256, clave de 256 bits) de forma transparente en `POST /expedientes/{id}/documentos` y `GET /documentos/{id}/contenido`; la huella SHA-256 se calcula sobre el contenido original; contenido alterado → error de descifrado (`500`), clave distinta → `503`. Sin clave, se almacenan en claro con advertencia en el registro (retrocompatibilidad). | ✅ | `test_cifrado_descifrado_simetrico`, `test_hash_sobre_contenido_original`, `test_documento_sin_clave_sin_cifrado`, `test_documento_corrompido_lanza_error` |
| AC-19 | Seguridad | Con `NGFS_JWT_PRIVATE_KEY_PATH`/`NGFS_JWT_PUBLIC_KEY_PATH` los JWT se firman con RS256 (RSA-2048 generado al arrancar si no existe, privada con permisos 0600, cabecera `kid`) y `GET /auth/jwks` publica solo la clave pública; un token HS256 se rechaza. Sin rutas se mantiene HS256 y el JWKS está vacío. | ✅ | `test_endpoint_jwks_retorna_clave_publica`, `test_token_rs256_verificable_con_jwks`, `test_retrocompatibilidad_hs256_sin_claves` |

## Fuera del alcance actual

- Pruebas de carga, firma electrónica cualificada de actas, rotación automática de claves de documentos,
  notificaciones y anclaje externo de la bitácora. Ver [hoja_de_ruta.md](hoja_de_ruta.md).
