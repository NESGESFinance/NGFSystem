"""Configuración de NGFS leída desde variables de entorno (prefijo ``NGFS_``)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SECRETO_DESARROLLO = "solo-desarrollo-cambiar-este-secreto-ngfs"  # noqa: S105 - valor de desarrollo, rechazado en producción


class Configuracion(BaseSettings):
    """Parámetros de ejecución. Ver ``.env.example`` para la lista completa."""

    model_config = SettingsConfigDict(env_prefix="NGFS_", env_file=".env", extra="ignore", populate_by_name=True)

    entorno: str = Field(default="desarrollo", description="desarrollo | pruebas | produccion")
    database_url: str = Field(default="sqlite:///./ngfs.db", validation_alias="DATABASE_URL")

    jwt_secreto: str = SECRETO_DESARROLLO
    jwt_algoritmo: str = "HS256"
    jwt_minutos_expiracion: int = Field(default=30, ge=1, le=1440)
    jwt_horas_sesion_maxima: int = Field(default=12, ge=1, le=168, description="Límite absoluto aunque se renueve el token")
    # RS256 (Fase 4): si se definen AMBAS rutas, los tokens se firman con RSA-2048 y la clave pública se publica en
    # GET /auth/jwks. Si los archivos no existen se generan al arrancar. Sin rutas → HS256 con jwt_secreto.
    jwt_private_key_path: str = ""
    jwt_public_key_path: str = ""

    # Firma HMAC-SHA256 de votos (Fase 4): hex de al menos 32 bytes. Vacía → se deriva de jwt_secreto ("firma:").
    firma_key: str = ""
    # Cifrado de documentos en reposo (Fase 4): clave Fernet en base64 urlsafe (44 caracteres).
    # Vacía → los documentos se almacenan sin cifrar (con advertencia en el registro).
    doc_encryption_key: str = ""

    # Base de datos: en desarrollo/pruebas las tablas se crean al arrancar; en producción use `ngfs migrar` (Alembic).
    crear_tablas_al_iniciar: bool = True

    # Limitación de peticiones por IP (ventana deslizante de 60 s, en memoria del proceso). 0 = desactivado.
    limite_peticiones_minuto: int = Field(default=120, ge=0)
    limite_login_minuto: int = Field(default=10, ge=0)
    confiar_x_forwarded_for: bool = Field(default=False, description="Activar solo detrás de un proxy inverso de confianza")

    # Registro estructurado (JSON por línea)
    log_nivel: str = "INFO"
    log_json: bool = True

    max_intentos_login: int = Field(default=5, ge=1)
    minutos_bloqueo: int = Field(default=15, ge=1)
    longitud_minima_password: int = Field(default=12, ge=8)
    max_tamano_documento_mb: int = Field(default=25, ge=1)

    # Adaptador UASI v5 (opcional, aislado, consultivo). Desactivado por defecto.
    uasi_habilitado: bool = False
    uasi_url: str = "http://localhost:8000"
    uasi_ruta_analisis: str = "/api/v5/ngfs/analisis-consultivo"
    uasi_token: str = ""
    uasi_timeout_segundos: float = Field(default=5.0, gt=0, le=60)

    @model_validator(mode="after")
    def _validar_produccion(self) -> Configuracion:
        if self.entorno == "produccion" and (self.jwt_secreto == SECRETO_DESARROLLO or len(self.jwt_secreto) < 32):
            raise ValueError("En producción NGFS_JWT_SECRETO debe definirse con al menos 32 caracteres aleatorios.")
        if bool(self.jwt_private_key_path) != bool(self.jwt_public_key_path):
            raise ValueError("Defina a la vez NGFS_JWT_PRIVATE_KEY_PATH y NGFS_JWT_PUBLIC_KEY_PATH (o ninguna).")
        if self.firma_key:
            try:
                clave = bytes.fromhex(self.firma_key)
            except ValueError as exc:
                raise ValueError("NGFS_FIRMA_KEY debe estar en hexadecimal.") from exc
            if len(clave) < 32:
                raise ValueError("NGFS_FIRMA_KEY debe tener al menos 32 bytes (64 caracteres hexadecimales).")
        if self.doc_encryption_key:
            from cryptography.fernet import Fernet

            try:
                Fernet(self.doc_encryption_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError) as exc:
                raise ValueError("NGFS_DOC_ENCRYPTION_KEY no es una clave Fernet válida (base64 urlsafe, 32 bytes).") from exc
        return self


@lru_cache
def obtener_configuracion() -> Configuracion:
    return Configuracion()
