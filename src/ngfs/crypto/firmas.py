"""Firma HMAC-SHA256 de votos individuales en decisiones colegiadas.

El mensaje firmado es ``f"{votacion_id}:{votante_id}:{decision}:{timestamp_voto}"`` donde ``timestamp_voto`` es la
marca de tiempo del voto normalizada a UTC en ISO 8601 con microsegundos (independiente del motor de base de datos).
La clave sale de ``NGFS_FIRMA_KEY`` (hex, ≥32 bytes) o, si no está definida, se deriva de ``NGFS_JWT_SECRETO`` con el
prefijo ``"firma:"``. La firma permite detectar cualquier alteración posterior del voto en la base de datos.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime

from ngfs.config import Configuracion, obtener_configuracion

PREFIJO_DERIVACION = "firma:"


@dataclass(frozen=True)
class DatosVoto:
    """Campos del voto cubiertos por la firma."""

    votacion_id: int
    votante_id: int
    decision: str
    timestamp_voto: datetime


def normalizar_marca(marca: datetime) -> str:
    """ISO 8601 en UTC con microsegundos. SQLite devuelve fechas sin zona: se interpretan como UTC."""
    utc = marca.replace(tzinfo=UTC) if marca.tzinfo is None else marca.astimezone(UTC)
    return utc.isoformat(timespec="microseconds")


def mensaje_voto(datos: DatosVoto) -> bytes:
    return f"{datos.votacion_id}:{datos.votante_id}:{datos.decision}:{normalizar_marca(datos.timestamp_voto)}".encode()


def clave_firmas(cfg: Configuracion) -> bytes:
    """Clave HMAC efectiva: ``NGFS_FIRMA_KEY`` o derivación SHA-256 de ``"firma:" + jwt_secreto``."""
    if cfg.firma_key:
        return bytes.fromhex(cfg.firma_key)
    return hashlib.sha256((PREFIJO_DERIVACION + cfg.jwt_secreto).encode("utf-8")).digest()


def firmar_voto(datos: DatosVoto, clave: bytes | None = None) -> str:
    """Devuelve ``HMAC-SHA256(clave, mensaje).hexdigest()``. Sin clave explícita usa la configuración global."""
    clave = clave if clave is not None else clave_firmas(obtener_configuracion())
    return hmac.new(clave, mensaje_voto(datos), hashlib.sha256).hexdigest()


def verificar_voto(datos: DatosVoto, firma: str | None, clave: bytes | None = None) -> bool:
    """Comparación en tiempo constante. Un voto sin firma nunca se considera verificado."""
    if not firma:
        return False
    return hmac.compare_digest(firmar_voto(datos, clave), firma)
