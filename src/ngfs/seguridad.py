"""Contraseñas (bcrypt) y tokens de acceso (JWT HS256 o RS256)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import bcrypt
import jwt

from ngfs.config import Configuracion
from ngfs.crypto.claves_jwt import material_jwt


class PasswordDebil(ValueError):
    pass


def validar_password(password: str, longitud_minima: int) -> None:
    if len(password) < longitud_minima:
        raise PasswordDebil(f"La contraseña debe tener al menos {longitud_minima} caracteres.")
    if len(password.encode("utf-8")) > 72:
        raise PasswordDebil("La contraseña no puede superar 72 bytes (límite de bcrypt).")
    if password.isalpha() or password.isdigit():
        raise PasswordDebil("La contraseña debe combinar letras y números o símbolos.")


def hashear_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verificar_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except ValueError:
        return False


@dataclass(frozen=True)
class TokenEmitido:
    token: str
    jti: str
    expira_en: datetime
    sesion_hasta: datetime


def emitir_token(
    cfg: Configuracion, *, usuario_id: int, usuario: str, rol: str, inicio_sesion: datetime | None = None
) -> TokenEmitido:
    """Emite un token de acceso con identificador único (``jti``) para poder revocarlo.

    ``ses`` guarda el inicio de la sesión original: las renovaciones lo conservan, de modo que una sesión
    nunca dura más de ``jwt_horas_sesion_maxima`` aunque se renueve indefinidamente.
    """
    ahora = datetime.now(UTC)
    inicio = inicio_sesion or ahora
    sesion_hasta = inicio + timedelta(hours=cfg.jwt_horas_sesion_maxima)
    expira = min(ahora + timedelta(minutes=cfg.jwt_minutos_expiracion), sesion_hasta)
    jti = uuid4().hex
    carga: dict[str, Any] = {
        "sub": str(usuario_id),
        "usr": usuario,
        "rol": rol,
        "tipo": "humano",  # NGFS solo emite tokens a personas; no existen tokens de servicio con permisos de decisión
        "jti": jti,
        "ses": int(inicio.timestamp()),
        "iat": ahora,
        "exp": expira,
    }
    material = material_jwt(cfg)  # RS256 si hay claves RSA configuradas; HS256 en caso contrario
    cabeceras = {"kid": material.kid} if material.kid else None
    token = jwt.encode(carga, material.clave_firma, algorithm=material.algoritmo, headers=cabeceras)
    return TokenEmitido(token=token, jti=jti, expira_en=expira, sesion_hasta=sesion_hasta)


def decodificar_token(cfg: Configuracion, token: str) -> dict[str, Any]:
    """Lanza ``jwt.PyJWTError`` si el token es inválido o expiró. Solo se acepta el algoritmo configurado."""
    material = material_jwt(cfg)
    return jwt.decode(
        token, material.clave_verificacion, algorithms=[material.algoritmo], options={"require": ["exp", "sub", "jti", "ses"]}
    )
