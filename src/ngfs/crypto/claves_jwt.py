"""Material de firma de los JWT: RS256 (RSA-2048) si hay rutas de claves configuradas, HS256 en caso contrario.

Con ``NGFS_JWT_PRIVATE_KEY_PATH`` y ``NGFS_JWT_PUBLIC_KEY_PATH`` definidas:
  * si ninguno de los dos archivos existe, se genera un par RSA-2048 al arrancar (privada con permisos 0600);
  * si solo existe la privada, se deriva y escribe la pública;
  * si solo existe la pública, se aborta (no se puede firmar y regenerar invalidaría a los verificadores externos).
La clave pública se expone como JSON Web Key Set en ``GET /auth/jwks`` (``kid`` = huella RFC 7638).
Sin rutas, se mantiene HS256 con ``NGFS_JWT_SECRETO`` (retrocompatibilidad v0.1/v0.2) y el JWKS queda vacío.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ngfs.config import Configuracion

ALGORITMO_RSA = "RS256"
BITS_RSA = 2048


class ClavesJWTError(Exception):
    """Configuración de claves RSA incoherente o ilegible."""


@dataclass(frozen=True)
class MaterialJWT:
    algoritmo: str
    clave_firma: Any
    clave_verificacion: Any
    kid: str | None = None
    jwk_publica: dict[str, str] | None = field(default=None)


def _b64url_entero(valor: int) -> str:
    crudo = valor.to_bytes((valor.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(crudo).rstrip(b"=").decode("ascii")


def jwk_desde_publica(publica: rsa.RSAPublicKey) -> dict[str, str]:
    numeros = publica.public_numbers()
    esencial = {"e": _b64url_entero(numeros.e), "kty": "RSA", "n": _b64url_entero(numeros.n)}
    # RFC 7638: huella SHA-256 del JSON canónico de los miembros obligatorios.
    huella = hashlib.sha256(json.dumps(esencial, separators=(",", ":"), sort_keys=True).encode()).digest()
    kid = base64.urlsafe_b64encode(huella).rstrip(b"=").decode("ascii")
    return {**esencial, "kid": kid, "use": "sig", "alg": ALGORITMO_RSA}


def _escribir(ruta: Path, datos: bytes, modo: int) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, modo)
    with os.fdopen(descriptor, "wb") as archivo:
        archivo.write(datos)


def preparar_claves_rsa(ruta_privada: Path, ruta_publica: Path) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Carga el par RSA o lo genera si no existe (ver reglas en el docstring del módulo)."""
    if not ruta_privada.exists():
        if ruta_publica.exists():
            raise ClavesJWTError(f"Existe la clave pública {ruta_publica} pero falta la privada {ruta_privada}.")
        privada_nueva = rsa.generate_private_key(public_exponent=65537, key_size=BITS_RSA)
        _escribir(ruta_privada, privada_nueva.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                            serialization.NoEncryption()), 0o600)
    try:
        privada = serialization.load_pem_private_key(ruta_privada.read_bytes(), password=None)
    except (ValueError, TypeError) as exc:
        raise ClavesJWTError(f"No se pudo leer la clave privada RSA {ruta_privada}.") from exc
    if not isinstance(privada, rsa.RSAPrivateKey):
        raise ClavesJWTError(f"{ruta_privada} no contiene una clave privada RSA.")
    if not ruta_publica.exists():
        _escribir(ruta_publica, privada.public_key().public_bytes(serialization.Encoding.PEM,
                                                                   serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)
    publica = serialization.load_pem_public_key(ruta_publica.read_bytes())
    if not isinstance(publica, rsa.RSAPublicKey) or publica.public_numbers() != privada.public_key().public_numbers():
        raise ClavesJWTError(f"La clave pública {ruta_publica} no corresponde a la privada {ruta_privada}.")
    return privada, publica


@lru_cache(maxsize=8)
def _material_rsa(ruta_privada: str, ruta_publica: str) -> MaterialJWT:
    privada, publica = preparar_claves_rsa(Path(ruta_privada), Path(ruta_publica))
    jwk = jwk_desde_publica(publica)
    return MaterialJWT(ALGORITMO_RSA, privada, publica, jwk["kid"], jwk)


def material_jwt(cfg: Configuracion) -> MaterialJWT:
    if cfg.jwt_private_key_path and cfg.jwt_public_key_path:
        return _material_rsa(cfg.jwt_private_key_path, cfg.jwt_public_key_path)
    return MaterialJWT(cfg.jwt_algoritmo, cfg.jwt_secreto, cfg.jwt_secreto)


def jwks(cfg: Configuracion) -> dict[str, list[dict[str, str]]]:
    """JSON Web Key Set público. Con HS256 está vacío: un secreto simétrico nunca se publica."""
    material = material_jwt(cfg)
    return {"keys": [material.jwk_publica] if material.jwk_publica else []}
