"""Cifrado simétrico de documentos en reposo con Fernet (``cryptography``).

Fernet usa una clave de 256 bits dividida en dos mitades: AES-128 en modo CBC para el cifrado y HMAC-SHA256 para la
autenticación del mensaje cifrado (cifrado autenticado). Cualquier alteración del texto cifrado o una clave
incorrecta se detecta al descifrar y produce :class:`DocumentoCifradoError`.

La huella SHA-256 del documento se calcula SIEMPRE sobre el contenido original (en claro), de modo que la
verificación de integridad (``POST /documentos/{id}/verificar``) es independiente del cifrado.
"""

from __future__ import annotations

import hashlib

from cryptography.fernet import Fernet, InvalidToken

from ngfs.config import obtener_configuracion


class DocumentoCifradoError(Exception):
    """El documento no se pudo cifrar/descifrar (clave ausente o incorrecta, o contenido alterado)."""


def generar_clave_documento() -> str:
    """Genera una clave Fernet nueva (base64 urlsafe, 44 caracteres) para ``NGFS_DOC_ENCRYPTION_KEY``."""
    return Fernet.generate_key().decode("ascii")


def identificador_clave(clave: str) -> str:
    """Huella corta (no reversible) de la clave, guardada en ``clave_doc_id`` para la futura rotación de claves."""
    return hashlib.sha256(clave.encode("ascii")).hexdigest()[:16]


def _fernet(clave: str | None) -> Fernet:
    clave = clave if clave is not None else obtener_configuracion().doc_encryption_key
    if not clave:
        raise DocumentoCifradoError("No hay clave de cifrado de documentos configurada (NGFS_DOC_ENCRYPTION_KEY).")
    try:
        return Fernet(clave.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise DocumentoCifradoError("La clave de cifrado de documentos no es una clave Fernet válida.") from exc


def cifrar_documento(contenido: bytes, clave: str | None = None) -> bytes:
    return _fernet(clave).encrypt(contenido)


def descifrar_documento(cifrado: bytes, clave: str | None = None) -> bytes:
    try:
        return _fernet(clave).decrypt(cifrado)
    except InvalidToken as exc:
        raise DocumentoCifradoError("No se pudo descifrar el documento: clave incorrecta o contenido alterado.") from exc
