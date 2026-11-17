"""Fase 4 — cifrado de documentos en reposo con Fernet (AC-18)."""

from __future__ import annotations

import hashlib
import logging

import pytest
from sqlalchemy import select, update

from conftest import Entorno, cfg_pruebas
from ngfs.crypto.documentos import (
    DocumentoCifradoError,
    cifrar_documento,
    descifrar_documento,
    generar_clave_documento,
    identificador_clave,
)
from ngfs.estados import Rol
from ngfs.modelos import Documento

CONTENIDO = b"%PDF-1.7 estudio de factibilidad " * 50


def _entorno(**extra: object) -> Entorno:
    e = Entorno(cfg_pruebas(**extra))
    e.usuario("sol", Rol.SOLICITANTE)
    e.usuario("aud", Rol.AUDITOR)
    return e


def _subir(e: Entorno, contenido: bytes = CONTENIDO) -> dict[str, object]:
    exp_id = e.crear_expediente()["id"]
    r = e.cliente.post(f"/expedientes/{exp_id}/documentos", files={"archivo": ("estudio.pdf", contenido, "application/pdf")},
                       headers=e.h("sol"))
    assert r.status_code == 201, r.text
    datos: dict[str, object] = r.json()
    return datos


def test_cifrado_descifrado_simetrico() -> None:
    clave = generar_clave_documento()
    assert len(clave) == 44
    cifrado = cifrar_documento(CONTENIDO, clave)
    assert cifrado != CONTENIDO and CONTENIDO not in cifrado
    assert descifrar_documento(cifrado, clave) == CONTENIDO
    with pytest.raises(DocumentoCifradoError):
        descifrar_documento(cifrado, generar_clave_documento())
    with pytest.raises(DocumentoCifradoError):
        cifrar_documento(CONTENIDO, "clave-invalida")
    with pytest.raises(ValueError, match="Fernet"):
        cfg_pruebas(doc_encryption_key="no-es-una-clave-fernet")


def test_hash_sobre_contenido_original() -> None:
    clave = generar_clave_documento()
    e = _entorno(doc_encryption_key=clave)
    doc = _subir(e)
    assert doc["sha256"] == hashlib.sha256(CONTENIDO).hexdigest() and doc["cifrado"] is True
    with e.sesion() as s:
        fila = s.get(Documento, doc["id"])
        assert fila is not None and fila.contenido is not None
        assert fila.contenido != CONTENIDO and fila.clave_doc_id == identificador_clave(clave)
        assert descifrar_documento(fila.contenido, clave) == CONTENIDO
    # Descarga transparente: devuelve el original y la huella
    r = e.cliente.get(f"/documentos/{doc['id']}/contenido", headers=e.h("aud"))
    assert r.status_code == 200 and r.content == CONTENIDO
    assert r.headers["x-ngfs-sha256"] == doc["sha256"]
    # La verificación por huella sigue funcionando con el archivo original
    ok = e.cliente.post(f"/documentos/{doc['id']}/verificar", files={"archivo": ("x", CONTENIDO)}, headers=e.h("sol")).json()
    assert ok["coincide"] is True


def test_documento_sin_clave_sin_cifrado(caplog: pytest.LogCaptureFixture) -> None:
    e = _entorno()
    with caplog.at_level(logging.WARNING, logger="ngfs.documentos"):
        doc = _subir(e)
    assert doc["cifrado"] is False
    assert any("SIN cifrar" in r.getMessage() for r in caplog.records)
    with e.sesion() as s:
        fila = s.get(Documento, doc["id"])
        assert fila is not None and fila.contenido == CONTENIDO and fila.clave_doc_id is None
    r = e.cliente.get(f"/documentos/{doc['id']}/contenido", headers=e.h("sol"))
    assert r.status_code == 200 and r.content == CONTENIDO
    # Documento heredado de v0.1/v0.2 (solo huella) → 404 explicativo
    with e.sesion() as s:
        s.execute(update(Documento).where(Documento.id == doc["id"]).values(contenido=None))
        s.commit()
    r = e.cliente.get(f"/documentos/{doc['id']}/contenido", headers=e.h("sol"))
    assert r.status_code == 404 and "huella" in r.json()["detail"]


def test_documento_corrompido_lanza_error() -> None:
    clave = generar_clave_documento()
    e = _entorno(doc_encryption_key=clave)
    doc = _subir(e)
    with e.sesion() as s:
        fila = s.execute(select(Documento).where(Documento.id == doc["id"])).scalar_one()
        assert fila.contenido is not None
        alterado = bytearray(fila.contenido)
        alterado[len(alterado) // 2] ^= 0x01
        s.execute(update(Documento).where(Documento.id == doc["id"]).values(contenido=bytes(alterado)))
        s.commit()
        with pytest.raises(DocumentoCifradoError):
            descifrar_documento(bytes(alterado), clave)
    r = e.cliente.get(f"/documentos/{doc['id']}/contenido", headers=e.h("sol"))
    assert r.status_code == 500 and "descifrar" in r.json()["detail"]
    # Otra clave configurada (rotación pendiente) → 503 sin intentar descifrar
    otra = Entorno(cfg_pruebas(doc_encryption_key=generar_clave_documento()))
    otra.app.state.db = e.app.state.db
    r = otra.cliente.get(f"/documentos/{doc['id']}/contenido", headers=e.h("sol"))
    assert r.status_code == 503
