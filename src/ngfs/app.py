"""Fábrica de la aplicación FastAPI de NGFS."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm.exc import StaleDataError

from ngfs import __version__
from ngfs.api import rutas_auth, rutas_expedientes, rutas_sistema, rutas_votaciones
from ngfs.config import Configuracion, obtener_configuracion
from ngfs.crypto.claves_jwt import material_jwt
from ngfs.db import BaseDeDatos
from ngfs.middleware import MiddlewareNGFS, configurar_registro
from ngfs.uasi_adaptador import AdaptadorUASI

DESCRIPCION = (
    "NGFSystem (NGFS) — capa de gestión, trazabilidad y auditoría del ecosistema NESGESFinance. "
    "Prototipo v0.3-dev: expedientes con máquina de estados de 8 etapas, RBAC, decisiones con supervisión "
    "humana obligatoria (individuales o colegiadas por quórum con votos firmados), bitácora encadenada SHA-256, "
    "documentos cifrados en reposo, JWT HS256/RS256 y adaptador UASI v5 opcional y consultivo."
)


async def _conflicto_concurrencia(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        {"detail": "El registro fue modificado simultáneamente por otra petición. Vuelva a consultarlo y reintente."},
        status_code=409,
    )


def crear_app(cfg: Configuracion | None = None, uasi: AdaptadorUASI | None = None) -> FastAPI:
    cfg = cfg or obtener_configuracion()
    configurar_registro(cfg)
    log = logging.getLogger("ngfs.app")
    material = material_jwt(cfg)  # genera el par RSA en disco si se configuraron rutas y aún no existe
    log.info("Firma de tokens JWT: %s", material.algoritmo)
    if not cfg.doc_encryption_key:
        log.warning("NGFS_DOC_ENCRYPTION_KEY no configurada: los documentos se almacenarán SIN cifrar.")
    if not cfg.firma_key:
        log.warning("NGFS_FIRMA_KEY no configurada: la clave de firma de votos se deriva de NGFS_JWT_SECRETO.")
    app = FastAPI(title="NGFSystem (NGFS)", version=__version__, description=DESCRIPCION)
    app.state.cfg = cfg
    app.state.db = BaseDeDatos(cfg.database_url)
    if cfg.crear_tablas_al_iniciar:
        app.state.db.crear_tablas()
    app.state.uasi = uasi or AdaptadorUASI(cfg)
    app.add_exception_handler(StaleDataError, _conflicto_concurrencia)
    app.add_middleware(MiddlewareNGFS, cfg=cfg)
    app.include_router(rutas_sistema.router)
    app.include_router(rutas_auth.router)
    app.include_router(rutas_expedientes.router)
    app.include_router(rutas_votaciones.router)
    return app
