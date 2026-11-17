"""Fábrica de la aplicación FastAPI de NGFS."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm.exc import StaleDataError

from ngfs import __version__
from ngfs.api import rutas_auth, rutas_expedientes, rutas_sistema
from ngfs.config import Configuracion, obtener_configuracion
from ngfs.db import BaseDeDatos
from ngfs.middleware import MiddlewareNGFS, configurar_registro
from ngfs.uasi_adaptador import AdaptadorUASI

DESCRIPCION = (
    "NGFSystem (NGFS) — capa de gestión, trazabilidad y auditoría del ecosistema NESGESFinance. "
    "Prototipo v0.2: expedientes con máquina de estados de 8 etapas, RBAC, decisiones con supervisión "
    "humana obligatoria, bitácora encadenada SHA-256 y adaptador UASI v5 opcional y consultivo."
)


async def _conflicto_concurrencia(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        {"detail": "El registro fue modificado simultáneamente por otra petición. Vuelva a consultarlo y reintente."},
        status_code=409,
    )


def crear_app(cfg: Configuracion | None = None, uasi: AdaptadorUASI | None = None) -> FastAPI:
    cfg = cfg or obtener_configuracion()
    configurar_registro(cfg)
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
    return app
