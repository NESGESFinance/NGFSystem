"""Middleware transversal: identificador de petición, registro estructurado y limitación de peticiones.

La limitación usa una ventana deslizante de 60 s **en memoria del proceso**. Con varios workers o réplicas,
cada uno lleva su propio contador; para un límite global hay que aplicarlo también en el proxy inverso
(p. ej. Nginx ``limit_req``) o sustituir ``LimitadorVentana`` por uno respaldado en Redis.
"""

from __future__ import annotations

import json
import logging
import math
import re
import sys
import time
import uuid
from collections import defaultdict, deque
from threading import Lock
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from ngfs.config import Configuracion

registro = logging.getLogger("ngfs")
_ID_VALIDO = re.compile(r"^[A-Za-z0-9._\-]{8,64}$")
VENTANA_SEGUNDOS = 60.0


class FormateadorJSON(logging.Formatter):
    """Una línea JSON por evento: fácil de ingerir por sistemas de observabilidad."""

    def format(self, record: logging.LogRecord) -> str:
        datos: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "nivel": record.levelname,
            "logger": record.name,
            "mensaje": record.getMessage(),
        }
        extra = getattr(record, "ngfs", None)
        if isinstance(extra, dict):
            datos.update(extra)
        if record.exc_info:
            datos["excepcion"] = self.formatException(record.exc_info)
        return json.dumps(datos, ensure_ascii=False, default=str)


def configurar_registro(cfg: Configuracion) -> None:
    if any(getattr(h, "_ngfs", False) for h in registro.handlers):
        return
    manejador = logging.StreamHandler(sys.stdout)
    manejador._ngfs = True  # type: ignore[attr-defined]
    manejador.setFormatter(FormateadorJSON() if cfg.log_json else logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    registro.addHandler(manejador)
    registro.setLevel(cfg.log_nivel.upper())
    registro.propagate = False


class LimitadorVentana:
    """Ventana deslizante por clave. Seguro para hilos."""

    def __init__(self) -> None:
        self._marcas: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def consumir(self, clave: str, limite: int, ahora: float | None = None) -> float:
        """Devuelve 0 si se permite; si no, los segundos que faltan para poder reintentar."""
        if limite <= 0:
            return 0.0
        t = time.monotonic() if ahora is None else ahora
        with self._lock:
            marcas = self._marcas[clave]
            while marcas and marcas[0] <= t - VENTANA_SEGUNDOS:
                marcas.popleft()
            if len(marcas) >= limite:
                return max(0.001, marcas[0] + VENTANA_SEGUNDOS - t)
            marcas.append(t)
            if len(self._marcas) > 50_000:  # evita crecimiento ilimitado con muchas IPs distintas
                for k in [k for k, v in self._marcas.items() if not v]:
                    del self._marcas[k]
            return 0.0


def ip_cliente(request: Request, confiar_proxy: bool) -> str:
    if confiar_proxy:
        reenviada = request.headers.get("x-forwarded-for", "")
        if reenviada:
            return reenviada.split(",")[0].strip()
    return request.client.host if request.client else "desconocida"


class MiddlewareNGFS(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, cfg: Configuracion) -> None:
        super().__init__(app)
        self.cfg = cfg
        self.limitador = LimitadorVentana()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        recibido = request.headers.get("x-request-id", "")
        id_peticion = recibido if _ID_VALIDO.match(recibido) else uuid.uuid4().hex
        ip = ip_cliente(request, self.cfg.confiar_x_forwarded_for)
        inicio = time.perf_counter()

        espera = self._limitar(request, ip)
        if espera:
            respuesta: Response = JSONResponse(
                {"detail": "Demasiadas peticiones. Inténtelo de nuevo más tarde."},
                status_code=429, headers={"Retry-After": str(math.ceil(espera))},
            )
        else:
            try:
                respuesta = await call_next(request)
            except Exception:  # noqa: BLE001 - última barrera: registrar y devolver 500 con id de petición
                registro.exception("error_no_controlado", extra={"ngfs": {"id_peticion": id_peticion}})
                respuesta = JSONResponse({"detail": "Error interno.", "id_peticion": id_peticion}, status_code=500)

        respuesta.headers["X-Request-ID"] = id_peticion
        registro.info("peticion", extra={"ngfs": {
            "id_peticion": id_peticion, "metodo": request.method, "ruta": request.url.path,
            "estado": respuesta.status_code, "duracion_ms": round((time.perf_counter() - inicio) * 1000, 2), "ip": ip,
        }})
        return respuesta

    def _limitar(self, request: Request, ip: str) -> float:
        if request.url.path == "/salud":
            return 0.0
        espera = self.limitador.consumir(f"global:{ip}", self.cfg.limite_peticiones_minuto)
        if not espera and request.url.path == "/auth/login":
            espera = self.limitador.consumir(f"login:{ip}", self.cfg.limite_login_minuto)
        return espera
