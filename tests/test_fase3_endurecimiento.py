"""Fase 3 — endurecimiento: migraciones, concurrencia optimista, revocación de tokens, límites y trazas."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import jwt
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError

from conftest import PASSWORD, Entorno, cfg_pruebas
from ngfs import cli, modelos  # noqa: F401 - registra los modelos
from ngfs.db import Base
from ngfs.estados import Rol
from ngfs.middleware import FormateadorJSON, LimitadorVentana


# --------------------------------------------------------------------------- migraciones
def _url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path / 'migrada.db'}"


def test_migracion_inicial_coincide_con_modelos(tmp_path: Path) -> None:
    """Si alguien cambia un modelo sin crear la migración correspondiente, esta prueba falla."""
    assert cli.migrar(url=_url(tmp_path)) == 0
    motor = create_engine(_url(tmp_path))
    with motor.connect() as conexion:
        diferencias = compare_metadata(MigrationContext.configure(conexion), Base.metadata)
        assert diferencias == [], f"Modelos y migraciones divergen: {diferencias}"
        triggers = {f for (f,) in conexion.execute(text("SELECT name FROM sqlite_master WHERE type = 'trigger'"))}
        assert {"ngfs_auditoria_no_update", "ngfs_auditoria_no_delete"} <= triggers
    motor.dispose()


def test_migracion_downgrade_y_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("DATABASE_URL", _url(tmp_path))
    from ngfs.config import obtener_configuracion

    obtener_configuracion.cache_clear()
    try:
        assert cli.main(["migrar", "--sql"]) == 0
        assert "CREATE TABLE expedientes" in capsys.readouterr().out
        assert cli.main(["migrar"]) == 0
        motor = create_engine(_url(tmp_path))
        assert "tokens_revocados" in inspect(motor).get_table_names()
        command.downgrade(cli.config_alembic(_url(tmp_path)), "base")
        assert set(inspect(motor).get_table_names()) <= {"alembic_version"}
        motor.dispose()
    finally:
        obtener_configuracion.cache_clear()


def test_app_sobre_bd_migrada_sin_create_all(tmp_path: Path) -> None:
    cli.migrar(url=_url(tmp_path))
    env = Entorno(cfg_pruebas(database_url=_url(tmp_path), crear_tablas_al_iniciar=False))
    env.usuario("sol", Rol.SOLICITANTE)
    exp = env.crear_expediente()
    assert exp["version"] == 1
    with env.sesion() as s, pytest.raises(DBAPIError, match="inmutable"):
        s.execute(text("DELETE FROM eventos_auditoria"))
    env.app.state.db.motor.dispose()


# --------------------------------------------------------------------------- concurrencia optimista
def test_version_incrementa_y_conflicto_409(env: Entorno) -> None:
    exp = env.crear_expediente()
    url = f"/expedientes/{exp['id']}"
    r = env.cliente.patch(url, json={"titulo": "Nuevo título", "version_esperada": 1}, headers=env.h("sol"))
    assert r.status_code == 200 and r.json()["version"] == 2
    # Un segundo cliente que leyó la versión 1 no puede pisar el cambio
    r = env.cliente.patch(url, json={"titulo": "Otro", "version_esperada": 1}, headers=env.h("sol"))
    assert r.status_code == 409 and "versión actual 2" in r.json()["detail"]
    r = env.cliente.post(f"{url}/transiciones", json={"accion": "enviar", "version_esperada": 1}, headers=env.h("sol"))
    assert r.status_code == 409
    r = env.cliente.post(f"{url}/transiciones", json={"accion": "enviar", "version_esperada": 2}, headers=env.h("sol"))
    assert r.status_code == 200 and r.json()["version"] == 3
    # Sin version_esperada el comportamiento es el de v0.1 (compatibilidad)
    assert env.transicion(exp["id"], "ana", "iniciar_revision").json()["version"] == 4


def test_actualizacion_concurrente_real_detectada_por_orm(env: Entorno) -> None:
    """Dos sesiones cargan la misma versión; la segunda en confirmar recibe StaleDataError."""
    from sqlalchemy.orm.exc import StaleDataError

    exp_id = env.crear_expediente()["id"]
    with env.sesion() as s1, env.sesion() as s2:
        a, b = s1.get(modelos.Expediente, exp_id), s2.get(modelos.Expediente, exp_id)
        assert a is not None and b is not None
        a.titulo = "Cambio A"
        s1.commit()
        b.titulo = "Cambio B"
        with pytest.raises(StaleDataError):
            s2.commit()


# --------------------------------------------------------------------------- tokens
def test_logout_revoca_token(env: Entorno) -> None:
    h = env.h("sol")
    assert env.cliente.post("/auth/logout", headers=h).status_code == 204
    r = env.cliente.get("/auth/yo", headers=h)
    assert r.status_code == 401 and "revocado" in r.json()["detail"]
    assert env.login("sol").status_code == 200  # puede iniciar sesión de nuevo
    with env.sesion() as s:
        acciones = [a for (a,) in s.execute(text("SELECT accion FROM eventos_auditoria"))]
    assert "logout" in acciones


def test_renovar_rota_token_y_respeta_sesion_maxima(env: Entorno) -> None:
    h = env.h("sol")
    r = env.cliente.post("/auth/renovar", headers=h)
    assert r.status_code == 200 and r.json()["renovable_hasta"]
    nuevo = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert env.cliente.get("/auth/yo", headers=h).status_code == 401  # el anterior queda revocado
    assert env.cliente.get("/auth/yo", headers=nuevo).status_code == 200
    viejo = jwt.decode(h["Authorization"][7:], options={"verify_signature": False})
    rotado = jwt.decode(nuevo["Authorization"][7:], options={"verify_signature": False})
    assert rotado["ses"] == viejo["ses"] and rotado["jti"] != viejo["jti"]

    # Token cuya sesión empezó hace más de jwt_horas_sesion_maxima (12 h): no se puede renovar
    cfg = env.app.state.cfg
    carga: dict[str, Any] = {**rotado, "jti": "b" * 32, "ses": rotado["ses"] - 13 * 3600}
    antiguo = jwt.encode(carga, cfg.jwt_secreto, algorithm=cfg.jwt_algoritmo)
    r = env.cliente.post("/auth/renovar", headers={"Authorization": f"Bearer {antiguo}"})
    assert r.status_code == 401 and "duración máxima" in r.json()["detail"]


def test_token_sin_jti_rechazado(env: Entorno) -> None:
    cfg = env.app.state.cfg
    token = jwt.encode({"sub": "1", "rol": "solicitante", "exp": 9999999999}, cfg.jwt_secreto, algorithm="HS256")
    assert env.cliente.get("/auth/yo", headers={"Authorization": f"Bearer {token}"}).status_code == 401


# --------------------------------------------------------------------------- límites, trazas y registro
def test_rate_limit_login() -> None:
    env = Entorno(cfg_pruebas(limite_login_minuto=3))
    for _ in range(3):
        assert env.login("nadie").status_code == 401
    r = env.login("nadie")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    assert env.cliente.get("/salud").status_code == 200  # /salud nunca se limita


def test_rate_limit_global() -> None:
    env = Entorno(cfg_pruebas(limite_peticiones_minuto=5))
    codigos = [env.cliente.get("/meta/estados").status_code for _ in range(7)]
    assert codigos.count(429) == 2


def test_limitador_ventana_deslizante() -> None:
    lim = LimitadorVentana()
    assert lim.consumir("ip", 2, ahora=0) == 0 and lim.consumir("ip", 2, ahora=1) == 0
    assert lim.consumir("ip", 2, ahora=30) == pytest.approx(30)
    assert lim.consumir("ip", 2, ahora=60.5) == 0  # la primera marca ya salió de la ventana
    assert lim.consumir("otra", 0) == 0  # 0 = desactivado


def test_x_request_id(env: Entorno) -> None:
    r = env.cliente.get("/salud", headers={"X-Request-ID": "peticion-externa-123"})
    assert r.headers["X-Request-ID"] == "peticion-externa-123"
    generado = env.cliente.get("/salud", headers={"X-Request-ID": "invalido con espacios"}).headers["X-Request-ID"]
    assert len(generado) == 32 and generado != "invalido con espacios"


def test_formato_log_json() -> None:
    registro = logging.LogRecord("ngfs", logging.INFO, __file__, 1, "peticion", None, None)
    registro.ngfs = {"id_peticion": "abc", "estado": 200}
    datos = json.loads(FormateadorJSON().format(registro))
    assert datos["mensaje"] == "peticion" and datos["id_peticion"] == "abc" and datos["nivel"] == "INFO"


def test_password_no_aparece_en_logs(env: Entorno, caplog: pytest.LogCaptureFixture) -> None:
    logging.getLogger("ngfs").propagate = True
    try:
        with caplog.at_level(logging.INFO, logger="ngfs"):
            env.login("sol")
        assert caplog.records and PASSWORD not in caplog.text
    finally:
        logging.getLogger("ngfs").propagate = False
