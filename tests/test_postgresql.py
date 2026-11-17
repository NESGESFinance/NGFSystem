"""Pruebas contra PostgreSQL real. Se omiten salvo que se defina NGFS_TEST_PG_URL, p. ej.:

    NGFS_TEST_PG_URL=postgresql+psycopg://ngfs:ngfs@localhost/ngfs_pruebas pytest tests/test_postgresql.py

¡La base de datos indicada se vacía por completo! Use una dedicada a pruebas.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from conftest import Entorno, cfg_pruebas
from ngfs import cli, modelos  # noqa: F401 - registra los modelos
from ngfs.auditoria import registrar_evento, verificar_cadena
from ngfs.db import Base
from ngfs.estados import Rol

URL = os.environ.get("NGFS_TEST_PG_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="NGFS_TEST_PG_URL no definida")


@pytest.fixture
def pg() -> Iterator[Entorno]:
    motor = create_engine(URL)
    with motor.begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE"))
        c.execute(text("CREATE SCHEMA public"))
    motor.dispose()
    cli.migrar(url=URL)
    env = Entorno(cfg_pruebas(database_url=URL, crear_tablas_al_iniciar=False))
    env.usuario("sol", Rol.SOLICITANTE)
    env.usuario("aud", Rol.AUDITOR)
    yield env
    env.app.state.db.motor.dispose()


def test_pg_migracion_coincide_con_modelos(pg: Entorno) -> None:
    with pg.app.state.db.motor.connect() as c:
        assert compare_metadata(MigrationContext.configure(c), Base.metadata) == []


@pytest.mark.parametrize("sentencia", [
    "UPDATE eventos_auditoria SET accion = 'x'", "DELETE FROM eventos_auditoria", "TRUNCATE eventos_auditoria",
])
def test_pg_bitacora_inmutable(pg: Entorno, sentencia: str) -> None:
    pg.crear_expediente()
    with pg.sesion() as s:
        with pytest.raises(DBAPIError, match="inmutable"):
            s.execute(text(sentencia))
        s.rollback()
    assert pg.cliente.get("/auditoria/verificar", headers=pg.h("aud")).json()["integra"] is True


def test_pg_eventos_concurrentes_mantienen_la_cadena(pg: Entorno) -> None:
    """Sin el bloqueo consultivo, dos transacciones leerían el mismo 'último evento' y una fallaría o bifurcaría."""

    def escribir(i: int) -> None:
        with pg.sesion() as s:
            registrar_evento(s, actor=None, accion="prueba_concurrencia", entidad_tipo="prueba", entidad_id=i)
            s.commit()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(escribir, range(40)))
    with pg.sesion() as s:
        resultado = verificar_cadena(s)
        total = s.execute(text("SELECT count(*) FROM eventos_auditoria WHERE accion = 'prueba_concurrencia'")).scalar()
    assert total == 40 and resultado.integra


def test_pg_downgrade(pg: Entorno) -> None:
    pg.app.state.db.motor.dispose()
    command.downgrade(cli.config_alembic(URL), "base")
    with create_engine(URL).connect() as c:
        tablas = c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")).scalars().all()
    assert set(tablas) <= {"alembic_version"}
