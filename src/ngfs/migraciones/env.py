"""Entorno Alembic de NGFS. La URL sale de ``sqlalchemy.url`` (si se fija) o de la configuración NGFS."""

from __future__ import annotations

from alembic import context

from ngfs import modelos  # noqa: F401 - registra los modelos en Base.metadata
from ngfs.config import Configuracion
from ngfs.db import Base, crear_motor

config = context.config
metadata_objetivo = Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or Configuracion().database_url


def ejecutar_offline() -> None:
    context.configure(url=_url(), target_metadata=metadata_objetivo, literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def ejecutar_online() -> None:
    motor = crear_motor(_url())
    with motor.connect() as conexion:
        context.configure(connection=conexion, target_metadata=metadata_objetivo, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
    motor.dispose()


if context.is_offline_mode():
    ejecutar_offline()
else:
    ejecutar_online()
