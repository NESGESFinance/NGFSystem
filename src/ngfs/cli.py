"""Utilidades de línea de comandos.

Crear el administrador inicial (la contraseña se lee de NGFS_ADMIN_PASSWORD o de --password):

    NGFS_ADMIN_PASSWORD='...' python -m ngfs.cli crear-admin --usuario admin --nombre "Administración"

Aplicar las migraciones de base de datos (producción, con NGFS_CREAR_TABLAS_AL_INICIAR=false):

    ngfs migrar                 # hasta la última revisión ("head")
    ngfs migrar --sql           # muestra el SQL sin ejecutarlo (modo offline)
    ngfs migrar --estampar      # marca una BD creada con create_all como ya migrada
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config as ConfigAlembic
from fastapi import HTTPException
from pydantic import ValidationError

from ngfs.api.rutas_auth import crear_usuario
from ngfs.config import obtener_configuracion
from ngfs.db import BaseDeDatos
from ngfs.esquemas import UsuarioCrear
from ngfs.estados import Rol


def crear_admin(usuario: str, nombre: str, password: str) -> int:
    cfg = obtener_configuracion()
    db = BaseDeDatos(cfg.database_url)
    db.crear_tablas()
    with db.fabrica() as sesion:
        try:
            nuevo = crear_usuario(sesion, UsuarioCrear(usuario=usuario, nombre=nombre, password=password, rol=Rol.ADMINISTRADOR),
                                  cfg.longitud_minima_password, None)
        except HTTPException as exc:
            print(f"Error: {exc.detail}", file=sys.stderr)
            return 1
        except ValidationError as exc:
            print(f"Error de validación: {exc.errors()[0]['msg']}", file=sys.stderr)
            return 1
    print(f"Administrador '{nuevo.usuario}' creado (id={nuevo.id}).")
    return 0


def config_alembic(url: str | None = None) -> ConfigAlembic:
    """Configuración Alembic programática: no requiere ``alembic.ini`` y funciona con el paquete instalado."""
    cfg = ConfigAlembic()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migraciones"))
    cfg.set_main_option("sqlalchemy.url", (url or obtener_configuracion().database_url).replace("%", "%%"))
    return cfg


def migrar(revision: str = "head", *, sql: bool = False, estampar: bool = False, url: str | None = None) -> int:
    cfg = config_alembic(url)
    if estampar:
        command.stamp(cfg, revision)
        print(f"Base de datos marcada en la revisión '{revision}'.", file=sys.stderr)
    else:
        command.upgrade(cfg, revision, sql=sql)
        if not sql:
            print(f"Migraciones aplicadas hasta '{revision}'.", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ngfs", description="Herramientas de administración de NGFSystem")
    sub = parser.add_subparsers(dest="comando", required=True)
    p = sub.add_parser("crear-admin", help="Crea un usuario con rol administrador")
    p.add_argument("--usuario", required=True)
    p.add_argument("--nombre", default="")
    p.add_argument("--password", default=None, help="Preferible usar la variable NGFS_ADMIN_PASSWORD")
    m = sub.add_parser("migrar", help="Aplica las migraciones Alembic de la base de datos")
    m.add_argument("revision", nargs="?", default="head")
    m.add_argument("--sql", action="store_true", help="Imprime el SQL en lugar de ejecutarlo")
    m.add_argument("--estampar", action="store_true", help="Solo registra la revisión, sin ejecutar cambios")
    args = parser.parse_args(argv)
    if args.comando == "migrar":
        return migrar(args.revision, sql=args.sql, estampar=args.estampar)
    password = args.password or os.environ.get("NGFS_ADMIN_PASSWORD", "")
    if not password:
        print("Error: defina NGFS_ADMIN_PASSWORD o use --password.", file=sys.stderr)
        return 2
    return crear_admin(args.usuario, args.nombre, password)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
