"""Cifrado de documentos en reposo: contenido (cifrado o en claro), indicador ``cifrado`` y ``clave_doc_id`` (Fase 4).

Los documentos existentes (v0.1/v0.2) quedan con ``contenido`` nulo y ``cifrado = false``: solo tienen huella.

Revisión: 0003
Anterior: 0002
Fecha: 2026-11-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ADD COLUMN es compatible con SQLite y PostgreSQL sin modo batch (permite además `ngfs migrar --sql`).
    op.add_column("documentos", sa.Column("contenido", sa.LargeBinary(), nullable=True))
    op.add_column("documentos", sa.Column("cifrado", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("documentos", sa.Column("clave_doc_id", sa.String(64), nullable=True))


def downgrade() -> None:
    # SQLite requiere modo batch (copia de tabla) para eliminar columnas de forma portable.
    with op.batch_alter_table("documentos") as lote:
        lote.drop_column("clave_doc_id")
        lote.drop_column("cifrado")
        lote.drop_column("contenido")
