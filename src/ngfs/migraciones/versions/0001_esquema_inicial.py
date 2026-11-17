"""Esquema inicial NGFS v0.2 (incluye versión optimista, tokens revocados y triggers de inmutabilidad).

Revisión: 0001
Anterior: —
Fecha: 2026-11-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from ngfs.modelos import sentencias_inmutabilidad

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "usuarios",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("usuario", sa.String(64), nullable=False),
        sa.Column("nombre", sa.String(200), nullable=False),
        sa.Column("password_hash", sa.String(100), nullable=False),
        sa.Column("rol", sa.String(32), nullable=False),
        sa.Column("activo", sa.Boolean(), nullable=False),
        sa.Column("intentos_fallidos", sa.Integer(), nullable=False),
        sa.Column("bloqueado_hasta", TZ, nullable=True),
        sa.Column("creado_en", TZ, nullable=False),
    )
    op.create_index("ix_usuarios_usuario", "usuarios", ["usuario"], unique=True)

    op.create_table(
        "expedientes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("codigo", sa.String(32), nullable=False),
        sa.Column("titulo", sa.String(200), nullable=False),
        sa.Column("descripcion", sa.Text(), nullable=False),
        sa.Column("monto_solicitado", sa.Numeric(20, 2), nullable=True),
        sa.Column("moneda", sa.String(8), nullable=False),
        sa.Column("estado", sa.String(32), nullable=False),
        sa.Column("solicitante_id", sa.Integer(), sa.ForeignKey("usuarios.id"), nullable=False),
        sa.Column("creado_en", TZ, nullable=False),
        sa.Column("actualizado_en", TZ, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_expedientes_codigo", "expedientes", ["codigo"], unique=True)
    op.create_index("ix_expedientes_estado", "expedientes", ["estado"])
    op.create_index("ix_expedientes_solicitante_id", "expedientes", ["solicitante_id"])

    op.create_table(
        "historial_transiciones",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("expediente_id", sa.Integer(), sa.ForeignKey("expedientes.id"), nullable=False),
        sa.Column("accion", sa.String(64), nullable=False),
        sa.Column("desde", sa.String(32), nullable=False),
        sa.Column("hacia", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("usuarios.id"), nullable=False),
        sa.Column("justificacion", sa.Text(), nullable=False),
        sa.Column("decision_humana", sa.Boolean(), nullable=False),
        sa.Column("creado_en", TZ, nullable=False),
    )
    op.create_index("ix_historial_transiciones_expediente_id", "historial_transiciones", ["expediente_id"])

    op.create_table(
        "documentos",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("expediente_id", sa.Integer(), sa.ForeignKey("expedientes.id"), nullable=False),
        sa.Column("nombre", sa.String(255), nullable=False),
        sa.Column("tipo_mime", sa.String(128), nullable=False),
        sa.Column("tamano_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("subido_por_id", sa.Integer(), sa.ForeignKey("usuarios.id"), nullable=False),
        sa.Column("etapa", sa.String(32), nullable=False),
        sa.Column("creado_en", TZ, nullable=False),
    )
    op.create_index("ix_documentos_expediente_id", "documentos", ["expediente_id"])
    op.create_index("ix_documentos_sha256", "documentos", ["sha256"])

    op.create_table(
        "analisis_consultivos",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("expediente_id", sa.Integer(), sa.ForeignKey("expedientes.id"), nullable=False),
        sa.Column("solicitado_por_id", sa.Integer(), sa.ForeignKey("usuarios.id"), nullable=False),
        sa.Column("disponible", sa.Boolean(), nullable=False),
        sa.Column("resultado", sa.JSON(), nullable=False),
        sa.Column("creado_en", TZ, nullable=False),
    )
    op.create_index("ix_analisis_consultivos_expediente_id", "analisis_consultivos", ["expediente_id"])

    op.create_table(
        "eventos_auditoria",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("secuencia", sa.Integer(), nullable=False),
        sa.Column("marca_tiempo", sa.String(40), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor", sa.String(64), nullable=False),
        sa.Column("accion", sa.String(64), nullable=False),
        sa.Column("entidad_tipo", sa.String(32), nullable=False),
        sa.Column("entidad_id", sa.String(64), nullable=False),
        sa.Column("datos", sa.Text(), nullable=False),
        sa.Column("hash_anterior", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("hash"),
    )
    op.create_index("ix_eventos_auditoria_secuencia", "eventos_auditoria", ["secuencia"], unique=True)
    op.create_index("ix_eventos_auditoria_accion", "eventos_auditoria", ["accion"])

    op.create_table(
        "tokens_revocados",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("usuario_id", sa.Integer(), sa.ForeignKey("usuarios.id"), nullable=False),
        sa.Column("expira_en", TZ, nullable=False),
        sa.Column("revocado_en", TZ, nullable=False),
    )
    op.create_index("ix_tokens_revocados_usuario_id", "tokens_revocados", ["usuario_id"])
    op.create_index("ix_tokens_revocados_expira_en", "tokens_revocados", ["expira_en"])

    for sentencia in sentencias_inmutabilidad(op.get_bind().dialect.name):
        op.execute(sentencia)


def downgrade() -> None:
    dialecto = op.get_bind().dialect.name
    if dialecto == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS ngfs_auditoria_inmutable ON eventos_auditoria")
        op.execute("DROP TRIGGER IF EXISTS ngfs_auditoria_no_truncate ON eventos_auditoria")
        op.execute("DROP FUNCTION IF EXISTS ngfs_bloquear_auditoria()")
    elif dialecto == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS ngfs_auditoria_no_update")
        op.execute("DROP TRIGGER IF EXISTS ngfs_auditoria_no_delete")
    for tabla in ("tokens_revocados", "eventos_auditoria", "analisis_consultivos", "documentos",
                  "historial_transiciones", "expedientes", "usuarios"):
        op.drop_table(tabla)
