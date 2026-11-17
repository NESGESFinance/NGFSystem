"""Decisiones colegiadas: votaciones con quórum y votos individuales firmados (Fase 4).

Revisión: 0002
Anterior: 0001
Fecha: 2026-11-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TZ = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.create_table(
        "votaciones_decision",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("expediente_id", sa.Integer(), sa.ForeignKey("expedientes.id"), nullable=False),
        sa.Column("transicion_objetivo", sa.String(64), nullable=False),
        sa.Column("iniciador_id", sa.Integer(), sa.ForeignKey("usuarios.id"), nullable=False),
        sa.Column("estado_votacion", sa.String(16), nullable=False),
        sa.Column("quorum_requerido", sa.Integer(), nullable=False),
        sa.Column("fecha_apertura", TZ, nullable=False),
        sa.Column("fecha_cierre_previsto", TZ, nullable=False),
        sa.Column("fecha_cierre_real", TZ, nullable=True),
        sa.Column("justificacion_cierre", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_votaciones_decision_expediente_id", "votaciones_decision", ["expediente_id"])
    op.create_index("ix_votaciones_decision_estado_votacion", "votaciones_decision", ["estado_votacion"])

    op.create_table(
        "votos_individuales",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("votacion_id", sa.Integer(), sa.ForeignKey("votaciones_decision.id"), nullable=False),
        sa.Column("votante_id", sa.Integer(), sa.ForeignKey("usuarios.id"), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("justificacion", sa.Text(), nullable=False),
        sa.Column("timestamp_voto", TZ, nullable=False),
        sa.Column("firma_voto", sa.String(64), nullable=True),
        sa.UniqueConstraint("votacion_id", "votante_id", name="uq_voto_votacion_votante"),
    )
    op.create_index("ix_votos_individuales_votacion_id", "votos_individuales", ["votacion_id"])


def downgrade() -> None:
    op.drop_index("ix_votos_individuales_votacion_id", table_name="votos_individuales")
    op.drop_table("votos_individuales")
    op.drop_index("ix_votaciones_decision_estado_votacion", table_name="votaciones_decision")
    op.drop_index("ix_votaciones_decision_expediente_id", table_name="votaciones_decision")
    op.drop_table("votaciones_decision")
