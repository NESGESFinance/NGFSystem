"""Lógica de dominio de las decisiones colegiadas (quórum) — Fase 4.

Reglas:
  * Solo se someten a votación las transiciones de decisión humana (``aprobar`` / ``rechazar``).
  * Una votación ABIERTA por expediente; mientras exista, no se permiten transiciones directas sobre él.
  * La transición se ejecuta automáticamente cuando los votos FAVOR alcanzan ``quorum_requerido``.
    Si los votos CONTRA alcanzan el quórum, la votación queda RECHAZADA y el expediente no cambia.
  * Las abstenciones no cuentan ni a favor ni en contra.
  * Vencido ``fecha_cierre_previsto`` sin resultado, la votación pasa a EXPIRADA (evaluación perezosa).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ngfs import rbac
from ngfs.auditoria import json_canonico, registrar_evento
from ngfs.crypto.firmas import DatosVoto, normalizar_marca
from ngfs.esquemas import ConteoVotos, DecisionVoto, EstadoVotacion
from ngfs.modelos import Usuario, VotacionDecision, VotoIndividual


def como_utc(valor: datetime) -> datetime:
    return valor if valor.tzinfo else valor.replace(tzinfo=UTC)


def datos_voto(voto: VotoIndividual) -> DatosVoto:
    return DatosVoto(votacion_id=voto.votacion_id, votante_id=voto.votante_id, decision=voto.decision,
                     timestamp_voto=voto.timestamp_voto)


def hash_voto(voto: VotoIndividual) -> str:
    """Huella SHA-256 del voto completo (incluida su firma), registrada en la bitácora al cerrar la votación."""
    return hashlib.sha256(json_canonico({
        "votacion_id": voto.votacion_id, "votante_id": voto.votante_id, "decision": voto.decision,
        "justificacion": voto.justificacion, "timestamp_voto": normalizar_marca(voto.timestamp_voto),
        "firma_voto": voto.firma_voto,
    }).encode("utf-8")).hexdigest()


def votos_de(sesion: Session, votacion_id: int) -> list[VotoIndividual]:
    consulta = select(VotoIndividual).where(VotoIndividual.votacion_id == votacion_id).order_by(VotoIndividual.id)
    return list(sesion.execute(consulta).scalars())


def contar(votos: list[VotoIndividual]) -> ConteoVotos:
    def n(decision: DecisionVoto) -> int:
        return sum(1 for v in votos if v.decision == decision.value)

    return ConteoVotos(favor=n(DecisionVoto.FAVOR), contra=n(DecisionVoto.CONTRA), abstencion=n(DecisionVoto.ABSTENCION))


def votacion_abierta(sesion: Session, expediente_id: int) -> VotacionDecision | None:
    consulta = select(VotacionDecision).where(VotacionDecision.expediente_id == expediente_id,
                                              VotacionDecision.estado_votacion == EstadoVotacion.ABIERTA.value)
    return sesion.execute(consulta).scalars().first()


def votantes_elegibles(sesion: Session, excluir_usuario_id: int) -> int:
    """Usuarios activos con rol de voto, excluido el solicitante del expediente (segregación de funciones)."""
    roles = [r.value for r in rbac.ACCIONES_GLOBALES[rbac.VOTAR]]
    consulta = select(func.count(Usuario.id)).where(Usuario.activo.is_(True), Usuario.rol.in_(roles),
                                                    Usuario.id != excluir_usuario_id)
    return int(sesion.execute(consulta).scalar_one())


def expirar_si_vencida(sesion: Session, votacion: VotacionDecision) -> bool:
    """Marca la votación como EXPIRADA si venció su plazo estando ABIERTA. Devuelve True si cambió."""
    ahora = datetime.now(UTC)
    if votacion.estado_votacion != EstadoVotacion.ABIERTA.value or como_utc(votacion.fecha_cierre_previsto) > ahora:
        return False
    votacion.estado_votacion = EstadoVotacion.EXPIRADA.value
    votacion.fecha_cierre_real = ahora
    votacion.justificacion_cierre = "Plazo vencido sin alcanzar el quórum."
    registrar_evento(sesion, actor=None, accion="VOTACION_EXPIRADA", entidad_tipo="votacion", entidad_id=votacion.id,
                     datos={"expediente_id": votacion.expediente_id, "transicion_objetivo": votacion.transicion_objetivo})
    return True
