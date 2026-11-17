"""Decisiones colegiadas: apertura de votaciones, votos firmados (HMAC-SHA256), quórum y cierre (Fase 4)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ngfs import rbac
from ngfs.api.dependencias import CfgDep, ClaimsDep, SesionDep, UsuarioDep, cargar_expediente, exigir_global
from ngfs.auditoria import registrar_evento
from ngfs.config import Configuracion
from ngfs.crypto.firmas import clave_firmas, firmar_voto, verificar_voto
from ngfs.esquemas import (
    DecisionVoto,
    EstadoVotacion,
    VotacionCerrar,
    VotacionCrear,
    VotacionSalida,
    VotoEmitir,
    VotoSalida,
)
from ngfs.estados import Estado, TransicionInvalida, buscar_transicion
from ngfs.modelos import Expediente, HistorialTransicion, Usuario, VotacionDecision, VotoIndividual
from ngfs.votaciones import (
    contar,
    datos_voto,
    expirar_si_vencida,
    hash_voto,
    votacion_abierta,
    votantes_elegibles,
    votos_de,
)

router = APIRouter(tags=["decisiones colegiadas"])


def _salida(sesion: SesionDep, cfg: Configuracion, votacion: VotacionDecision) -> VotacionSalida:
    clave = clave_firmas(cfg)
    votos = votos_de(sesion, votacion.id)
    return VotacionSalida(
        id=votacion.id, expediente_id=votacion.expediente_id, transicion_objetivo=votacion.transicion_objetivo,
        iniciador_id=votacion.iniciador_id, estado_votacion=votacion.estado_votacion,
        quorum_requerido=votacion.quorum_requerido, fecha_apertura=votacion.fecha_apertura,
        fecha_cierre_previsto=votacion.fecha_cierre_previsto, fecha_cierre_real=votacion.fecha_cierre_real,
        justificacion_cierre=votacion.justificacion_cierre, conteo=contar(votos),
        votos=[VotoSalida(id=v.id, votante_id=v.votante_id, decision=v.decision, justificacion=v.justificacion,
                          timestamp_voto=v.timestamp_voto, firma_voto=v.firma_voto,
                          verified=verificar_voto(datos_voto(v), v.firma_voto, clave)) for v in votos],
    )


def _cargar_votacion(sesion: SesionDep, usuario: Usuario, votacion_id: int) -> tuple[VotacionDecision, Expediente]:
    votacion = sesion.get(VotacionDecision, votacion_id)
    if votacion is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Votación no encontrada.")
    try:
        exp = cargar_expediente(sesion, usuario, votacion.expediente_id)
    except HTTPException as exc:  # no revelar votaciones de expedientes no visibles
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Votación no encontrada.") from exc
    return votacion, exp


@router.post("/expedientes/{expediente_id}/votaciones", response_model=VotacionSalida, status_code=201)
def abrir_votacion(expediente_id: int, datos: VotacionCrear, usuario: UsuarioDep, sesion: SesionDep,
                   cfg: CfgDep) -> VotacionSalida:
    exigir_global(usuario, rbac.ABRIR_VOTACION)
    exp = cargar_expediente(sesion, usuario, expediente_id)
    try:
        t = buscar_transicion(Estado(exp.estado), datos.transicion_objetivo)
    except TransicionInvalida as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if not t.decision_humana:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "Solo las transiciones de decisión (aprobar/rechazar) se someten a votación colegiada.")
    previa = votacion_abierta(sesion, exp.id)
    if previa is not None and expirar_si_vencida(sesion, previa):
        sesion.commit()
        previa = None
    if previa is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"El expediente ya tiene una votación abierta (#{previa.id}).")
    elegibles = votantes_elegibles(sesion, exp.solicitante_id)
    if elegibles < datos.quorum_requerido:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            f"Quórum inalcanzable: se requieren {datos.quorum_requerido} votos y solo hay "
                            f"{elegibles} votantes elegibles.")
    ahora = datetime.now(UTC)
    votacion = VotacionDecision(expediente_id=exp.id, transicion_objetivo=t.accion, iniciador_id=usuario.id,
                                estado_votacion=EstadoVotacion.ABIERTA.value, quorum_requerido=datos.quorum_requerido,
                                fecha_apertura=ahora, fecha_cierre_previsto=ahora + timedelta(hours=datos.duracion_horas))
    sesion.add(votacion)
    sesion.flush()
    registrar_evento(sesion, actor=usuario, accion="VOTACION_ABIERTA", entidad_tipo="votacion", entidad_id=votacion.id,
                     datos={"expediente_id": exp.id, "transicion_objetivo": t.accion,
                            "quorum_requerido": datos.quorum_requerido,
                            "fecha_cierre_previsto": votacion.fecha_cierre_previsto.isoformat()})
    sesion.commit()
    return _salida(sesion, cfg, votacion)


@router.get("/votaciones/{votacion_id}", response_model=VotacionSalida)
def ver_votacion(votacion_id: int, usuario: UsuarioDep, sesion: SesionDep, cfg: CfgDep) -> VotacionSalida:
    votacion, _ = _cargar_votacion(sesion, usuario, votacion_id)
    if expirar_si_vencida(sesion, votacion):
        sesion.commit()
    return _salida(sesion, cfg, votacion)


@router.get("/expedientes/{expediente_id}/votaciones", response_model=list[VotacionSalida])
def listar_votaciones(expediente_id: int, usuario: UsuarioDep, sesion: SesionDep, cfg: CfgDep) -> list[VotacionSalida]:
    exp = cargar_expediente(sesion, usuario, expediente_id)
    consulta = select(VotacionDecision).where(VotacionDecision.expediente_id == exp.id).order_by(VotacionDecision.id)
    return [_salida(sesion, cfg, v) for v in sesion.execute(consulta).scalars()]


def _ejecutar_transicion_por_quorum(sesion: SesionDep, votacion: VotacionDecision, exp: Expediente, actor: Usuario,
                                    votos: list[VotoIndividual]) -> None:
    t = buscar_transicion(Estado(exp.estado), votacion.transicion_objetivo)
    favor = [v for v in votos if v.decision == DecisionVoto.FAVOR.value]
    justificacion = (f"Decisión colegiada: votación #{votacion.id} aprobada por quórum "
                     f"({len(favor)}/{votacion.quorum_requerido} votos a favor).")
    exp.estado = t.hacia.value
    votacion.estado_votacion = EstadoVotacion.APROBADA.value
    votacion.fecha_cierre_real = datetime.now(UTC)
    votacion.justificacion_cierre = justificacion
    sesion.add(HistorialTransicion(expediente_id=exp.id, accion=t.accion, desde=t.desde.value, hacia=t.hacia.value,
                                   actor_id=actor.id, justificacion=justificacion, decision_humana=True))
    registrar_evento(sesion, actor=actor, accion="transicion", entidad_tipo="expediente", entidad_id=exp.id,
                     datos={"accion": t.accion, "desde": t.desde.value, "hacia": t.hacia.value,
                            "justificacion": justificacion, "decision_humana": True, "votacion_id": votacion.id})
    registrar_evento(sesion, actor=actor, accion="VOTACION_APROBADA", entidad_tipo="votacion", entidad_id=votacion.id,
                     datos={"expediente_id": exp.id, "transicion": t.accion, "desde": t.desde.value,
                            "hacia": t.hacia.value, "quorum_requerido": votacion.quorum_requerido,
                            "votantes": [{"votante_id": v.votante_id, "decision": v.decision, "hash_voto": hash_voto(v)}
                                         for v in votos]})


@router.post("/votaciones/{votacion_id}/votar", response_model=VotacionSalida)
def votar(votacion_id: int, datos: VotoEmitir, usuario: UsuarioDep, claims: ClaimsDep, sesion: SesionDep,
          cfg: CfgDep) -> VotacionSalida:
    exigir_global(usuario, rbac.VOTAR)
    votacion, exp = _cargar_votacion(sesion, usuario, votacion_id)
    if expirar_si_vencida(sesion, votacion):
        sesion.commit()
    if votacion.estado_votacion != EstadoVotacion.ABIERTA.value:
        raise HTTPException(status.HTTP_409_CONFLICT, f"La votación no está abierta (estado {votacion.estado_votacion}).")
    if claims.get("tipo") != "humano" or not datos.confirmacion_humana:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "Los votos exigen confirmación humana explícita (confirmacion_humana=true).")
    if exp.solicitante_id == usuario.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Segregación de funciones: no puede votar sobre un expediente que usted mismo presentó.")
    ya_voto = select(VotoIndividual.id).where(VotoIndividual.votacion_id == votacion.id,
                                              VotoIndividual.votante_id == usuario.id)
    if sesion.execute(ya_voto).first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Ya emitió su voto en esta votación.")
    try:
        buscar_transicion(Estado(exp.estado), votacion.transicion_objetivo)
    except TransicionInvalida as exc:  # el expediente cambió de etapa por otra vía: la votación ya no aplica
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    voto = VotoIndividual(votacion_id=votacion.id, votante_id=usuario.id, decision=datos.decision.value,
                          justificacion=datos.justificacion.strip(), timestamp_voto=datetime.now(UTC))
    voto.firma_voto = firmar_voto(datos_voto(voto), clave_firmas(cfg))
    sesion.add(voto)
    try:
        sesion.flush()
    except IntegrityError as exc:  # restricción UNIQUE (votacion_id, votante_id) ante votos simultáneos
        sesion.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Ya emitió su voto en esta votación.") from exc
    registrar_evento(sesion, actor=usuario, accion="VOTO_EMITIDO", entidad_tipo="votacion", entidad_id=votacion.id,
                     datos={"expediente_id": exp.id, "decision": voto.decision, "hash_voto": hash_voto(voto)})

    votos = votos_de(sesion, votacion.id)
    conteo = contar(votos)
    if conteo.favor >= votacion.quorum_requerido:
        _ejecutar_transicion_por_quorum(sesion, votacion, exp, usuario, votos)
    elif conteo.contra >= votacion.quorum_requerido:
        votacion.estado_votacion = EstadoVotacion.RECHAZADA.value
        votacion.fecha_cierre_real = datetime.now(UTC)
        votacion.justificacion_cierre = f"Votos en contra alcanzaron el quórum ({conteo.contra}/{votacion.quorum_requerido})."
        registrar_evento(sesion, actor=usuario, accion="VOTACION_RECHAZADA", entidad_tipo="votacion",
                         entidad_id=votacion.id,
                         datos={"expediente_id": exp.id, "transicion_objetivo": votacion.transicion_objetivo,
                                "votantes": [{"votante_id": v.votante_id, "decision": v.decision,
                                              "hash_voto": hash_voto(v)} for v in votos]})
    sesion.commit()
    return _salida(sesion, cfg, votacion)


@router.post("/votaciones/{votacion_id}/cerrar", response_model=VotacionSalida)
def cerrar_votacion(votacion_id: int, datos: VotacionCerrar, usuario: UsuarioDep, sesion: SesionDep,
                    cfg: CfgDep) -> VotacionSalida:
    """Cierre manual sin ejecutar la transición: la votación queda RECHAZADA con la justificación indicada."""
    exigir_global(usuario, rbac.CERRAR_VOTACION)
    votacion, exp = _cargar_votacion(sesion, usuario, votacion_id)
    if expirar_si_vencida(sesion, votacion):
        sesion.commit()
    if votacion.estado_votacion != EstadoVotacion.ABIERTA.value:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Solo se pueden cerrar votaciones abiertas "
                                                      f"(estado {votacion.estado_votacion}).")
    votos = votos_de(sesion, votacion.id)
    votacion.estado_votacion = EstadoVotacion.RECHAZADA.value
    votacion.fecha_cierre_real = datetime.now(UTC)
    votacion.justificacion_cierre = datos.justificacion.strip()
    registrar_evento(sesion, actor=usuario, accion="VOTACION_CERRADA", entidad_tipo="votacion", entidad_id=votacion.id,
                     datos={"expediente_id": exp.id, "resultado": EstadoVotacion.RECHAZADA.value,
                            "justificacion": votacion.justificacion_cierre, "conteo": contar(votos).model_dump(),
                            "votantes": [{"votante_id": v.votante_id, "decision": v.decision,
                                          "hash_voto": hash_voto(v)} for v in votos]})
    sesion.commit()
    return _salida(sesion, cfg, votacion)
