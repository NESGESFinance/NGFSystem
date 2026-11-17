"""Expedientes: CRUD básico, máquina de estados, documentos y análisis consultivo UASI."""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, status
from sqlalchemy import select, update
from sqlalchemy.orm.attributes import set_committed_value

from ngfs import rbac
from ngfs.api.dependencias import CfgDep, ClaimsDep, SesionDep, UsuarioDep, cargar_expediente, exigir_global, obtener_uasi
from ngfs.auditoria import registrar_evento
from ngfs.config import Configuracion
from ngfs.crypto.documentos import DocumentoCifradoError, cifrar_documento, descifrar_documento, identificador_clave
from ngfs.esquemas import (
    AnalisisSalida,
    DocumentoSalida,
    ExpedienteCrear,
    ExpedienteEditar,
    ExpedienteSalida,
    HistorialSalida,
    SolicitudTransicion,
    TransicionDisponible,
    VerificacionDocumento,
)
from ngfs.estados import ETAPAS, Estado, Rol, TransicionInvalida, buscar_transicion, transiciones_desde
from ngfs.modelos import AnalisisConsultivo, Documento, Expediente, HistorialTransicion
from ngfs.uasi_adaptador import AdaptadorUASI
from ngfs.votaciones import votacion_abierta

router = APIRouter(tags=["expedientes"])
_TROZO = 1024 * 1024
log = logging.getLogger("ngfs.documentos")


def a_salida(exp: Expediente) -> ExpedienteSalida:
    etapa, nombre = ETAPAS[Estado(exp.estado)]
    return ExpedienteSalida(
        id=exp.id, codigo=exp.codigo, titulo=exp.titulo, descripcion=exp.descripcion,
        monto_solicitado=exp.monto_solicitado, moneda=exp.moneda, estado=exp.estado, etapa=etapa,
        etapa_nombre=nombre, solicitante_id=exp.solicitante_id, creado_en=exp.creado_en, actualizado_en=exp.actualizado_en,
        version=exp.version,
    )


def comprobar_version(exp: Expediente, version_esperada: int | None) -> None:
    """Concurrencia optimista explícita: el cliente indica la versión que leyó."""
    if version_esperada is not None and version_esperada != exp.version:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"El expediente fue modificado por otra persona (versión actual {exp.version}, "
            f"esperada {version_esperada}). Vuelva a consultarlo antes de continuar.",
        )


@router.post("/expedientes", response_model=ExpedienteSalida, status_code=201)
def crear_expediente(datos: ExpedienteCrear, usuario: UsuarioDep, sesion: SesionDep) -> ExpedienteSalida:
    exigir_global(usuario, rbac.CREAR_EXPEDIENTE)
    exp = Expediente(codigo=f"TMP-{uuid4().hex[:16]}", titulo=datos.titulo, descripcion=datos.descripcion,
                     monto_solicitado=datos.monto_solicitado, moneda=datos.moneda,
                     estado=Estado.BORRADOR.value, solicitante_id=usuario.id)
    sesion.add(exp)
    sesion.flush()
    # El código depende del id autogenerado. Se fija con un UPDATE directo para que la creación no cuente
    # como modificación: el expediente nace con version = 1.
    codigo = f"NGFS-{datetime.now(UTC).year}-{exp.id:05d}"
    sesion.execute(update(Expediente).where(Expediente.id == exp.id).values(codigo=codigo))
    set_committed_value(exp, "codigo", codigo)
    registrar_evento(sesion, actor=usuario, accion="expediente_creado", entidad_tipo="expediente", entidad_id=exp.id,
                     datos={"codigo": exp.codigo, "titulo": exp.titulo, "estado": exp.estado})
    sesion.commit()
    return a_salida(exp)


@router.get("/expedientes", response_model=list[ExpedienteSalida])
def listar_expedientes(usuario: UsuarioDep, sesion: SesionDep, estado: Estado | None = None) -> list[ExpedienteSalida]:
    rol = Rol(usuario.rol)
    visibles = [e.value for e in Estado if rbac.permitido(rol, e, rbac.VER)]
    consulta = select(Expediente).where(Expediente.estado.in_(visibles)).order_by(Expediente.id)
    if rol == Rol.SOLICITANTE:
        consulta = consulta.where(Expediente.solicitante_id == usuario.id)
    if estado is not None:
        consulta = consulta.where(Expediente.estado == estado.value)
    return [a_salida(e) for e in sesion.execute(consulta).scalars()]


@router.get("/expedientes/{expediente_id}", response_model=ExpedienteSalida)
def ver_expediente(expediente_id: int, usuario: UsuarioDep, sesion: SesionDep) -> ExpedienteSalida:
    return a_salida(cargar_expediente(sesion, usuario, expediente_id))


@router.patch("/expedientes/{expediente_id}", response_model=ExpedienteSalida)
def editar_expediente(expediente_id: int, datos: ExpedienteEditar, usuario: UsuarioDep, sesion: SesionDep) -> ExpedienteSalida:
    exp = cargar_expediente(sesion, usuario, expediente_id, rbac.EDITAR)
    comprobar_version(exp, datos.version_esperada)
    cambios = datos.model_dump(exclude_unset=True, exclude_none=True, exclude={"version_esperada"})
    for campo, valor in cambios.items():
        setattr(exp, campo, valor)
    if cambios:
        registrar_evento(sesion, actor=usuario, accion="expediente_editado", entidad_tipo="expediente",
                         entidad_id=exp.id, datos={k: str(v) for k, v in cambios.items()})
    sesion.commit()
    return a_salida(exp)


@router.get("/expedientes/{expediente_id}/transiciones-disponibles", response_model=list[TransicionDisponible])
def transiciones_disponibles(expediente_id: int, usuario: UsuarioDep, sesion: SesionDep) -> list[TransicionDisponible]:
    exp = cargar_expediente(sesion, usuario, expediente_id)
    rol = Rol(usuario.rol)
    return [
        TransicionDisponible(accion=t.accion, hacia=t.hacia.value, decision_humana=t.decision_humana,
                             requiere_justificacion=t.requiere_justificacion, descripcion=t.descripcion)
        for t in transiciones_desde(Estado(exp.estado)) if rol in t.roles
    ]


@router.post("/expedientes/{expediente_id}/transiciones", response_model=ExpedienteSalida)
def ejecutar_transicion(
    expediente_id: int, solicitud: SolicitudTransicion, usuario: UsuarioDep, claims: ClaimsDep, sesion: SesionDep
) -> ExpedienteSalida:
    exp = cargar_expediente(sesion, usuario, expediente_id)
    comprobar_version(exp, solicitud.version_esperada)
    abierta = votacion_abierta(sesion, exp.id)
    if abierta is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"El expediente tiene una votación colegiada abierta (#{abierta.id}); la decisión se "
                            "tomará por quórum o tras cerrarla.")
    estado_actual = Estado(exp.estado)
    try:
        t = buscar_transicion(estado_actual, solicitud.accion)
    except TransicionInvalida as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    if not rbac.permitido(Rol(usuario.rol), estado_actual, t.accion):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"El rol '{usuario.rol}' no puede ejecutar '{t.accion}' en la etapa '{estado_actual.value}'.")
    justificacion = solicitud.justificacion.strip()
    if t.requiere_justificacion and len(justificacion) < 10:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "Esta transición exige una justificación de al menos 10 caracteres.")
    if t.decision_humana:
        if claims.get("tipo") != "humano" or not solicitud.confirmacion_humana:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                "Las decisiones exigen confirmación humana explícita (confirmacion_humana=true).")
        if exp.solicitante_id == usuario.id:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "Segregación de funciones: no puede decidir sobre un expediente que usted mismo presentó.")
    exp.estado = t.hacia.value
    sesion.add(HistorialTransicion(expediente_id=exp.id, accion=t.accion, desde=t.desde.value, hacia=t.hacia.value,
                                   actor_id=usuario.id, justificacion=justificacion, decision_humana=t.decision_humana))
    registrar_evento(sesion, actor=usuario, accion="transicion", entidad_tipo="expediente", entidad_id=exp.id,
                     datos={"accion": t.accion, "desde": t.desde.value, "hacia": t.hacia.value,
                            "justificacion": justificacion, "decision_humana": t.decision_humana})
    sesion.commit()
    return a_salida(exp)


@router.get("/expedientes/{expediente_id}/historial", response_model=list[HistorialSalida])
def historial(expediente_id: int, usuario: UsuarioDep, sesion: SesionDep) -> list[HistorialTransicion]:
    exp = cargar_expediente(sesion, usuario, expediente_id)
    consulta = select(HistorialTransicion).where(HistorialTransicion.expediente_id == exp.id).order_by(HistorialTransicion.id)
    return list(sesion.execute(consulta).scalars())


def _leer_archivo(archivo: UploadFile, limite_bytes: int) -> tuple[bytes, str]:
    """Lee el archivo por trozos respetando el límite y devuelve (contenido original, SHA-256 del original)."""
    h = hashlib.sha256()
    trozos: list[bytes] = []
    total = 0
    while trozo := archivo.file.read(_TROZO):
        total += len(trozo)
        if total > limite_bytes:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "El documento supera el tamaño máximo permitido.")
        h.update(trozo)
        trozos.append(trozo)
    return b"".join(trozos), h.hexdigest()


def _hash_archivo(archivo: UploadFile, limite_bytes: int) -> tuple[str, int]:
    contenido, sha = _leer_archivo(archivo, limite_bytes)
    return sha, len(contenido)


def _proteger(contenido: bytes, cfg: Configuracion) -> tuple[bytes, bool, str | None]:
    """Cifrado transparente en reposo. Sin clave configurada se guarda en claro (retrocompatibilidad) con aviso."""
    if not cfg.doc_encryption_key:
        log.warning("NGFS_DOC_ENCRYPTION_KEY no configurada: el documento se almacena SIN cifrar.")
        return contenido, False, None
    return cifrar_documento(contenido, cfg.doc_encryption_key), True, identificador_clave(cfg.doc_encryption_key)


@router.post("/expedientes/{expediente_id}/documentos", response_model=DocumentoSalida, status_code=201)
def adjuntar_documento(expediente_id: int, archivo: UploadFile, usuario: UsuarioDep, sesion: SesionDep, cfg: CfgDep) -> Documento:
    exp = cargar_expediente(sesion, usuario, expediente_id, rbac.ADJUNTAR)
    original, sha = _leer_archivo(archivo, cfg.max_tamano_documento_mb * 1024 * 1024)  # huella sobre el ORIGINAL
    almacenado, cifrado, clave_id = _proteger(original, cfg)
    doc = Documento(expediente_id=exp.id, nombre=(archivo.filename or "sin_nombre")[:255],
                    tipo_mime=(archivo.content_type or "application/octet-stream")[:128], tamano_bytes=len(original),
                    sha256=sha, subido_por_id=usuario.id, etapa=exp.estado, contenido=almacenado, cifrado=cifrado,
                    clave_doc_id=clave_id)
    sesion.add(doc)
    sesion.flush()
    registrar_evento(sesion, actor=usuario, accion="documento_registrado", entidad_tipo="documento", entidad_id=doc.id,
                     datos={"expediente_id": exp.id, "nombre": doc.nombre, "sha256": sha, "tamano_bytes": len(original),
                            "cifrado": cifrado, "clave_doc_id": clave_id})
    sesion.commit()
    return doc


@router.get("/documentos/{documento_id}/contenido", response_class=Response,
            responses={200: {"content": {"application/octet-stream": {}}, "description": "Contenido original"}})
def descargar_documento(documento_id: int, usuario: UsuarioDep, sesion: SesionDep, cfg: CfgDep) -> Response:
    """Devuelve el contenido ORIGINAL (descifrado si procede) tras comprobar su huella SHA-256."""
    doc = sesion.get(Documento, documento_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Documento no encontrado.")
    cargar_expediente(sesion, usuario, doc.expediente_id)
    if doc.contenido is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "Este documento se registró solo por su huella SHA-256 (v0.1/v0.2): no hay contenido almacenado.")
    contenido = doc.contenido
    if doc.cifrado:
        if not cfg.doc_encryption_key:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "El documento está cifrado y no hay clave de descifrado configurada.")
        if doc.clave_doc_id and doc.clave_doc_id != identificador_clave(cfg.doc_encryption_key):
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                                "El documento se cifró con otra clave (rotación pendiente): no se puede descifrar.")
        try:
            contenido = descifrar_documento(contenido, cfg.doc_encryption_key)
        except DocumentoCifradoError as exc:
            log.error("Fallo al descifrar el documento %s: %s", doc.id, exc)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                "No se pudo descifrar el documento: contenido alterado o clave incorrecta.") from exc
    if hashlib.sha256(contenido).hexdigest() != doc.sha256:
        log.error("La huella SHA-256 del documento %s no coincide con la registrada.", doc.id)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            "Integridad comprometida: el contenido no coincide con la huella SHA-256 registrada.")
    registrar_evento(sesion, actor=usuario, accion="documento_descargado", entidad_tipo="documento", entidad_id=doc.id,
                     datos={"expediente_id": doc.expediente_id, "sha256": doc.sha256, "cifrado": doc.cifrado})
    sesion.commit()
    nombre_seguro = "".join(c if c.isalnum() or c in "._-" else "_" for c in doc.nombre) or "documento"
    return Response(content=contenido, media_type=doc.tipo_mime,
                    headers={"Content-Disposition": f'attachment; filename="{nombre_seguro}"', "X-NGFS-SHA256": doc.sha256})


@router.get("/expedientes/{expediente_id}/documentos", response_model=list[DocumentoSalida])
def listar_documentos(expediente_id: int, usuario: UsuarioDep, sesion: SesionDep) -> list[Documento]:
    exp = cargar_expediente(sesion, usuario, expediente_id)
    return list(sesion.execute(select(Documento).where(Documento.expediente_id == exp.id).order_by(Documento.id)).scalars())


@router.post("/documentos/{documento_id}/verificar", response_model=VerificacionDocumento)
def verificar_documento(documento_id: int, archivo: UploadFile, usuario: UsuarioDep, sesion: SesionDep,
                        cfg: CfgDep) -> VerificacionDocumento:
    doc = sesion.get(Documento, documento_id)
    if doc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Documento no encontrado.")
    cargar_expediente(sesion, usuario, doc.expediente_id)
    sha, _ = _hash_archivo(archivo, cfg.max_tamano_documento_mb * 1024 * 1024)
    return VerificacionDocumento(documento_id=doc.id, coincide=sha == doc.sha256,
                                 sha256_registrado=doc.sha256, sha256_recibido=sha)


@router.post("/expedientes/{expediente_id}/analisis-uasi", response_model=AnalisisSalida, status_code=201, tags=["uasi"])
def solicitar_analisis_uasi(expediente_id: int, usuario: UsuarioDep, sesion: SesionDep,
                            uasi: Annotated[AdaptadorUASI, Depends(obtener_uasi)]) -> AnalisisConsultivo:
    exp = cargar_expediente(sesion, usuario, expediente_id, rbac.CONSULTAR_UASI)
    docs = sesion.execute(select(Documento.sha256).where(Documento.expediente_id == exp.id)).scalars().all()
    resumen: dict[str, Any] = {"codigo": exp.codigo, "titulo": exp.titulo, "descripcion": exp.descripcion,
                               "monto_solicitado": str(exp.monto_solicitado) if exp.monto_solicitado is not None else None,
                               "moneda": exp.moneda, "estado": exp.estado, "documentos_sha256": list(docs)}
    estado_previo = exp.estado
    resultado = uasi.analizar(resumen)
    if exp.estado != estado_previo:  # salvaguarda: el adaptador nunca puede alterar estados
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Violación de aislamiento del adaptador UASI.")
    analisis = AnalisisConsultivo(expediente_id=exp.id, solicitado_por_id=usuario.id, disponible=resultado.disponible,
                                  resultado=resultado.como_dict())
    sesion.add(analisis)
    sesion.flush()
    registrar_evento(sesion, actor=usuario, accion="uasi_consulta", entidad_tipo="expediente", entidad_id=exp.id,
                     datos={"analisis_id": analisis.id, "disponible": resultado.disponible, "motivo": resultado.motivo})
    sesion.commit()
    return analisis


@router.get("/expedientes/{expediente_id}/analisis-uasi", response_model=list[AnalisisSalida], tags=["uasi"])
def listar_analisis(expediente_id: int, usuario: UsuarioDep, sesion: SesionDep) -> list[AnalisisConsultivo]:
    exp = cargar_expediente(sesion, usuario, expediente_id)
    consulta = select(AnalisisConsultivo).where(AnalisisConsultivo.expediente_id == exp.id).order_by(AnalisisConsultivo.id)
    return list(sesion.execute(consulta).scalars())
