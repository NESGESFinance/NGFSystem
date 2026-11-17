"""Fase 4 — decisiones colegiadas con quórum y firma HMAC-SHA256 de votos (AC-16, AC-17)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, update

from conftest import Entorno
from ngfs.crypto.firmas import DatosVoto, clave_firmas, firmar_voto, verificar_voto
from ngfs.estados import Rol
from ngfs.modelos import EventoAuditoria, VotacionDecision, VotoIndividual

JUST = "Revisado el expediente completo y conforme."


@pytest.fixture
def envv(env: Entorno) -> Entorno:
    env.usuario("com2", Rol.COMITE)
    env.usuario("com3", Rol.COMITE)
    return env


def _expediente_en_cumplimiento(env: Entorno) -> int:
    exp_id = int(env.crear_expediente()["id"])
    env.llevar_a_cumplimiento(exp_id)
    return exp_id


def _abrir(env: Entorno, exp_id: int, usuario: str = "ana", **extra: Any) -> Any:
    datos = {"transicion_objetivo": "aprobar", **extra}
    return env.cliente.post(f"/expedientes/{exp_id}/votaciones", json=datos, headers=env.h(usuario))


def _votar(env: Entorno, votacion_id: int, usuario: str, decision: str = "FAVOR", confirmacion: bool = True) -> Any:
    return env.cliente.post(f"/votaciones/{votacion_id}/votar", headers=env.h(usuario),
                            json={"decision": decision, "justificacion": JUST, "confirmacion_humana": confirmacion})


def test_crear_votacion(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    r = _abrir(envv, exp_id)
    assert r.status_code == 201, r.text
    v = r.json()
    assert v["estado_votacion"] == "ABIERTA" and v["quorum_requerido"] == 2 and v["transicion_objetivo"] == "aprobar"
    assert v["votos"] == [] and v["conteo"] == {"favor": 0, "contra": 0, "abstencion": 0}
    # Una sola votación abierta por expediente
    assert _abrir(envv, exp_id).status_code == 409
    # El solicitante y el auditor no pueden abrir votaciones
    assert _abrir(envv, exp_id, "aud").status_code == 403
    # Solo transiciones de decisión humana
    otro = int(envv.crear_expediente()["id"])
    envv.llevar_a_cumplimiento(otro)
    assert _abrir(envv, otro, transicion_objetivo="devolver_a_analisis").status_code == 422
    assert _abrir(envv, otro, transicion_objetivo="inexistente").status_code == 409
    # Quórum inalcanzable (solo hay 4 votantes elegibles: com, com2, com3, adm)
    assert _abrir(envv, otro, quorum_requerido=5).status_code == 422
    # Mientras la votación esté abierta, no hay transiciones directas
    r = envv.transicion(exp_id, "com", "aprobar", JUST, confirmacion=True)
    assert r.status_code == 409 and "votación" in r.json()["detail"]


def test_votar_a_favor(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id, quorum_requerido=3).json()["id"]
    r = _votar(envv, vid, "com")
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["conteo"]["favor"] == 1 and v["estado_votacion"] == "ABIERTA"
    assert v["votos"][0]["decision"] == "FAVOR" and len(v["votos"][0]["firma_voto"]) == 64
    # Abstención no cuenta para el quórum
    v = _votar(envv, vid, "com2", "ABSTENCION").json()
    assert v["conteo"] == {"favor": 1, "contra": 0, "abstencion": 1} and v["estado_votacion"] == "ABIERTA"
    # Voto sin confirmación humana o con justificación corta
    assert _votar(envv, vid, "com3", confirmacion=False).status_code == 422
    corta = envv.cliente.post(f"/votaciones/{vid}/votar", headers=envv.h("com3"),
                              json={"decision": "FAVOR", "justificacion": "corta", "confirmacion_humana": True})
    assert corta.status_code == 422
    assert envv.cliente.get(f"/expedientes/{exp_id}", headers=envv.h("com")).json()["estado"] == "revision_cumplimiento"


def test_quorum_dispara_transicion(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id).json()["id"]
    assert _votar(envv, vid, "com", "CONTRA").json()["estado_votacion"] == "ABIERTA"
    assert _votar(envv, vid, "com2").json()["estado_votacion"] == "ABIERTA"
    v = _votar(envv, vid, "adm").json()  # 2 FAVOR = quórum
    assert v["estado_votacion"] == "APROBADA" and v["fecha_cierre_real"] is not None
    exp = envv.cliente.get(f"/expedientes/{exp_id}", headers=envv.h("com")).json()
    assert exp["estado"] == "aprobado"
    hist = envv.cliente.get(f"/expedientes/{exp_id}/historial", headers=envv.h("com")).json()
    assert hist[-1]["accion"] == "aprobar" and hist[-1]["decision_humana"] is True
    assert f"votación #{vid}" in hist[-1]["justificacion"]
    # Bitácora: VOTACION_APROBADA con votantes y hashes de votos, y la cadena sigue íntegra
    with envv.sesion() as s:
        ev = s.execute(select(EventoAuditoria).where(EventoAuditoria.accion == "VOTACION_APROBADA")).scalar_one()
        datos = json.loads(ev.datos)
        assert datos["hacia"] == "aprobado" and len(datos["votantes"]) == 3
        assert all(len(x["hash_voto"]) == 64 for x in datos["votantes"])
    ver = envv.cliente.get("/auditoria/verificar", headers=envv.h("aud")).json()
    assert ver["integra"] is True
    # Votación cerrada: no admite más votos
    assert _votar(envv, vid, "com3").status_code == 409


def test_votos_en_contra_rechazan_votacion_y_cierre_manual(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id).json()["id"]
    _votar(envv, vid, "com", "CONTRA")
    assert _votar(envv, vid, "com2", "CONTRA").json()["estado_votacion"] == "RECHAZADA"
    assert envv.cliente.get(f"/expedientes/{exp_id}", headers=envv.h("com")).json()["estado"] == "revision_cumplimiento"
    # Nueva votación y cierre manual (solo administrador, solo si está ABIERTA)
    vid2 = _abrir(envv, exp_id, "com", transicion_objetivo="rechazar").json()["id"]
    cuerpo = {"justificacion": "Se convoca nueva sesión del comité."}
    assert envv.cliente.post(f"/votaciones/{vid2}/cerrar", json=cuerpo, headers=envv.h("com")).status_code == 403
    r = envv.cliente.post(f"/votaciones/{vid2}/cerrar", json=cuerpo, headers=envv.h("adm"))
    assert r.status_code == 200 and r.json()["estado_votacion"] == "RECHAZADA"
    assert envv.cliente.post(f"/votaciones/{vid2}/cerrar", json=cuerpo, headers=envv.h("adm")).status_code == 409


def test_votacion_expira(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id, duracion_horas=1).json()["id"]
    with envv.sesion() as s:
        s.execute(update(VotacionDecision).where(VotacionDecision.id == vid)
                  .values(fecha_cierre_previsto=datetime.now(UTC) - timedelta(minutes=1)))
        s.commit()
    assert _votar(envv, vid, "com").status_code == 409
    assert envv.cliente.get(f"/votaciones/{vid}", headers=envv.h("aud")).json()["estado_votacion"] == "EXPIRADA"
    assert _abrir(envv, exp_id).status_code == 201  # libera el expediente para una nueva votación


def test_doble_voto_rechazado(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id, quorum_requerido=3).json()["id"]
    assert _votar(envv, vid, "com").status_code == 200
    r = _votar(envv, vid, "com", "CONTRA")
    assert r.status_code == 409
    v = envv.cliente.get(f"/votaciones/{vid}", headers=envv.h("com")).json()
    assert len(v["votos"]) == 1 and v["conteo"]["favor"] == 1


def test_voto_sin_rol_rechazado(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id).json()["id"]
    for usuario in ("ana", "cum", "aud"):
        assert _votar(envv, vid, usuario).status_code == 403, usuario
    # El solicitante no ve el expediente en revisión de otro, pero aunque tuviese rol de voto, sería 403 por segregación
    assert _votar(envv, vid, "sol").status_code == 403
    assert envv.cliente.get("/votaciones/9999", headers=envv.h("com")).status_code == 404


def test_firma_voto_correcta(envv: Entorno) -> None:
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id).json()["id"]
    _votar(envv, vid, "com")
    clave = clave_firmas(envv.app.state.cfg)
    with envv.sesion() as s:
        voto = s.execute(select(VotoIndividual).where(VotoIndividual.votacion_id == vid)).scalar_one()
        datos = DatosVoto(voto.votacion_id, voto.votante_id, voto.decision, voto.timestamp_voto)
        assert voto.firma_voto == firmar_voto(datos, clave)
    v = envv.cliente.get(f"/votaciones/{vid}", headers=envv.h("aud")).json()
    assert v["votos"][0]["verified"] is True


def test_verificacion_firma(envv: Entorno) -> None:
    clave = bytes.fromhex("ab" * 32)
    datos = DatosVoto(1, 7, "FAVOR", datetime(2026, 11, 16, 12, 0, 0, 123456, tzinfo=UTC))
    firma = firmar_voto(datos, clave)
    assert verificar_voto(datos, firma, clave)
    # Fecha sin zona (como la devuelve SQLite) equivale a UTC
    assert verificar_voto(DatosVoto(1, 7, "FAVOR", datetime(2026, 11, 16, 12, 0, 0, 123456)), firma, clave)
    assert not verificar_voto(DatosVoto(1, 7, "CONTRA", datos.timestamp_voto), firma, clave)
    assert not verificar_voto(datos, firma, bytes.fromhex("cd" * 32))
    assert not verificar_voto(datos, None, clave)
    # Manipulación del voto en BD → verified = False en la API
    exp_id = _expediente_en_cumplimiento(envv)
    vid = _abrir(envv, exp_id, quorum_requerido=3).json()["id"]
    _votar(envv, vid, "com")
    with envv.sesion() as s:
        s.execute(update(VotoIndividual).where(VotoIndividual.votacion_id == vid).values(decision="CONTRA"))
        s.commit()
    v = envv.cliente.get(f"/votaciones/{vid}", headers=envv.h("aud")).json()
    assert v["votos"][0]["verified"] is False


def test_clave_firma_configurable() -> None:
    from conftest import cfg_pruebas

    cfg = cfg_pruebas(firma_key="0f" * 32)
    assert clave_firmas(cfg) == bytes.fromhex("0f" * 32)
    assert clave_firmas(cfg_pruebas()) != clave_firmas(cfg)
    with pytest.raises(ValueError, match="32 bytes"):
        cfg_pruebas(firma_key="ab" * 8)
    with pytest.raises(ValueError, match="hexadecimal"):
        cfg_pruebas(firma_key="no-es-hex" * 8)
