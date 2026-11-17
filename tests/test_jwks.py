"""Fase 4 — tokens JWT firmados con RS256 y publicación JWKS (AC-19)."""

from __future__ import annotations

import stat
from pathlib import Path

import jwt
import pytest

from conftest import Entorno, cfg_pruebas
from ngfs.crypto.claves_jwt import ClavesJWTError, preparar_claves_rsa
from ngfs.estados import Rol


def _entorno_rsa(tmp_path: Path) -> Entorno:
    cfg = cfg_pruebas(jwt_private_key_path=str(tmp_path / "claves" / "jwt_priv.pem"),
                      jwt_public_key_path=str(tmp_path / "claves" / "jwt_pub.pem"))
    e = Entorno(cfg)
    e.usuario("sol", Rol.SOLICITANTE)
    return e


def test_endpoint_jwks_retorna_clave_publica(tmp_path: Path) -> None:
    e = _entorno_rsa(tmp_path)
    privada = tmp_path / "claves" / "jwt_priv.pem"
    assert privada.exists() and (tmp_path / "claves" / "jwt_pub.pem").exists()  # generadas al arrancar
    assert stat.S_IMODE(privada.stat().st_mode) == 0o600
    r = e.cliente.get("/auth/jwks")
    assert r.status_code == 200
    claves = r.json()["keys"]
    assert len(claves) == 1
    k = claves[0]
    assert k["kty"] == "RSA" and k["alg"] == "RS256" and k["use"] == "sig" and k["e"] == "AQAB" and k["kid"]
    assert "d" not in k and "p" not in k  # nunca se publica material privado
    # Un segundo arranque reutiliza el mismo par de claves
    assert _entorno_rsa(tmp_path).cliente.get("/auth/jwks").json()["keys"][0]["kid"] == k["kid"]


def test_token_rs256_verificable_con_jwks(tmp_path: Path) -> None:
    e = _entorno_rsa(tmp_path)
    token = e.login("sol").json()["access_token"]
    cabecera = jwt.get_unverified_header(token)
    assert cabecera["alg"] == "RS256"
    jwk = next(k for k in e.cliente.get("/auth/jwks").json()["keys"] if k["kid"] == cabecera["kid"])
    publica = jwt.PyJWK.from_dict(jwk).key
    claims = jwt.decode(token, publica, algorithms=["RS256"])
    assert claims["usr"] == "sol" and claims["tipo"] == "humano"
    assert e.cliente.get("/auth/yo", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    # Un token HS256 firmado con el secreto compartido ya no se acepta cuando RS256 está activo
    falso = jwt.encode({**claims, "exp": claims["exp"]}, "x" * 40, algorithm="HS256")
    assert e.cliente.get("/auth/yo", headers={"Authorization": f"Bearer {falso}"}).status_code == 401


def test_retrocompatibilidad_hs256_sin_claves(env: Entorno) -> None:
    assert env.cliente.get("/auth/jwks").json() == {"keys": []}
    token = env.login("sol").json()["access_token"]
    assert jwt.get_unverified_header(token)["alg"] == "HS256"
    assert env.cliente.get("/auth/yo", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_configuracion_claves_incoherente(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="a la vez"):
        cfg_pruebas(jwt_private_key_path=str(tmp_path / "solo_priv.pem"))
    publica_huerfana = tmp_path / "pub.pem"
    publica_huerfana.write_text("x")
    with pytest.raises(ClavesJWTError):
        preparar_claves_rsa(tmp_path / "priv.pem", publica_huerfana)
