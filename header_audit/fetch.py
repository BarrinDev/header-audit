"""Acesso à rede: uma requisição GET por endereço, seguindo redirecionamentos.

Só lê os cabeçalhos da resposta (o corpo da página não é baixado) e consulta o
certificado TLS. É o mesmo tráfego de um navegador abrindo a página uma vez.
"""

from __future__ import annotations

import datetime as dt
import http.client
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field

from .checks import Headers

USER_AGENT = "header-audit/1.0 (+https://github.com/BarrinDev/header-audit)"
REDIRECIONAMENTOS = {301, 302, 303, 307, 308}


@dataclass
class Resposta:
    url_pedida: str
    url_final: str
    status: int
    headers: Headers
    caminho: list[str] = field(default_factory=list)
    http_redireciona: bool | None = None
    dias_certificado: int | None = None
    erro_certificado: str | None = None


def normalizar(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    partes = urllib.parse.urlsplit(url)
    if partes.scheme not in ("http", "https") or not partes.hostname:
        raise ValueError(f"Endereço inválido: {url}")
    return url


def _get(url: str, timeout: float) -> tuple[int, Headers]:
    partes = urllib.parse.urlsplit(url)
    caminho = (partes.path or "/") + (f"?{partes.query}" if partes.query else "")
    if partes.scheme == "https":
        conexao = http.client.HTTPSConnection(partes.hostname, partes.port or 443, timeout=timeout,
                                              context=ssl.create_default_context())
    else:
        conexao = http.client.HTTPConnection(partes.hostname, partes.port or 80, timeout=timeout)
    try:
        conexao.request("GET", caminho, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*"})
        resposta = conexao.getresponse()
        headers: Headers = {}
        for nome, valor in resposta.getheaders():
            headers.setdefault(nome.lower(), []).append(valor)
        return resposta.status, headers
    finally:
        conexao.close()


def _dias_certificado(host: str, porta: int, timeout: float) -> tuple[int | None, str | None]:
    try:
        with socket.create_connection((host, porta), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                certificado = tls.getpeercert()
    except ssl.SSLCertVerificationError as erro:
        return None, erro.verify_message or str(erro)
    except (OSError, ssl.SSLError):
        return None, None
    vence = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(certificado["notAfter"]), tz=dt.timezone.utc)
    return (vence - dt.datetime.now(dt.timezone.utc)).days, None


def _http_redireciona_para_https(host: str, timeout: float) -> bool | None:
    try:
        status, headers = _get(f"http://{host}/", timeout)
    except OSError:
        return None
    destino = (headers.get("location") or [""])[0]
    return status in REDIRECIONAMENTOS and destino.startswith("https://")


def buscar(url: str, timeout: float = 10, max_redirecionamentos: int = 5) -> Resposta:
    """Faz a requisição, segue redirecionamentos e reúne o que as regras precisam."""
    pedida = normalizar(url)
    atual = pedida
    caminho = [atual]
    for _ in range(max_redirecionamentos + 1):
        status, headers = _get(atual, timeout)
        destino = (headers.get("location") or [None])[0]
        if status not in REDIRECIONAMENTOS or not destino:
            break
        atual = urllib.parse.urljoin(atual, destino)
        caminho.append(atual)
    else:
        raise RuntimeError(f"Mais de {max_redirecionamentos} redirecionamentos a partir de {pedida}")

    resposta = Resposta(pedida, atual, status, headers, caminho)
    partes = urllib.parse.urlsplit(atual)
    if partes.scheme == "https":
        resposta.dias_certificado, resposta.erro_certificado = _dias_certificado(
            partes.hostname, partes.port or 443, timeout)
        if pedida.startswith("https://"):
            resposta.http_redireciona = _http_redireciona_para_https(partes.hostname, timeout)
        else:
            resposta.http_redireciona = True
    return resposta
