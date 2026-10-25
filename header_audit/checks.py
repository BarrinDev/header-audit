"""Regras que avaliam os cabeçalhos de segurança de uma resposta HTTP.

Cada função recebe os cabeçalhos já normalizados (nome em minúsculas -> lista de
valores) e devolve uma lista de achados. Nada aqui acessa a rede, então tudo pode
ser testado com cabeçalhos de exemplo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

Headers = dict[str, list[str]]

OK, INFO, AVISO, FALHA = "ok", "info", "aviso", "falha"
ORDEM = {FALHA: 0, AVISO: 1, INFO: 2, OK: 3}
PENALIDADE = {FALHA: 20, AVISO: 8, INFO: 2, OK: 0}

SEIS_MESES = 15_552_000  # segundos; mínimo recomendado para o max-age do HSTS


@dataclass
class Achado:
    regra: str
    titulo: str
    status: str
    detalhe: str
    correcao: str = ""


def _primeiro(headers: Headers, nome: str) -> str | None:
    valores = headers.get(nome.lower())
    return valores[0].strip() if valores else None


def _diretivas_csp(csp: str) -> dict[str, list[str]]:
    diretivas: dict[str, list[str]] = {}
    for parte in csp.split(";"):
        tokens = parte.strip().split()
        if tokens:
            diretivas[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return diretivas


def verificar_https(url_final: str, http_redireciona: bool | None) -> list[Achado]:
    titulo = "HTTPS"
    if not url_final.startswith("https://"):
        return [Achado("https", titulo, FALHA, "O site termina em HTTP, sem criptografia.",
                       "Sirva o site por HTTPS e redirecione todo acesso HTTP para ele.")]
    if http_redireciona is False:
        return [Achado("https", titulo, AVISO, "O endereço HTTP responde sem redirecionar para HTTPS.",
                       "Configure um redirecionamento 301 de http:// para https://.")]
    if http_redireciona is None:
        return [Achado("https", titulo, INFO, "Não foi possível testar o acesso por HTTP (porta 80 fechada ou sem resposta).")]
    return [Achado("https", titulo, OK, "Usa HTTPS e redireciona o HTTP para ele.")]


def verificar_hsts(headers: Headers, https: bool) -> list[Achado]:
    titulo = "Strict-Transport-Security (HSTS)"
    if not https:
        return []
    valor = _primeiro(headers, "strict-transport-security")
    if not valor:
        return [Achado("hsts", titulo, FALHA, "Cabeçalho ausente: o navegador aceita voltar para HTTP.",
                       "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    achou = re.search(r"max-age\s*=\s*\"?(\d+)", valor, re.IGNORECASE)
    max_age = int(achou.group(1)) if achou else 0
    if max_age < SEIS_MESES:
        return [Achado("hsts", titulo, AVISO, f"max-age={max_age} é curto (menos de seis meses).",
                       "Use max-age de pelo menos 15552000; o comum é 31536000 (um ano).")]
    if "includesubdomains" not in valor.lower():
        return [Achado("hsts", titulo, INFO, f"max-age={max_age}, sem includeSubDomains.",
                       "Se todos os subdomínios usam HTTPS, acrescente includeSubDomains.")]
    return [Achado("hsts", titulo, OK, f"max-age={max_age} com includeSubDomains.")]


def verificar_csp(headers: Headers) -> list[Achado]:
    titulo = "Content-Security-Policy (CSP)"
    csp = _primeiro(headers, "content-security-policy")
    if not csp:
        if _primeiro(headers, "content-security-policy-report-only"):
            return [Achado("csp", titulo, AVISO, "A política existe só em modo relatório; nada é bloqueado.",
                           "Depois de revisar os relatórios, publique a mesma política em Content-Security-Policy.")]
        return [Achado("csp", titulo, FALHA, "Cabeçalho ausente: nada limita de onde vêm scripts e estilos.",
                       "Comece por: Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'")]
    diretivas = _diretivas_csp(csp)
    scripts = diretivas.get("script-src", diretivas.get("default-src"))
    if scripts is None:
        return [Achado("csp", titulo, AVISO, "A política não tem default-src nem script-src, então scripts continuam liberados.",
                       "Inclua default-src 'self' ou um script-src explícito.")]
    problemas = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in scripts]
    if "*" in scripts or "https:" in scripts:
        problemas.append("origem curinga (* ou https:)")
    if problemas:
        return [Achado("csp", titulo, AVISO, "A fonte de scripts aceita " + ", ".join(problemas) + ".",
                       "Troque scripts inline por arquivos ou por nonce/hash e remova curingas.")]
    return [Achado("csp", titulo, OK, "Política presente e sem liberações amplas para scripts.")]


def verificar_frames(headers: Headers) -> list[Achado]:
    titulo = "Proteção contra clickjacking"
    xfo = (_primeiro(headers, "x-frame-options") or "").upper()
    csp = _diretivas_csp(_primeiro(headers, "content-security-policy") or "")
    if "frame-ancestors" in csp:
        return [Achado("frames", titulo, OK, "CSP define frame-ancestors.")]
    if xfo in ("DENY", "SAMEORIGIN"):
        return [Achado("frames", titulo, OK, f"X-Frame-Options: {xfo}.")]
    return [Achado("frames", titulo, FALHA, "O site pode ser carregado dentro de um iframe de outro domínio.",
                   "Adicione X-Frame-Options: SAMEORIGIN ou a diretiva CSP frame-ancestors 'self'.")]


def verificar_nosniff(headers: Headers) -> list[Achado]:
    titulo = "X-Content-Type-Options"
    if (_primeiro(headers, "x-content-type-options") or "").lower() == "nosniff":
        return [Achado("nosniff", titulo, OK, "nosniff ativado.")]
    return [Achado("nosniff", titulo, AVISO, "O navegador pode adivinhar o tipo do arquivo (MIME sniffing).",
                   "Adicione: X-Content-Type-Options: nosniff")]


def verificar_referrer(headers: Headers) -> list[Achado]:
    titulo = "Referrer-Policy"
    valor = (_primeiro(headers, "referrer-policy") or "").lower()
    if not valor:
        return [Achado("referrer", titulo, AVISO, "Cabeçalho ausente; vale o padrão do navegador.",
                       "Adicione: Referrer-Policy: strict-origin-when-cross-origin")]
    if valor in ("unsafe-url", "no-referrer-when-downgrade"):
        return [Achado("referrer", titulo, AVISO, f"'{valor}' envia o endereço completo para outros sites.",
                       "Use strict-origin-when-cross-origin ou no-referrer.")]
    return [Achado("referrer", titulo, OK, valor)]


def verificar_permissions(headers: Headers) -> list[Achado]:
    titulo = "Permissions-Policy"
    if _primeiro(headers, "permissions-policy"):
        return [Achado("permissions", titulo, OK, "Política de recursos do navegador definida.")]
    return [Achado("permissions", titulo, INFO, "Cabeçalho ausente; câmera, microfone e localização ficam no padrão.",
                   "Desligue o que o site não usa, por exemplo: Permissions-Policy: camera=(), microphone=(), geolocation=()")]


def verificar_exposicao(headers: Headers) -> list[Achado]:
    achados = []
    servidor = _primeiro(headers, "server")
    if servidor and re.search(r"\d", servidor):
        achados.append(Achado("exposicao", "Versão do servidor exposta", AVISO,
                              f"Server: {servidor}",
                              "Esconda a versão (no nginx: server_tokens off; no Apache: ServerTokens Prod)."))
    for nome in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        valor = _primeiro(headers, nome)
        if valor:
            achados.append(Achado("exposicao", "Tecnologia exposta", AVISO, f"{nome}: {valor}",
                                  f"Remova o cabeçalho {nome}; ele ajuda quem procura falhas conhecidas."))
    if not achados:
        achados.append(Achado("exposicao", "Exposição de versões", OK, "Nenhuma versão de software nos cabeçalhos."))
    return achados


def verificar_cookies(headers: Headers, https: bool) -> list[Achado]:
    achados = []
    for cookie in headers.get("set-cookie", []):
        nome = cookie.split("=", 1)[0].strip()
        atributos = [a.strip().lower() for a in cookie.split(";")[1:]]
        faltando = []
        if https and "secure" not in atributos:
            faltando.append("Secure")
        if "httponly" not in atributos:
            faltando.append("HttpOnly")
        if not any(a.startswith("samesite") for a in atributos):
            faltando.append("SameSite")
        if faltando:
            status = AVISO if "Secure" in faltando or "HttpOnly" in faltando else INFO
            achados.append(Achado("cookies", f"Cookie {nome}", status, "Sem " + ", ".join(faltando) + ".",
                                  "Defina Secure; HttpOnly; SameSite=Lax (HttpOnly só se o JavaScript não precisar ler o cookie)."))
        else:
            achados.append(Achado("cookies", f"Cookie {nome}", OK, "Secure, HttpOnly e SameSite definidos."))
    return achados


def verificar_certificado(dias_restantes: int | None, erro: str | None) -> list[Achado]:
    titulo = "Certificado TLS"
    if erro:
        return [Achado("certificado", titulo, FALHA, f"Certificado rejeitado: {erro}",
                       "Renove ou corrija o certificado (Let's Encrypt resolve de graça).")]
    if dias_restantes is None:
        return []
    if dias_restantes < 0:
        return [Achado("certificado", titulo, FALHA, f"Vencido há {-dias_restantes} dias.", "Renove o certificado.")]
    if dias_restantes < 30:
        return [Achado("certificado", titulo, AVISO, f"Vence em {dias_restantes} dias.",
                       "Renove agora e automatize a renovação.")]
    return [Achado("certificado", titulo, OK, f"Válido por mais {dias_restantes} dias.")]


def avaliar(headers: Headers, url_final: str, http_redireciona: bool | None = None,
            dias_certificado: int | None = None, erro_certificado: str | None = None) -> list[Achado]:
    """Roda todas as regras e devolve os achados do mais grave para o mais leve."""
    https = url_final.startswith("https://")
    achados = (
        verificar_https(url_final, http_redireciona)
        + verificar_certificado(dias_certificado, erro_certificado)
        + verificar_hsts(headers, https)
        + verificar_csp(headers)
        + verificar_frames(headers)
        + verificar_nosniff(headers)
        + verificar_referrer(headers)
        + verificar_permissions(headers)
        + verificar_exposicao(headers)
        + verificar_cookies(headers, https)
    )
    return sorted(achados, key=lambda a: ORDEM[a.status])


def nota(achados: list[Achado]) -> tuple[int, str]:
    """Pontuação própria deste projeto: começa em 100 e perde pontos por achado."""
    pontos = max(0, 100 - sum(PENALIDADE[a.status] for a in achados))
    for minimo, letra in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if pontos >= minimo:
            return pontos, letra
    return pontos, "F"
