"""Linha de comando: header-audit https://meusite.com.br [--markdown relatorio.md] [--json]"""

from __future__ import annotations

import argparse
import datetime as dt
import sys

from . import __version__
from .checks import avaliar
from .fetch import buscar
from .report import em_json, markdown, texto


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="header-audit",
        description="Confere os cabeçalhos de segurança HTTP e o certificado TLS de um site. "
                    "Use só em sites seus ou que você tem permissão para avaliar.")
    parser.add_argument("urls", nargs="+", help="um ou mais endereços (https:// é colocado se faltar)")
    parser.add_argument("--markdown", metavar="ARQUIVO", help="salva um relatório em Markdown")
    parser.add_argument("--json", action="store_true", help="imprime o resultado em JSON")
    parser.add_argument("--timeout", type=float, default=10, help="segundos de espera por resposta (padrão 10)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    # No Windows, a saída redirecionada usa cp1252 e estraga os acentos
    for fluxo in (sys.stdout, sys.stderr):
        if hasattr(fluxo, "reconfigure"):
            fluxo.reconfigure(encoding="utf-8", errors="replace")

    resultados = []
    teve_falha = False
    for url in args.urls:
        try:
            resposta = buscar(url, timeout=args.timeout)
        except (OSError, ValueError, RuntimeError) as erro:
            print(f"{url}: não foi possível acessar ({erro})", file=sys.stderr)
            teve_falha = True
            continue
        achados = avaliar(resposta.headers, resposta.url_final, resposta.http_redireciona,
                          resposta.dias_certificado, resposta.erro_certificado)
        resultados.append((resposta.url_final, achados))
        teve_falha = teve_falha or any(a.status == "falha" for a in achados)
        if not args.json:
            print(texto(resposta.url_final, achados), end="\n\n")

    if args.json:
        print(em_json(resultados))
    if args.markdown and resultados:
        with open(args.markdown, "w", encoding="utf-8") as arquivo:
            arquivo.write(markdown(resultados, dt.date.today().isoformat()))
        print(f"Relatório salvo em {args.markdown}", file=sys.stderr)
    return 1 if teve_falha else 0


if __name__ == "__main__":
    sys.exit(main())
