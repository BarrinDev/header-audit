"""Transforma os achados em texto para o terminal, Markdown ou JSON."""

from __future__ import annotations

import json
from dataclasses import asdict

from .checks import Achado, nota

ROTULO = {"ok": "OK", "info": "INFO", "aviso": "AVISO", "falha": "FALHA"}


def texto(url: str, achados: list[Achado]) -> str:
    pontos, letra = nota(achados)
    linhas = [f"{url}", f"Nota {letra} ({pontos}/100)", ""]
    for a in achados:
        linhas.append(f"  [{ROTULO[a.status]:5}] {a.titulo}: {a.detalhe}")
        if a.correcao and a.status != "ok":
            linhas.append(f"          Como corrigir: {a.correcao}")
    return "\n".join(linhas)


def markdown(resultados: list[tuple[str, list[Achado]]], data: str) -> str:
    linhas = ["# Relatório de cabeçalhos de segurança", "", f"Gerado em {data} pelo header-audit.", ""]
    for url, achados in resultados:
        pontos, letra = nota(achados)
        linhas += [f"## {url}", "", f"**Nota {letra}** ({pontos}/100)", "",
                   "| Situação | Item | O que foi visto | Como corrigir |", "|---|---|---|---|"]
        for a in achados:
            correcao = a.correcao if a.status != "ok" else ""
            linhas.append(f"| {ROTULO[a.status]} | {a.titulo} | {_md(a.detalhe)} | {_md(correcao)} |")
        linhas.append("")
    return "\n".join(linhas)


def em_json(resultados: list[tuple[str, list[Achado]]]) -> str:
    saida = []
    for url, achados in resultados:
        pontos, letra = nota(achados)
        saida.append({"url": url, "nota": letra, "pontos": pontos, "achados": [asdict(a) for a in achados]})
    return json.dumps(saida, ensure_ascii=False, indent=2)


def _md(texto_celula: str) -> str:
    return texto_celula.replace("|", "\\|")
