#!/usr/bin/env python3
"""httpx_parse.py — parsing estruturado da saída JSON (-json) do httpx.

Motivação (Bug #1): a Fase 2 emitia o output TEXTO do httpx (`url [status]
[title] [tech]`) e o tech_profile tratava QUALQUER token entre colchetes como
"tecnologia" — então o título HTTP (`Not Found`) e a flag `HSTS` viravam techs
high-confidence, poluindo o inventário e impedindo a detecção do framework real
(Django) → scan adaptativo enfraquecido.

A saída `-json` separa `title`, `tech` (array) e `webserver`. Este módulo:
- `parse_jsonl` lê o JSONL do httpx (tolerante a linhas inválidas);
- `tech_inventory` deriva o inventário SÓ de `tech`+`webserver` (nunca `title`);
- `to_legacy_text`/`to_legacy_line` regeneram o `httpx_results.txt` legado que os
  demais consumidores (1ª coluna = URL; grep de edge CDN/LB) ainda esperam.

Lógica pura + CLI (`to-txt <jsonl>`); sem rede.
"""
import json
import sys


def parse_jsonl(text):
    """Lista de registros do JSONL do httpx. Ignora linhas vazias/inválidas."""
    records = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except (ValueError, TypeError):
            continue
    return records


def _split_name_version(token):
    """`Nginx:1.18.0` -> (`Nginx`, `1.18.0`); `Django` -> (`Django`, '')."""
    if ":" in token:
        name, _, ver = token.partition(":")
        return name.strip(), ver.strip()
    return token.strip(), ""


def tech_inventory(records):
    """Inventário {tech: {version, source, confidence}} de `tech`+`webserver`.

    Nunca inclui `title` — essa é exatamente a fonte do FP do Bug #1.
    """
    inv = {}
    seen = {}  # nome-lowercase -> chave canônica em inv (dedup case-insensitive)

    def _add(name, ver):
        if not name:
            return
        key = seen.get(name.lower())
        if key is None:
            inv[name] = {"version": ver, "source": "httpx", "confidence": "high"}
            seen[name.lower()] = name
        elif ver and not inv[key].get("version"):
            inv[key]["version"] = ver

    for rec in records:
        # tech array primeiro: sua forma capitalizada vence sobre o webserver.
        for token in (rec.get("tech") or []):
            _add(*_split_name_version(token))
        ws = rec.get("webserver")
        if ws:
            _add(*_split_name_version(ws))
    return inv


def to_legacy_line(rec):
    """Linha no formato texto legado: `url [status] [title] [tech] [webserver] [cdn]`.

    Preserva URL na 1ª coluna (consumido por security_headers/openapi_discover) e
    inclui tech/webserver/cdn como tokens para o grep de edge (CDN/LB) do stiglitz.sh.
    """
    parts = [rec.get("url") or rec.get("input") or ""]
    sc = rec.get("status_code")
    if sc is not None:
        parts.append(f"[{sc}]")
    title = rec.get("title")
    if title:
        parts.append(f"[{title}]")
    techs = rec.get("tech") or []
    if techs:
        parts.append("[" + ",".join(str(t) for t in techs) + "]")
    ws = rec.get("webserver")
    if ws:
        parts.append(f"[{ws}]")
    cdn = rec.get("cdn_name")
    if cdn:
        parts.append(f"[{cdn}]")
    return " ".join(parts)


def to_legacy_text(jsonl_text):
    """Converte o JSONL inteiro no texto legado (uma linha por registro)."""
    return "\n".join(to_legacy_line(r) for r in parse_jsonl(jsonl_text))


def _main(argv):
    if len(argv) >= 2 and argv[0] == "to-txt":
        try:
            with open(argv[1], encoding="utf-8", errors="replace") as fh:
                sys.stdout.write(to_legacy_text(fh.read()) + "\n")
        except OSError:
            pass
        return 0
    sys.stderr.write("uso: httpx_parse.py to-txt <httpx.jsonl>\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
