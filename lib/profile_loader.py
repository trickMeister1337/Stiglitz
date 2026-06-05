#!/usr/bin/env python3
"""
profile_loader.py — Valida um perfil JSON e emite assignments bash.

Schema (mínimo viável):
{
  "name": "engagement-xyz",   # opcional — sobrescreve $PROFILE
  "description": "...",       # opcional — apenas documentação
  "sqlmap": {                 # opcional
    "level": 1..5,
    "risk":  1..3,
    "threads": int,
    "techniques": "BEU"|"BEUT"|"BEUSTQ"|...,   # opcional
    "dump": bool                                # informativo (sqli.sh decide por perfil)
  },
  "msf_payload": "NONE"|"<msf payload>",
  "brute_force":   bool,
  "nikto_enabled": bool,
  "xss_workers":   int,
  "recon_threads": int,
  "crawl_depth":   int,
  "max_exploits":  int,
  "timeouts": {
    "sqlmap_url": int, "sqlmap_crawl": int,
    "msf": int, "hydra": int, "nikto": int,
    "xss": int, "crawl": int, "nmap": int
  }
}

Uso:
    python3 lib/profile_loader.py engagement.json staging   # -p ativo
    # imprime, em stdout, linhas bash do tipo:
    #   PROFILE_SQLMAP_LEVEL[staging]=3
    #   PROFILE_BRUTE_FORCE[staging]=false
    #   ...
    # Exit 0 OK, exit 1 erro (mensagem em stderr).
"""
import json
import re
import sys


_VALID_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]{0,40}$")


def _err(msg):
    print(f"profile_loader: {msg}", file=sys.stderr)
    sys.exit(1)


def _bool_to_bash(v):
    if not isinstance(v, bool):
        raise ValueError(f"esperado bool, recebido {type(v).__name__}: {v!r}")
    return "true" if v else "false"


def _int(name, v, lo=None, hi=None):
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{name}: esperado inteiro, recebido {v!r}")
    if lo is not None and v < lo:
        raise ValueError(f"{name}: {v} < {lo}")
    if hi is not None and v > hi:
        raise ValueError(f"{name}: {v} > {hi}")
    return v


def _str(name, v, allowed=None):
    if not isinstance(v, str):
        raise ValueError(f"{name}: esperado string, recebido {v!r}")
    if allowed is not None and v not in allowed:
        raise ValueError(f"{name}: '{v}' não está em {allowed}")
    return v


def validate(data):
    """Valida estrutura. Levanta ValueError; retorna dict normalizado."""
    if not isinstance(data, dict):
        raise ValueError("raiz deve ser um objeto JSON")

    out = {}
    if "name" in data:
        name = _str("name", data["name"])
        if not _VALID_NAME.match(name):
            raise ValueError(f"name '{name}' inválido (use [a-zA-Z][a-zA-Z0-9._-]*)")
        out["name"] = name

    sqlmap = data.get("sqlmap") or {}
    if not isinstance(sqlmap, dict):
        raise ValueError("sqlmap: esperado objeto")
    if "level" in sqlmap:
        out["sqlmap_level"]   = _int("sqlmap.level",   sqlmap["level"], 1, 5)
    if "risk" in sqlmap:
        out["sqlmap_risk"]    = _int("sqlmap.risk",    sqlmap["risk"],  1, 3)
    if "threads" in sqlmap:
        out["sqlmap_threads"] = _int("sqlmap.threads", sqlmap["threads"], 1, 50)
    if "techniques" in sqlmap:
        out["sqlmap_techniques"] = _str(
            "sqlmap.techniques", sqlmap["techniques"],
            allowed={"B", "E", "U", "S", "T", "Q",
                     "BEU", "BEUT", "BEUST", "BEUSTQ", "BUST"})

    if "msf_payload" in data:
        out["msf_payload"] = _str("msf_payload", data["msf_payload"])
    if "brute_force" in data:
        out["brute_force"] = bool(data["brute_force"])
        if not isinstance(data["brute_force"], bool):
            raise ValueError("brute_force: esperado bool")
    if "nikto_enabled" in data:
        if not isinstance(data["nikto_enabled"], bool):
            raise ValueError("nikto_enabled: esperado bool")
        out["nikto_enabled"] = data["nikto_enabled"]
    if "xss_workers" in data:
        out["xss_workers"] = _int("xss_workers", data["xss_workers"], 1, 50)
    if "recon_threads" in data:
        out["recon_threads"] = _int("recon_threads", data["recon_threads"], 1, 500)
    if "crawl_depth" in data:
        out["crawl_depth"] = _int("crawl_depth", data["crawl_depth"], 1, 10)
    if "max_exploits" in data:
        out["max_exploits"] = _int("max_exploits", data["max_exploits"], 1, 9999)

    timeouts = data.get("timeouts") or {}
    if not isinstance(timeouts, dict):
        raise ValueError("timeouts: esperado objeto")
    _TKEYS = {"sqlmap_url", "sqlmap_crawl", "msf", "hydra",
              "nikto", "xss", "crawl", "nmap"}
    for tk in _TKEYS:
        if tk in timeouts:
            out[f"timeout_{tk}"] = _int(f"timeouts.{tk}", timeouts[tk], 1, 86400)
    extra = set(timeouts) - _TKEYS
    if extra:
        raise ValueError(f"timeouts: chaves desconhecidas: {sorted(extra)}")

    return out


# Mapa interno → nome do array bash em lib/profiles.conf
_BASH_ARRAY = {
    "sqlmap_level":      "PROFILE_SQLMAP_LEVEL",
    "sqlmap_risk":       "PROFILE_SQLMAP_RISK",
    "sqlmap_threads":    "PROFILE_SQLMAP_THREADS",
    "sqlmap_techniques": "PROFILE_SQLMAP_TECHNIQUES",  # novo array
    "msf_payload":       "PROFILE_MSF_PAYLOAD",
    "brute_force":       "PROFILE_BRUTE_FORCE",
    "nikto_enabled":     "PROFILE_NIKTO_ENABLED",
    "xss_workers":       "PROFILE_XSS_WORKERS",
    "recon_threads":     "PROFILE_RECON_THREADS",
    "crawl_depth":       "PROFILE_CRAWL_DEPTH",
    "max_exploits":      "PROFILE_MAX_EXPLOITS",
    "timeout_sqlmap_url":   "PROFILE_TIMEOUT_SQLMAP_URL",
    "timeout_sqlmap_crawl": "PROFILE_TIMEOUT_SQLMAP_CRAWL",
    "timeout_msf":          "PROFILE_TIMEOUT_MSF",
    "timeout_hydra":        "PROFILE_TIMEOUT_HYDRA",
    "timeout_nikto":        "PROFILE_TIMEOUT_NIKTO",
    "timeout_xss":          "PROFILE_TIMEOUT_XSS",
    "timeout_crawl":        "PROFILE_TIMEOUT_CRAWL",
    "timeout_nmap":         "PROFILE_TIMEOUT_NMAP",
}


def emit_bash(out, profile_key):
    """Gera as linhas bash para serem `eval`ed pelo orquestrador.

    O nome ativo do perfil vem do CLI (`-p`); `name` no JSON é apenas
    documentação. Cada chave válida vira:
        declare -gA PROFILE_X
        PROFILE_X["<profile_key>"]=value
    O `declare -gA` é idempotente e garante que o array é associativo
    (importante para perfis customizados com nomes que contenham '-' —
    em arrays indexados, bash trataria 'eng-custom' como aritmética).
    """
    lines = []
    declared = set()
    for k, v in out.items():
        if k == "name":
            continue
        arr = _BASH_ARRAY.get(k)
        if not arr:
            continue
        if arr not in declared:
            lines.append(f"declare -gA {arr}")
            declared.add(arr)
        if isinstance(v, bool):
            v_repr = "true" if v else "false"
        else:
            v_repr = str(v)
        # Aspas em torno da chave evitam expansão aritmética.
        lines.append(f'{arr}["{profile_key}"]="{v_repr}"')
    return "\n".join(lines)


def main():
    if len(sys.argv) != 3:
        _err("uso: profile_loader.py <profile.json> <profile_key>")
    path, key = sys.argv[1], sys.argv[2]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        _err(f"falha ao carregar {path}: {e}")
        return
    try:
        out = validate(data)
    except ValueError as e:
        _err(str(e))
        return
    print(emit_bash(out, key))


if __name__ == "__main__":
    main()
