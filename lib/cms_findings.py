#!/usr/bin/env python3
"""
cms_findings.py — estrutura achados dos scanners de CMS (Fase 10.5) em findings.

Os scanners wpscan/joomscan/droopescan gravam saída bruta (raw/wpscan.json,
raw/joomscan.txt, raw/droopescan.txt) que, sem este módulo, só virava link de
artefato no apêndice do relatório — as vulnerabilidades detectadas (CVEs de
plugins/temas, itens [!] do joomscan, versão/URLs sensíveis do Drupal) não
chegavam aos findings. Aqui convertemos cada saída para raw/cms_findings.json,
no MESMO formato dos demais *_findings.json, para o stiglitz_report.py agregar
e o cve_enrich.py enriquecer (NVD/EPSS/KEV).

Uso: python3 cms_findings.py <outdir> <target>
"""
import sys
import os
import re
import json

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _cve_list(raw_refs):
    """Normaliza referências de CVE (lista 'YYYY-NNNN' ou já 'CVE-...') → 'CVE-...'."""
    out = []
    for c in raw_refs or []:
        c = str(c).strip().upper()
        if not c:
            continue
        out.append(c if c.startswith("CVE-") else f"CVE-{c}")
    return out


def _cve_str(cves):
    return ", ".join(sorted(set(cves))) if cves else "N/A"


def parse_wpscan(data, target=""):
    """Extrai vulnerabilidades de plugins, temas e core do JSON do wpscan."""
    findings = []

    def _vulns_from(container, kind):
        """container: dict com chave 'vulnerabilities'. kind: rótulo p/ o nome."""
        for v in (container or {}).get("vulnerabilities", []) or []:
            title = v.get("title", "WordPress vulnerability")
            cves = _cve_list((v.get("references", {}) or {}).get("cve", []))
            fixed = v.get("fixed_in")
            remediation = (f"Update to version {fixed} or later." if fixed
                           else "Update the affected WordPress component to the latest version.")
            findings.append({
                "tool": "wpscan",
                "type": "cms_vulnerability",
                "source": "wpscan",
                "name": f"WordPress {kind}: {title}",
                "url": target,
                "severity": "high",
                "description": (f"wpscan reported a known vulnerability on the WordPress "
                                f"{kind.lower()}: {title}."),
                "remediation": remediation,
                "cve": _cve_str(cves),
            })

    # Core (chave 'version') e top-level 'vulnerabilities' (formato legado)
    _vulns_from(data.get("version", {}), "core")
    _vulns_from({"vulnerabilities": data.get("vulnerabilities", [])}, "core")
    # Tema principal e temas adicionais
    _vulns_from(data.get("main_theme", {}), "theme")
    for _slug, theme in (data.get("themes", {}) or {}).items():
        _vulns_from(theme, f"theme {_slug}")
    # Plugins
    for slug, plugin in (data.get("plugins", {}) or {}).items():
        _vulns_from(plugin, f"plugin {slug}")

    return findings


def parse_joomscan(text, target=""):
    """Cada linha '[!] ...' do joomscan vira um finding (CVE → high, senão medium)."""
    findings = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line.startswith("[!]"):
            continue
        item = line[3:].strip().lstrip(":").strip()
        if not item:
            continue
        cves = _cve_list(c.upper() for c in _CVE_RE.findall(line))
        findings.append({
            "tool": "joomscan",
            "type": "cms_vulnerability",
            "source": "joomscan",
            "name": f"Joomla: {item}",
            "url": target,
            "severity": "high" if cves else "medium",
            "description": f"joomscan flagged a security item on the Joomla target: {item}.",
            "remediation": "Update Joomla core/extensions and review the flagged item.",
            "cve": _cve_str(cves),
        })
    return findings


def parse_droopescan(text, target=""):
    """Extrai versão divulgada e URLs sensíveis das seções '[+] ...' do droopescan."""
    findings = []
    section = None
    versions = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[+]"):
            section = stripped[3:].strip().lower()
            continue
        if not stripped or section is None:
            continue
        if section.startswith("possible version"):
            versions.append(stripped)
        elif section.startswith("possible interesting urls"):
            # formato: "Label - http://..."
            m = re.search(r"(https?://\S+)", stripped)
            if m:
                url = m.group(1)
                label = stripped.split(" - ")[0].strip() if " - " in stripped else stripped
                findings.append({
                    "tool": "droopescan",
                    "type": "cms_exposure",
                    "source": "droopescan",
                    "name": f"Drupal exposed resource: {label}",
                    "url": url,
                    "severity": "low",
                    "description": f"droopescan found a potentially sensitive Drupal resource: {label} ({url}).",
                    "remediation": "Remove or restrict access to the exposed resource if not required.",
                    "cve": "N/A",
                })
    if versions:
        findings.insert(0, {
            "tool": "droopescan",
            "type": "cms_vulnerability",
            "source": "droopescan",
            "name": "Drupal version disclosed",
            "url": target,
            "severity": "low",
            "description": ("droopescan disclosed the Drupal version(s): "
                            + ", ".join(versions) + " — eases targeted exploitation."),
            "remediation": "Suppress version disclosure (CHANGELOG.txt, headers) and keep Drupal updated.",
            "cve": "N/A",
        })
    return findings


def main(outdir, target):
    target = (target or "").rstrip("/")
    raw = os.path.join(outdir, "raw")
    findings = []

    wp = os.path.join(raw, "wpscan.json")
    if os.path.exists(wp):
        try:
            with open(wp, encoding="utf-8", errors="ignore") as fh:
                findings += parse_wpscan(json.load(fh), target)
        except (ValueError, OSError):
            pass

    jm = os.path.join(raw, "joomscan.txt")
    if os.path.exists(jm):
        try:
            with open(jm, encoding="utf-8", errors="ignore") as fh:
                findings += parse_joomscan(fh.read(), target)
        except OSError:
            pass

    dp = os.path.join(raw, "droopescan.txt")
    if os.path.exists(dp):
        try:
            with open(dp, encoding="utf-8", errors="ignore") as fh:
                findings += parse_droopescan(fh.read(), target)
        except OSError:
            pass

    for i, f in enumerate(findings, 1):
        f["id"] = f"CMS-{i:03d}"

    out = os.path.join(raw, "cms_findings.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)

    if findings:
        print(f"  [✓] CMS scanners: {len(findings)} finding(s) estruturado(s) → cms_findings.json")
    else:
        print("  [○] CMS scanners: sem findings estruturados")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
