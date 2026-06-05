#!/usr/bin/env python3
"""
version_fingerprint.py — PROBES de versão de tecnologias → version_findings.json

Extraído de stiglitz.sh (heredoc PYVERSION). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import sys, json, re, urllib.request, urllib.error, ssl

outdir = sys.argv[1]
target = sys.argv[2].rstrip("/")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch(url, timeout=8, attempts=3, backoff=4):
    last_err = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read().decode("utf-8", errors="replace"), r.status
        except urllib.error.HTTPError as e:
            # Resposta definitiva (404 = endpoint ausente, 403 = bloqueado).
            # Não é falha transitória — não re-tentar.
            return "", e.code
        except Exception as e:
            last_err = e
            if attempt < attempts - 1:
                import time; time.sleep(backoff)
    print(f"  [!] fetch falhou após {attempts} tentativa(s): {url} — {type(last_err).__name__}: {last_err}")
    return None, None

# ── Technology probe definitions ──────────────────────────────────
# Fields: (tech_name, [(path, required_body_substring)],
#           version_regex, min_ok_version,
#           severity_if_outdated, cve_refs, remediation)
# required_body_substring: string that must be in the response to avoid
# false positives (e.g. another app responding to the same endpoint).
PROBES = [
    (
        "Grafana",
        [("/api/health", '"database"'), ("/login", "grafana")],
        r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "10.0",
        "high",
        "CVE-2023-3128, CVE-2023-6152, CVE-2023-2183, CVE-2023-1410",
        "Update Grafana to version 10.x or higher. "
        "See https://grafana.com/security/security-advisories/ for the security changelog.",
    ),
    (
        "Prometheus",
        [("/api/v1/status/buildinfo", '"appName"'), ("/-/healthy", "Prometheus")],
        r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "2.45",
        "medium",
        "CVE-2022-21698",
        "Update Prometheus to version 2.45+ (current LTS).",
    ),
    (
        "Kibana",
        [("/api/status", '"tagline"')],
        r'"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "8.0",
        "high",
        "CVE-2023-31416, CVE-2022-23712",
        "Update Kibana to the current 8.x version.",
    ),
    (
        "Jenkins",
        [("/api/json?pretty=true", '"_class"'), ("/login", "Jenkins")],
        r'Jenkins\s+ver\.\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)|"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
        "2.440",
        "high",
        "CVE-2024-23897, CVE-2023-27898",
        "Update Jenkins to the latest LTS version.",
    ),
    (
        "HashiCorp Vault",
        [("/v1/sys/health", '"initialized"')],
        r'"version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "1.15",
        "high",
        "CVE-2023-3774, CVE-2023-0620",
        "Update Vault to the current 1.15+ version.",
    ),
    (
        "Elasticsearch",
        [("/", '"cluster_name"'), ("/_cluster/health", '"cluster_name"')],
        r'"number"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "8.0",
        "high",
        "CVE-2023-31418, CVE-2022-23712",
        "Update Elasticsearch to the current 8.x version.",
    ),
    (
        "Consul",
        [("/v1/agent/self", '"Config"')],
        r'"Version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "1.17",
        "medium",
        "CVE-2023-3518",
        "Update Consul to the current 1.17+ version.",
    ),
    (
        "Traefik",
        [("/api/version", '"Version"'), ("/dashboard/api/version", '"Version"')],
        r'"Version"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+[^"]*)"',
        "3.0",
        "medium",
        "CVE-2022-46153",
        "Update Traefik to the current 3.x version.",
    ),
    # ── Web Application Stacks ──────────────────────────────────────────────────
    (
        "WordPress",
        [("/feed/", "wordpress.org"),
         ("/wp-login.php", "WordPress"),
         ("/wp-json/", '"wp:rest-api"')],
        r'wordpress\.org/\?v=([0-9]+\.[0-9]+\.?[0-9]*)',
        "6.4",
        "high",
        "CVE-2024-6307, CVE-2023-5561, CVE-2023-2745",
        "Update WordPress core to 6.4+. Keep plugins updated: wp plugin list --update=available. "
        "Disable xmlrpc.php if unused. Enable two-factor authentication for administrators.",
    ),
    (
        "Drupal",
        [("/CHANGELOG.txt", "Drupal"),
         ("/core/CHANGELOG.txt", "Drupal")],
        r'Drupal ([0-9]+\.[0-9]+\.?[0-9]*)',
        "10.0",
        "high",
        "CVE-2023-5256, CVE-2022-25271, SA-CORE-2022-015",
        "Update to Drupal 10.x. Run: drush updb && drush cr. "
        "Remove publicly accessible CHANGELOG.txt and INSTALL.txt. See: https://www.drupal.org/security",
    ),
    (
        "Joomla",
        [("/administrator/manifests/files/joomla.xml", "<version>")],
        r'<version>([0-9]+\.[0-9]+\.?[0-9]*)</version>',
        "4.4",
        "high",
        "CVE-2023-40626, CVE-2023-23752",
        "Update Joomla to 4.4+. Restrict /administrator/ by IP/network. "
        "Apply patches from: https://developer.joomla.org/security-centre.html",
    ),
    (
        "Spring Boot Actuator",
        [("/actuator", '"_links"'),
         ("/actuator/health", '"status"')],
        r'"Spring Boot"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"',
        "3.2.0",
        "high",
        "CVE-2022-22965, CVE-2023-20883, CVE-2022-22950",
        "Restrict /actuator with Spring Security (authentication required). "
        "Never expose /actuator/heapdump, /actuator/env or /actuator/shutdown publicly. "
        "Update to Spring Boot 3.2+.",
    ),
    (
        "Django Debug",
        [("/__debug__/", "djdt"),
         ("/admin/", "Django administration")],
        r'Django/([0-9]+\.[0-9]+\.?[0-9]*)',
        "4.2",
        "medium",
        "CVE-2024-27351, CVE-2023-46695, CVE-2022-34265",
        "Set DEBUG=False in production. Remove django-debug-toolbar from public environments. "
        "Update Django to 4.2+ (LTS).",
    ),
    (
        "Laravel Debug",
        [("/telescope", "Laravel Telescope"),
         ("/horizon", "Laravel Horizon"),
         ("/_debugbar/", "Debugbar")],
        r'Laravel\s+v?([0-9]+\.[0-9]+\.?[0-9]*)',
        "10.0",
        "high",
        "CVE-2023-47128, CVE-2021-43996",
        "Set APP_DEBUG=false in production. Protect /telescope and /horizon with authentication middleware. "
        "Update Laravel to 10.x.",
    ),
    (
        "Apache Struts",
        [("/struts2-showcase/", "Struts Showcase"),
         ("/index.action", "Apache Struts")],
        r'Struts\s+([0-9]+\.[0-9]+\.[0-9]+)',
        "6.3.0.2",
        "critical",
        "CVE-2024-53677, CVE-2023-50164, CVE-2021-31805, S2-066",
        "Update Apache Struts 2 to 6.3.0.2+ IMMEDIATELY — CVE-2023-50164 and S2-066 have public RCE exploits. "
        "Remove struts2-showcase. See: https://struts.apache.org/security",
    ),
]

def version_tuple(v):
    """Convert '9.5.6' to (9, 5, 6) for comparison."""
    try:
        parts = re.sub(r"[^0-9.]", "", v.split("-")[0]).split(".")
        return tuple(int(x) for x in parts if x)
    except Exception:
        return (0,)

findings = []

for tech, path_specs, version_re, min_ok_version, sev, cves, remediation in PROBES:
    detected_version = None
    hit_path = path_specs[0][0]
    for path, required in path_specs:
        body, status = fetch(target + path)
        if not body:
            continue
        if required.lower() not in body.lower():
            continue          # discriminator failed — wrong technology
        m = re.search(version_re, body, re.IGNORECASE)
        if m:
            detected_version = next((g for g in m.groups() if g), None)
            hit_path = path
            break

    if not detected_version:
        continue

    detected_t = version_tuple(detected_version)
    min_t      = version_tuple(min_ok_version)
    is_outdated = (detected_t < min_t) if detected_t and min_t else False

    status_str = "OUTDATED" if is_outdated else "ok"
    print(f"  [version] {tech} {detected_version} → {status_str}")
    # Only emit findings for outdated versions — current versions have no remediation value
    # and may produce false positives from multi-tenant endpoints.
    if not is_outdated:
        continue
    finding = {
        "id":          f"version-{tech.lower().replace(' ','-').replace('/','-')}",
        "name":        f"{tech} v{detected_version} — Outdated Version",
        "severity":    sev,
        "source":      "Version Fingerprint",
        "url":         target,
        "cve":         f"CWE-1104 — {cves}",
        "cve_ids":     [],
        "description": (
            f"{tech} version {detected_version} detected via unauthenticated endpoint "
            f"({hit_path}). Outdated version — recommended minimum: {min_ok_version}. "
            f"Known CVEs for this line: {cves}."
        ),
        "remediation": remediation,
        "evidence":    f"GET {hit_path} → {{\"version\":\"{detected_version}\"}}",
        "param": "", "attack": "", "other": "",
        "severity_orig": sev,
        "severity_reclassified": False,
        "detected_version": detected_version,
        "min_version": min_ok_version,
        "is_outdated": True,
    }
    findings.append(finding)

out_file = f"{outdir}/raw/version_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

if findings:
    outdated = [x for x in findings if x["is_outdated"]]
    print(f"  [✓] {len(findings)} tecnologia(s) detectada(s), {len(outdated)} desatualizada(s)")
else:
    print("  [✓] Nenhuma tecnologia com versão detectável encontrada")
