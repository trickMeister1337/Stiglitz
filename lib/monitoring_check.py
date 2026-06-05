#!/usr/bin/env python3
"""
monitoring_check.py — Checa endpoints de monitoramento expostos → monitoring_findings.json

Extraído de stiglitz.sh (heredoc PYMONITORING). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import sys, re, json, urllib.request, urllib.error, ssl

outdir, target = sys.argv[1], sys.argv[2].rstrip("/")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

MONITORING_PATHS = [
    "/metrics",
    "/-/metrics",
    "/actuator/prometheus",
    "/actuator/metrics",
    "/api/v1/metrics",
]

PCI_TERMS = re.compile(r'\b(cde|pci|cardholder|card.?holder|pan|cvv|payment.?card)\b', re.I)

def fetch(url, attempts=3, backoff=4):
    import time as _t
    last_err = None
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            r = urllib.request.urlopen(req, timeout=10, context=ctx)
            return r.read().decode("utf-8", errors="replace"), r.status
        except urllib.error.HTTPError as e:
            return "", e.code
        except Exception as e:
            last_err = e
            if attempt < attempts - 1:
                _t.sleep(backoff)
    print(f"  [!] fetch falhou após {attempts} tentativa(s): {url} — {type(last_err).__name__}: {last_err}")
    return "", 0

findings = []

for path in MONITORING_PATHS:
    body, status = fetch(target + path)
    if status != 200 or not body:
        continue
    # Must look like Prometheus text format or JSON metrics
    if not any(marker in body for marker in ("# HELP", "# TYPE", "_total", "_bucket", '"names"')):
        continue

    print(f"  [!] {path} acessível sem autenticação (HTTP 200, {len(body)} bytes)")

    # Extract named labels: datasource="...", name="...", dialer_name="..."
    label_pattern = re.compile(r'(?:datasource|dialer_name|name)="([^"]+)"')
    names = sorted(set(label_pattern.findall(body)))

    # Separate datasource names from alert names
    ds_names  = sorted(set(re.findall(r'datasource="([^"]+)"', body)))
    alert_names = sorted(set(re.findall(r'name="([^"]+)"', body)))

    # Technology inference from plugin_id labels
    plugin_ids = sorted(set(re.findall(r'plugin_id="([^"]+)"', body)))

    # PCI sensitive
    pci_hits = [n for n in names if PCI_TERMS.search(n)]

    sev = "critical" if pci_hits else "high"

    desc_parts = [
        f"Endpoint {path} returns internal metrics without authentication (HTTP 200).",
    ]
    if ds_names:
        desc_parts.append(f"Exposed datasources ({len(ds_names)}): {', '.join(ds_names[:10])}" +
                          (" ..." if len(ds_names) > 10 else "."))
    if pci_hits:
        desc_parts.append(f"PCI DSS WARNING: datasource(s) with CDE environment naming detected: {', '.join(pci_hits)}.")
    if alert_names:
        desc_parts.append(f"Exposed alert names: {', '.join(alert_names[:5])}" +
                          (" ..." if len(alert_names) > 5 else "."))
    if plugin_ids:
        desc_parts.append(f"Stack inferred via plugin_id: {', '.join(plugin_ids)}.")

    rem = (
        f"Restrict {path} by IP or require authentication. "
        "In Grafana: set metrics_endpoint_enabled = false under [metrics] in grafana.ini, "
        "or protect via reverse proxy (allow only from monitoring subnet). "
        "Reference: https://grafana.com/docs/grafana/latest/setup-grafana/set-up-grafana-monitoring/"
    )

    findings.append({
        "id":          f"exposed-metrics-{path.strip('/').replace('/', '-')}",
        "name":        f"Endpoint {path} Exposed Without Authentication",
        "severity":    sev,
        "source":      "Version Fingerprint",
        "url":         target + path,
        "cve":         "CWE-200 — Information Exposure",
        "cve_ids":     [],
        "description": " ".join(desc_parts),
        "remediation": rem,
        "evidence":    f"GET {path} → HTTP 200 ({len(body)} bytes of internal telemetry)",
        "param": "", "attack": "", "other": "",
        "severity_orig": sev,
        "severity_reclassified": False,
        "datasources": ds_names,
        "pci_labels":  pci_hits,
        "alert_names": alert_names,
        "plugins":     plugin_ids,
    })
    # Only report the first accessible metrics path
    break

out_file = f"{outdir}/raw/monitoring_findings.json"
with open(out_file, "w") as f:
    json.dump(findings, f, indent=2, ensure_ascii=False)

if findings:
    print(f"  [✓] {len(findings)} endpoint(s) de monitoramento exposto(s)")
else:
    print("  [✓] Nenhum endpoint de monitoramento exposto sem autenticação")
