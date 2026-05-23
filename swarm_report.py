#!/usr/bin/env python3
"""
swarm_report.py — Gerador de relatório HTML do SWARM.

Lê os artefatos em $OUTDIR/raw/ e gera:
  - relatorio_swarm.html   (relatório técnico completo)
  - sumario_executivo.html (sumário executivo)
  - findings.json          (achados estruturados)

Entrada via variáveis de ambiente (exportadas pelo swarm.sh):
  OUTDIR, TARGET, DOMAIN, SCAN_START_TS, OPEN_PORTS, ACTIVE_COUNT,
  SUB_COUNT, IS_SUBDOMAIN, OPENAPI_FOUND, TLS_ISSUES, CONFIRMED_COUNT,
  JS_SECRETS, JS_ENDPOINTS, JS_FRAMEWORKS, JS_FILES, KATANA_URLS,
  WAF_DETECTED, WAF_NAME, EMAIL_ISSUES, SMUGGLER_FOUND, FFUF_FOUND,
  TRUFFLEHOG_FOUND, AUTH_TOKEN, AUTH_HEADER, WPSCAN_VULNS

Uso direto (regenerar relatório de um scan existente):
  OUTDIR=scan_dir TARGET=https://alvo DOMAIN=alvo python3 swarm_report.py
"""
import json, os, html, re
from datetime import datetime, timezone

# ── Tabela CWE → CVSS sintético (baseado em médias históricas NVD) ──
# Usada como fallback para alertas ZAP que não trazem CVE nas referências
CWE_CVSS_TABLE = {
    # Injeção / execução
    "89":  {"cvss": 9.8, "sev": "CRITICAL", "name": "SQL Injection"},
    "78":  {"cvss": 9.8, "sev": "CRITICAL", "name": "OS Command Injection"},
    "77":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Command Injection"},
    "94":  {"cvss": 9.8, "sev": "CRITICAL", "name": "Code Injection"},
    "502": {"cvss": 9.8, "sev": "CRITICAL", "name": "Deserialization of Untrusted Data"},
    "611": {"cvss": 9.1, "sev": "CRITICAL", "name": "XXE"},
    "918": {"cvss": 9.8, "sev": "CRITICAL", "name": "SSRF"},
    # Autenticação / controle de acesso
    "287": {"cvss": 9.1, "sev": "CRITICAL", "name": "Improper Authentication"},
    "306": {"cvss": 9.1, "sev": "CRITICAL", "name": "Missing Authentication"},
    "284": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Access Control"},
    "285": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Authorization"},
    "862": {"cvss": 8.1, "sev": "HIGH",     "name": "Missing Authorization"},
    "863": {"cvss": 8.1, "sev": "HIGH",     "name": "Incorrect Authorization"},
    "269": {"cvss": 8.8, "sev": "HIGH",     "name": "Improper Privilege Management"},
    # Exposição de dados
    "22":  {"cvss": 7.5, "sev": "HIGH",     "name": "Path Traversal"},
    "23":  {"cvss": 7.5, "sev": "HIGH",     "name": "Relative Path Traversal"},
    "200": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Information Disclosure"},
    "312": {"cvss": 5.5, "sev": "MEDIUM",   "name": "Cleartext Storage of Sensitive Info"},
    "319": {"cvss": 5.9, "sev": "MEDIUM",   "name": "Cleartext Transmission"},
    "359": {"cvss": 6.5, "sev": "MEDIUM",   "name": "Privacy Violation"},
    # XSS / client-side
    "79":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Cross-Site Scripting (XSS)"},
    "80":  {"cvss": 6.1, "sev": "MEDIUM",   "name": "Basic XSS"},
    "116": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Improper Encoding/Escaping"},
    "1021":{"cvss": 4.7, "sev": "MEDIUM",   "name": "Clickjacking"},
    # CSRF / sessão
    "352": {"cvss": 8.8, "sev": "HIGH",     "name": "Cross-Site Request Forgery"},
    "384": {"cvss": 7.1, "sev": "HIGH",     "name": "Session Fixation"},
    "613": {"cvss": 5.4, "sev": "MEDIUM",   "name": "Insufficient Session Expiration"},
    # Criptografia / TLS
    "326": {"cvss": 7.5, "sev": "HIGH",     "name": "Inadequate Encryption Strength"},
    "327": {"cvss": 7.5, "sev": "HIGH",     "name": "Broken Crypto Algorithm"},
    "330": {"cvss": 7.5, "sev": "HIGH",     "name": "Insufficient Random Values"},
    "295": {"cvss": 7.4, "sev": "HIGH",     "name": "Improper Certificate Validation"},
    # Configuração / exposição
    "16":  {"cvss": 5.3, "sev": "MEDIUM",   "name": "Configuration"},
    "693": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Missing Security Header"},
    "1004":{"cvss": 4.0, "sev": "MEDIUM",   "name": "Cookie Without HttpOnly"},
    "1395":{"cvss": 6.1, "sev": "MEDIUM",   "name": "Vulnerable JavaScript Library"},
    "404": {"cvss": 5.3, "sev": "MEDIUM",   "name": "Improper Resource Shutdown"},
    "497": {"cvss": 4.3, "sev": "MEDIUM",   "name": "Exposure of System Data"},
    "525": {"cvss": 3.7, "sev": "LOW",      "name": "Browser Caching Sensitive Info"},
}

def cwe_enrich(cweid_str):
    """Dado CWE-89 ou 89, retorna dict com cvss/sev/name ou None."""
    if not cweid_str: return None
    cwe_num = re.sub(r"[^0-9]", "", str(cweid_str))
    return CWE_CVSS_TABLE.get(cwe_num)

# ── Mapa de impacto prático por CWE (linguagem para tech lead) ──
IMPACT_MAP = {
    "89":  "Um atacante pode ler, modificar ou apagar dados do banco de dados, incluindo dados de usuários e transações.",
    "78":  "Um atacante pode executar comandos arbitrários no servidor, comprometendo toda a infraestrutura.",
    "79":  "Scripts maliciosos podem ser executados no navegador de usuários, roubando sessões e credenciais.",
    "352": "Um atacante pode forçar usuários autenticados a executar ações não autorizadas (ex: transferências, alteração de dados).",
    "22":  "Um atacante pode acessar arquivos arbitrários do servidor, incluindo configurações e chaves privadas.",
    "287": "Acesso não autorizado à aplicação, permitindo personificar qualquer usuário incluindo administradores.",
    "306": "Endpoints críticos acessíveis sem autenticação, expondo dados e funcionalidades a qualquer pessoa.",
    "284": "Usuários podem acessar recursos ou dados de outros usuários (IDOR, escalada de privilégios).",
    "918": "O servidor pode ser usado como proxy para acessar serviços internos protegidos (AWS metadata, bancos de dados).",
    "611": "Processamento de XML externo pode vazar arquivos do servidor ou causar denial of service.",
    "502": "Deserialização de dados não confiáveis pode resultar em execução remota de código.",
    "326": "Comunicações criptografadas podem ser interceptadas e decifradas por atacantes na rede.",
    "327": "Algoritmos criptográficos fracos podem ser quebrados, expondo dados sensíveis.",
    "295": "Comunicações TLS podem ser interceptadas por ataques man-in-the-middle.",
    "1021":"Usuários podem ser induzidos a clicar em elementos invisíveis sobrepostos (clickjacking).",
    "319": "Dados transmitidos em texto claro podem ser interceptados por qualquer observador na rede.",
    "200": "Informações sobre tecnologias, versões ou estrutura interna expostas a atacantes.",
    "693": "Ausência de cabeçalhos de segurança deixa o browser do usuário sem proteções básicas contra XSS e injeção.",
    "1004":"Cookies de sessão acessíveis via JavaScript podem ser roubados por scripts maliciosos (XSS).",
    "1395":"Biblioteca JavaScript com vulnerabilidade conhecida e exploit público disponível.",
    "312": "Dados sensíveis armazenados sem criptografia podem ser acessados diretamente no banco de dados.",
    "384": "Um atacante pode fixar o identificador de sessão de um usuário e assumir sua conta após login.",
}

# ── Mapa de remediação específica por CWE ────────────────────
REMEDIATION_MAP = {
    "89":  "Use prepared statements (parametrized queries) em todas as queries SQL. Nunca concatene dados do usuário diretamente.",
    "79":  "Escape de output em contexto HTML/JS. Implemente Content-Security-Policy. Use bibliotecas como DOMPurify.",
    "352": "Implemente tokens CSRF (ex: SameSite=Strict em cookies, token por formulário). Frameworks como Spring, Django e Rails têm suporte nativo.",
    "22":  "Valide e normalize caminhos de arquivo. Use allowlist de diretórios permitidos. Evite concatenar input do usuário em caminhos.",
    "287": "Implemente autenticação forte com MFA. Use sessões seguras com expiração adequada.",
    "306": "Adicione autenticação a todos os endpoints. Use middleware de auth centralizado.",
    "284": "Valide no servidor que o usuário tem permissão para acessar o recurso solicitado. Não confie apenas no ID da URL.",
    "918": "Valide e filtre URLs de destino em qualquer funcionalidade de proxy/redirect. Use allowlist de hosts permitidos.",
    "693": "Configure cabeçalhos: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security.",
    "1004":"Adicione flag HttpOnly em todos os cookies de sessão. Use também Secure e SameSite=Strict.",
    "1395":"Atualize a biblioteca para a versão mais recente. Verifique release notes para breaking changes.",
    "326": "Use TLS 1.2+ com cipher suites modernas. Desabilite SSLv3, TLS 1.0, TLS 1.1 e RC4.",
    "319": "Force HTTPS em toda a aplicação. Implemente HSTS. Redirecione HTTP para HTTPS.",
    "352": "Tokens CSRF em formulários e headers X-CSRF-Token para APIs. Verifique Origin/Referer como camada adicional.",
    "312": "Criptografe dados sensíveis em repouso. Use bcrypt/Argon2 para senhas. Nunca armazene em texto claro.",
}

def cvss_to_sev(score):
    """Converte score CVSS para severidade pelo padrão NVD."""
    if score is None: return None
    score = float(score)
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score >= 0.1: return "low"
    return "info"

OUTDIR          = os.environ.get('OUTDIR','scan_output')
TARGET          = os.environ.get('TARGET','https://example.com')
DOMAIN          = os.environ.get('DOMAIN','example.com')
OPEN_PORTS      = os.environ.get('OPEN_PORTS','N/A')
ACTIVE_COUNT    = os.environ.get('ACTIVE_COUNT','0')
SUB_COUNT       = os.environ.get('SUB_COUNT','0')
OPENAPI_FOUND   = os.environ.get('OPENAPI_FOUND','0') == '1'
TLS_ISSUES      = int(os.environ.get('TLS_ISSUES','0'))
CONFIRMED_COUNT = int(os.environ.get('CONFIRMED_COUNT','0'))
SCAN_START_TS   = int(os.environ.get('SCAN_START_TS','0'))

# Carregar tempos por fase
phase_times = {}
_ptf = os.path.join(OUTDIR,'raw','.phase_times')
if os.path.exists(_ptf):
    try:
        for _line in open(_ptf):
            _parts = _line.strip().split(':')
            if len(_parts) >= 5 and _parts[1] == 'end':
                phase_times[_parts[0]] = int(_parts[4])
    except: pass
JS_SECRETS      = int(os.environ.get('JS_SECRETS','0'))
JS_ENDPOINTS    = int(os.environ.get('JS_ENDPOINTS','0'))
JS_FRAMEWORKS   = int(os.environ.get('JS_FRAMEWORKS','0'))
JS_FILES        = int(os.environ.get('JS_FILES','0'))
KATANA_URLS      = int(os.environ.get('KATANA_URLS','0'))
SMUGGLER_FOUND   = int(os.environ.get('SMUGGLER_FOUND','0'))
FFUF_FOUND       = int(os.environ.get('FFUF_FOUND','0'))
TRUFFLEHOG_FOUND = int(os.environ.get('TRUFFLEHOG_FOUND','0'))
WAF_DETECTED    = os.environ.get('WAF_DETECTED','') == '1'
WAF_NAME        = os.environ.get('WAF_NAME','')
EMAIL_ISSUES    = int(os.environ.get('EMAIL_ISSUES','0'))
errors = []

# Nuclei
findings = []
nuclei_file = os.path.join(OUTDIR,"raw","nuclei.json")
if os.path.exists(nuclei_file) and os.path.getsize(nuclei_file) > 0:
    with open(nuclei_file,"r",encoding="utf-8") as f:
        for ln, line in enumerate(f,1):
            line = line.strip()
            if not line: continue
            try:
                data = json.loads(line)
                info = data.get("info",{})
                sev  = info.get("severity","info").lower()
                cl   = info.get("classification",{}) or {}
                cves = cl.get("cve-id",[]) or []
                # Evidência: montar a partir de request/response/matcher do nuclei
                ev_parts = []
                if data.get("request"): ev_parts.append("REQUEST:\n" + str(data["request"]))
                if data.get("response"): ev_parts.append("RESPONSE:\n" + str(data["response"]))
                if data.get("extracted-results"): ev_parts.append("EXTRACTED: " + str(data["extracted-results"]))
                if data.get("curl-command"): ev_parts.append("CURL:\n" + str(data["curl-command"]))
                ev = "\n\n".join(ev_parts)  # sem truncagem — evidência completa
                meta = data.get("meta",{}) or {}
                findings.append({"source":"Nuclei","name":info.get("name","Vuln"),
                    "severity":sev,"description":(info.get("description","N/A") or "N/A"),
                    "cve":", ".join(cves) if cves else "N/A","url":data.get("matched-at",TARGET),
                    "remediation":info.get("remediation","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":str(meta.get("username","") or meta.get("param","") or ""),
                    "attack":str(meta.get("password","") or ""),
                    "other":data.get("template-id","") or ""})
            except json.JSONDecodeError as e: errors.append(f"Nuclei L{ln}: {e}")
            except Exception as e: errors.append(f"Nuclei L{ln}: {type(e).__name__}: {e}")

# ZAP — com deduplicação de alertas repetidos e filtro de confiança
zap_findings = []
zap_low_groups = {}  # Low/Info: tabela compacta
zap_dedup      = {}  # Critical/High/Medium: card único por tipo
# Carregar request/response do XML ZAP para evidência completa
_zap_xml_evidence = {}  # name -> {request, response}
_zap_xml_path = os.path.join(OUTDIR,"raw","zap_evidencias.xml")
if os.path.exists(_zap_xml_path):
    try:
        import xml.etree.ElementTree as ET
        _xtree = ET.parse(_zap_xml_path)
        for _xalert in _xtree.findall(".//alertitem"):
            _xname = (_xalert.findtext("alert") or "").strip()
            if _xname and _xname not in _zap_xml_evidence:
                _xreq  = (_xalert.findtext("requestheader") or "").strip()
                _xreqb = (_xalert.findtext("requestbody") or "").strip()
                _xres  = (_xalert.findtext("responseheader") or "").strip()
                _xresb = (_xalert.findtext("responsebody") or "").strip()
                _xfull_req = _xreq + ("\n\n" + _xreqb if _xreqb else "")
                _xfull_res = _xres + ("\n\n" + _xresb if _xresb else "")  # evidência completa sem truncagem
                _zap_xml_evidence[_xname] = {
                    "request":  _xfull_req,
                    "response": _xfull_res
                }
    except Exception as _xe: errors.append(f"ZAP XML: {_xe}")

zap_file = os.path.join(OUTDIR,"raw","zap_alerts.json")
if os.path.exists(zap_file) and os.path.getsize(zap_file) > 0:
    try:
        zap_data = json.load(open(zap_file,"r",encoding="utf-8"))
        rmap = {"high":"high","medium":"medium","low":"low","informational":"info"}
        SKIP_CONFIDENCE = {"false positive"}

        # ── Padrões de URLs geradas pelo spider que não representam recursos reais ──
        # Redirects de autenticação (Jenkins, Jira, Confluence, etc.)
        # e URLs com parâmetros de redirect injetados pelo scanner
        URL_SKIP_PATTERNS = [
            r'/securityRealm/',          # Jenkins auth redirect
            r'moLogin\?from=',           # Jenkins login redirect
            r'j_spring_security',        # Spring Security login
            r'login\?from=%2F',          # Generic auth redirect
            r'login\?next=%2F',          # Django/Flask auth redirect
            r'signin\?returnUrl=',       # Generic signin redirect
            r'auth\?redirect=',          # Generic auth redirect
            r'\?from=%2F',              # ZAP-injected redirect param
            r'\?from=%2Fsitemap',        # sitemap redirect artifact
            r'\?from=%2Fstatic',         # static asset redirect artifact
            r'/j_acegi_security',        # Legacy Spring Security
            r'oauth/authorize\?',        # OAuth artifacts
            r'saml/login\?',             # SAML redirect artifacts
        ]

        def url_is_real(url):
            """Retorna False se a URL é claramente um artefato de redirect/scanner."""
            if not url:
                return True
            for pattern in URL_SKIP_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
            return True

        for i,a in enumerate(zap_data.get("alerts",[])):
            try:
                sev_orig = rmap.get(a.get("risk","info").lower(),"info")
                conf = a.get("confidence","").lower()
                if conf in SKIP_CONFIDENCE:
                    continue

                # ── Filtrar URLs que não representam recursos reais ──────────
                alert_url = a.get("url","")
                if not url_is_real(alert_url):
                    errors.append(f"ZAP URL filtrada (redirect artefato): {alert_url[:80]}")
                    continue
                # Reclassificar severidade via CVSS do CWE (Opção C — tabela sintética)
                _cweid = str(a.get("cweid","") or "")
                _cwe_data = cwe_enrich(_cweid)
                sev_reclassified = False
                if _cwe_data:
                    sev_from_cvss = cvss_to_sev(_cwe_data["cvss"])
                    if sev_from_cvss and sev_from_cvss != sev_orig:
                        sev = sev_from_cvss
                        sev_reclassified = True
                    else:
                        sev = sev_orig
                else:
                    sev = sev_orig
                # Evidência completa: campos JSON + request/response do XML ZAP
                ev_parts_zap = []
                _alert_name = a.get("name","")
                _xml_ev = _zap_xml_evidence.get(_alert_name, {})
                if a.get("param",""):      ev_parts_zap.append(f"Parâmetro: {a['param']}")
                if a.get("attack",""):     ev_parts_zap.append(f"Vetor de Ataque:\n{a['attack']}")
                if a.get("evidence",""):   ev_parts_zap.append(f"Evidência:\n{a['evidence']}")
                if _xml_ev.get("request"): ev_parts_zap.append(f"--- REQUISIÇÃO HTTP ---\n{_xml_ev['request']}")
                if _xml_ev.get("response"):ev_parts_zap.append(f"--- RESPOSTA HTTP ---\n{_xml_ev['response']}")
                if a.get("other",""):      ev_parts_zap.append(f"Detalhe adicional:\n{a['other']}")
                ev = "\n\n".join(ev_parts_zap)  # sem truncagem — evidência completa
                # Extrair CVE do campo reference; fallback para CWE
                _refs = a.get("reference","") or ""
                _cves = re.findall(r"CVE-\d{4}-\d{4,7}", _refs, re.IGNORECASE)
                _cve_str = ", ".join(sorted(set(c.upper() for c in _cves))) if _cves \
                    else f"CWE-{a.get('cweid','N/A')}"
                f_entry = {"source":"OWASP ZAP","name":a.get("name","Alerta"),
                    "severity":sev,
                    "severity_orig":sev_orig,
                    "severity_reclassified":sev_reclassified,
                    "cvss_synthetic":_cwe_data["cvss"] if _cwe_data else None,
                    "description":(a.get("description","N/A") or "N/A"),
                    "cve": f"{_cve_str} | Conf: {a.get('confidence','?')}",
                    "url":a.get("url",TARGET),
                    "remediation":a.get("solution","Revisar.") or "Revisar.",
                    "evidence":ev,
                    "param":(a.get("param","") or ""),
                    "attack":(a.get("attack","") or ""),
                    "other":(a.get("other","") or "")}
                # Estratégia de deduplicação por severidade:
                # Critical/High → card único por nome (melhor evidência + lista de URLs)
                # Medium        → card único por nome (melhor evidência + lista de URLs)
                # Low/Info      → tabela compacta agrupada
                name = a.get("name","Alerta")
                url  = a.get("url","")
                if sev in ("low","info"):
                    if name not in zap_low_groups:
                        zap_low_groups[name] = {"count":0,"urls":[],"finding":f_entry,
                            "cve": _cve_str, "conf":a.get("confidence","?"),
                            "sev": sev}
                    zap_low_groups[name]["count"] += 1
                    if url and url not in zap_low_groups[name]["urls"]:
                        zap_low_groups[name]["urls"].append(url)
                else:
                    # Deduplicar Medium/High/Critical por nome
                    # Manter o finding com maior evidência; acumular URLs distintas
                    if name not in zap_dedup:
                        zap_dedup[name] = {"finding": f_entry, "urls": [], "count": 0, "sev": sev}
                    # Promover para maior severidade encontrada
                    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
                    if sev_order.get(sev,5) < sev_order.get(zap_dedup[name]["sev"],5):
                        zap_dedup[name]["finding"] = f_entry
                        zap_dedup[name]["sev"] = sev
                    # Preferir finding com evidência real
                    if f_entry.get("evidence") and not zap_dedup[name]["finding"].get("evidence"):
                        zap_dedup[name]["finding"] = f_entry
                    zap_dedup[name]["count"] += 1
                    if url and url not in zap_dedup[name]["urls"]:
                        zap_dedup[name]["urls"].append(url)
            except Exception as e: errors.append(f"ZAP alerta {i}: {e}")
    except json.JSONDecodeError as e: errors.append(f"ZAP JSON malformado: {e}")
    except Exception as e: errors.append(f"ZAP: {e}")

# Converter zap_dedup em zap_findings, injetando lista de URLs afetadas
for name, grp in zap_dedup.items():
    f = dict(grp["finding"])  # cópia
    affected = grp["urls"]
    f["severity"] = grp["sev"]  # severidade mais alta encontrada
    f["affected_count"] = grp["count"]
    f["affected_urls"] = affected
    # Se mais de uma URL, adicionar lista às outras informações do card
    if len(affected) > 1:
        extra = f"\n\n[{len(affected)} URLs afetadas]\n" + "\n".join(f"  • {u}" for u in affected[:20])
        if len(affected) > 20:
            extra += f"\n  ... e mais {len(affected)-20} URL(s)"
        f["other"] = (f.get("other","") + extra).strip()
    zap_findings.append(f)

# httpx / nmap
httpx_lines = []
hf = os.path.join(OUTDIR,"raw","httpx_results.txt")
if os.path.exists(hf):
    try: httpx_lines = [l.strip() for l in open(hf) if l.strip()]
    except Exception as e: errors.append(f"httpx: {e}")

nmap_lines = []
nf = os.path.join(OUTDIR,"raw","nmap.txt")
if os.path.exists(nf):
    try: nmap_lines = [l.strip() for l in open(nf) if "open" in l and "/tcp" in l]
    except Exception as e: errors.append(f"nmap: {e}")

# ── testssl ───────────────────────────────────────────────────
# Mapeamento de IDs testssl → nome legível, descrição e remediação
TLS_ID_INFO = {
    "cipherlist_NULL": {
        "name": "Cipher Suites NULL Habilitadas (Sem Criptografia)",
        "desc": "O servidor aceita cipher suites do tipo NULL, que não aplicam nenhuma criptografia ao tráfego. Qualquer atacante com acesso à rede pode ler e modificar os dados em trânsito sem barreiras.",
        "rem":  "Desabilitar todas as cipher suites NULL na configuração TLS do servidor. Em Nginx: ssl_ciphers 'HIGH:!NULL:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5'; em Apache: SSLCipherSuite HIGH:!NULL:!aNULL. Reiniciar o servidor após a mudança.",
    },
    "cipherlist_aNULL": {
        "name": "Cipher Suites Anônimas Habilitadas (Sem Autenticação)",
        "desc": "O servidor aceita cipher suites anônimas (aNULL/DH anônimo), que não autenticam o servidor. Isso permite ataques Man-in-the-Middle onde um atacante se passa pelo servidor legítimo sem que o cliente perceba.",
        "rem":  "Desabilitar cipher suites aNULL e DH anônimo. Em Nginx: ssl_ciphers 'HIGH:!aNULL:!NULL:!eNULL'; em Apache: SSLCipherSuite HIGH:!aNULL:!NULL. Também remover ciphers EXPORT, DES e RC4 da configuração.",
    },
    "cipherlist_EXPORT": {
        "name": "Cipher Suites EXPORT Habilitadas (Criptografia Fraca — FREAK/LogJam)",
        "desc": "O servidor aceita cipher suites de exportação (40-56 bits), criadas nos anos 90 para contornar regulações de exportação dos EUA. São vulneráveis aos ataques FREAK (CVE-2015-0204) e LOGJAM.",
        "rem":  "Remover cipher suites EXPORT: ssl_ciphers '!EXPORT' (Nginx) / SSLCipherSuite !EXPORT (Apache). Atualizar para TLS 1.2+ com ciphers modernos (AES-256-GCM, CHACHA20).",
    },
    "cipherlist_LOW": {
        "name": "Cipher Suites de Baixa Segurança Habilitadas",
        "desc": "O servidor aceita cipher suites com criptografia fraca (DES, RC2, 56-bit). Essas cifras podem ser quebradas por força bruta com hardware moderno.",
        "rem":  "Remover todos os ciphers LOW e MEDIUM: ssl_ciphers 'HIGH:!LOW:!MEDIUM:!EXPORT:!aNULL:!NULL' (Nginx). Manter apenas AES-128-GCM, AES-256-GCM e CHACHA20-POLY1305.",
    },
    "cipherlist_3DES_IDEA": {
        "name": "3DES/IDEA Habilitado (Vulnerável ao SWEET32)",
        "desc": "O servidor aceita 3DES ou IDEA, vulneráveis ao ataque SWEET32 (CVE-2016-2183) que permite descriptografar sessões longas após ~768 GB de dados trocados.",
        "rem":  "Desabilitar 3DES e IDEA: adicionar '!3DES:!IDEA' à diretiva ssl_ciphers. Priorizar AES-GCM e CHACHA20.",
    },
    "cipherlist_OBSOLETED": {
        "name": "Cipher Suites Obsoletas Habilitadas",
        "desc": "O servidor aceita cipher suites consideradas obsoletas (RC4, DES, IDEA, SEED ou similar). Essas cifras possuem fraquezas conhecidas e não devem ser usadas em ambientes de produção.",
        "rem":  "Restringir o servidor a cipher suites modernas: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3) e ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2).",
    },
    "cipherlist_STRONG_NOFS": {
        "name": "Ausência de Forward Secrecy em Ciphers Fortes",
        "desc": "Cipher suites fortes sem Perfect Forward Secrecy (PFS) estão habilitadas. Se a chave privada do servidor for comprometida no futuro, sessões passadas gravadas podem ser descriptografadas retroativamente.",
        "rem":  "Priorizar cipher suites ECDHE/DHE: ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305'. Desativar RSA key exchange estático.",
    },
    "fallback_SCSV": {
        "name": "TLS Fallback SCSV Não Suportado (Vulnerável a Downgrade)",
        "desc": "O servidor não suporta TLS Fallback SCSV (RFC 7507), mecanismo que impede ataques de downgrade de protocolo. Sem isso, um atacante MITM pode forçar a conexão a usar uma versão TLS mais antiga e menos segura.",
        "rem":  "Atualizar a biblioteca TLS do servidor (OpenSSL 1.0.1j+, NSS 3.17.1+). O suporte a SCSV é automático em versões modernas. Também desabilitar TLS 1.0 e 1.1 para eliminar o vetor de downgrade.",
    },
    "BEAST": {
        "name": "Vulnerabilidade BEAST (CVE-2011-3389)",
        "desc": "O servidor está vulnerável ao ataque BEAST via CBC em TLS 1.0. Um atacante MITM pode injetar texto plano e realizar um ataque chosen-plaintext para recuperar partes do tráfego.",
        "rem":  "Desabilitar TLS 1.0: ssl_protocols TLSv1.2 TLSv1.3 (Nginx). Como mitigação adicional, priorizar ciphers RC4 foi sugerido no passado, mas RC4 também é fraco — a solução correta é desativar TLS 1.0.",
    },
    "LUCKY13": {
        "name": "Vulnerabilidade LUCKY13 (CVE-2013-0169)",
        "desc": "O servidor está potencialmente vulnerável ao LUCKY13, um timing attack contra CBC em TLS/DTLS que pode permitir recuperação parcial de texto plano.",
        "rem":  "Priorizar ciphers GCM (AEAD) em vez de CBC: ssl_ciphers 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:!CBC'. Em TLS 1.3, LUCKY13 não se aplica.",
    },
    "POODLE_SSL": {
        "name": "Vulnerabilidade POODLE (CVE-2014-3566) — SSLv3",
        "desc": "O servidor suporta SSLv3, vulnerável ao ataque POODLE que permite recuperar bytes individuais do texto plano em sessões HTTPS através de ataques de padding oracle.",
        "rem":  "Desabilitar SSLv3 imediatamente: ssl_protocols TLSv1.2 TLSv1.3 (Nginx) / SSLProtocol TLSv1.2 TLSv1.3 (Apache). SSLv3 não deve ser usado em nenhum cenário de produção.",
    },
    "POODLE_TLS": {
        "name": "Vulnerabilidade POODLE-TLS — Padding Oracle em TLS",
        "desc": "Implementação TLS vulnerável ao POODLE via padding oracle em TLS (não apenas SSLv3). Alguns stacks TLS aceitam padding inválido sem reportar erro, permitindo ataque similar ao POODLE original.",
        "rem":  "Atualizar o servidor/biblioteca TLS para versão que corrige o padding oracle. Habilitar apenas TLS 1.2 e 1.3 que são resistentes a este ataque.",
    },
    "DROWN": {
        "name": "Vulnerabilidade DROWN (CVE-2016-0800)",
        "desc": "O servidor ou um servidor com a mesma chave privada suporta SSLv2, vulnerável ao DROWN. Um atacante pode descriptografar sessões TLS modernas usando o oráculo SSLv2.",
        "rem":  "Desabilitar SSLv2 em todos os servidores que compartilham a chave privada. Revogar e renegociar certificados se a chave foi exposta. Nunca reutilizar a mesma chave privada em serviços com configurações TLS diferentes.",
    },
    "LOGJAM": {
        "name": "Vulnerabilidade LOGJAM — DH Fraco (CVE-2015-4000)",
        "desc": "O servidor aceita parâmetros Diffie-Hellman com tamanho insuficiente (< 2048 bits), vulneráveis ao ataque LOGJAM que permite downgrade para export-grade DH e descriptografia offline.",
        "rem":  "Gerar parâmetros DH fortes: openssl dhparam -out dhparam.pem 2048. Configurar ssl_dhparam /etc/nginx/dhparam.pem. Preferir ECDHE sobre DHE para eliminar este vetor.",
    },
    "SWEET32": {
        "name": "Vulnerabilidade SWEET32 (CVE-2016-2183)",
        "desc": "O servidor suporta cifras com bloco de 64 bits (3DES, DES, IDEA, Blowfish), vulneráveis ao SWEET32. Após ~768 GB de dados com a mesma chave de sessão, colisões de bloco permitem recuperação parcial de texto.",
        "rem":  "Desabilitar 3DES, DES, IDEA e Blowfish: adicionar '!3DES:!DES:!IDEA' ao ssl_ciphers. Limitar duração de sessões TLS (ssl_session_timeout 1h) como mitigação adicional.",
    },
    "ROBOT": {
        "name": "Vulnerabilidade ROBOT — Return of Bleichenbacher Oracle Threat",
        "desc": "O servidor é vulnerável ao ROBOT, uma variação do ataque Bleichenbacher de 1998 que permite descriptografar sessões RSA e gerar assinaturas RSA forjadas usando RSA PKCS#1 v1.5.",
        "rem":  "Desabilitar RSA key exchange (static RSA): remover !RSA (sem ECDHE) dos ciphers. Habilitar apenas ciphers com forward secrecy (ECDHE). Atualizar a biblioteca TLS se o fornecedor lançou patch específico.",
    },
    "HEARTBLEED": {
        "name": "Vulnerabilidade Heartbleed (CVE-2014-0160) — CRÍTICA",
        "desc": "O servidor está vulnerável ao Heartbleed, falha crítica no OpenSSL que permite ler até 64 KB da memória do processo por request. Dados como chaves privadas, senhas e tokens de sessão podem ser extraídos remotamente sem autenticação.",
        "rem":  "Atualizar OpenSSL para 1.0.1g+ / 1.0.2+ IMEDIATAMENTE. Revogar todos os certificados e gerar novos após o patch. Invalidar todas as sessões ativas e forçar troca de senhas de usuários.",
    },
    "CCS": {
        "name": "OpenSSL CCS Injection (CVE-2014-0224)",
        "desc": "O servidor está vulnerável à injeção ChangeCipherSpec do OpenSSL. Permite a um atacante MITM inserir uma chave de sessão nula, descriptografando e modificando o tráfego TLS em tempo real.",
        "rem":  "Atualizar OpenSSL para versão 0.9.8za, 1.0.0m ou 1.0.1h e superiores. Esta vulnerabilidade exige patch na biblioteca — não há workaround de configuração.",
    },
    "CRIME_TLS": {
        "name": "Vulnerabilidade CRIME (CVE-2012-4929) — Compressão TLS",
        "desc": "O servidor suporta compressão TLS, vulnerável ao CRIME. Um atacante que injeta texto no tráfego pode inferir cookies de sessão e tokens por análise de variação no tamanho comprimido.",
        "rem":  "Desabilitar compressão TLS: ssl_comp_add_compression_method() não deve ser chamado; em OpenSSL, compilar com -DOPENSSL_NO_COMP. Em Nginx moderno a compressão TLS já é desabilitada por padrão.",
    },
    "BREACH": {
        "name": "Vulnerabilidade BREACH — Compressão HTTP",
        "desc": "O servidor usa compressão HTTP (gzip) em respostas que contêm segredos (CSRF tokens, dados de sessão), vulnerável ao BREACH. Similar ao CRIME mas explora a compressão na camada HTTP.",
        "rem":  "Desabilitar compressão em respostas que contêm segredos: não comprimir endpoints com CSRF token ou dados sensíveis. Implementar CSRF tokens variáveis por request (masked tokens). A compressão HTTP geral pode ser mantida em recursos estáticos.",
    },
    "TICKETBLEED": {
        "name": "Vulnerabilidade Ticketbleed (CVE-2016-9244)",
        "desc": "O servidor F5/Citrix está vulnerável ao Ticketbleed, falha em session tickets TLS que vaza até 31 bytes de memória não inicializada por conexão.",
        "rem":  "Aplicar patch do fornecedor (F5 BIG-IP, Citrix). Desabilitar TLS session tickets como mitigação temporária: ssl_session_tickets off (Nginx).",
    },
    "TLS1": {
        "name": "TLS 1.0 Habilitado (Protocolo Deprecado)",
        "desc": "O servidor suporta TLS 1.0, depreciado pelo IETF (RFC 8996) e proibido pelo PCI DSS desde 2018. Está sujeito a múltiplos ataques (BEAST, POODLE, CRIME) e usa funções hash fracas (MD5/SHA-1).",
        "rem":  "Desabilitar TLS 1.0 e 1.1: ssl_protocols TLSv1.2 TLSv1.3 (Nginx) / SSLProtocol -all +TLSv1.2 +TLSv1.3 (Apache). Verificar compatibilidade com clientes legítimos antes de aplicar.",
    },
    "TLS1_1": {
        "name": "TLS 1.1 Habilitado (Protocolo Deprecado)",
        "desc": "O servidor suporta TLS 1.1, depreciado pelo IETF (RFC 8996) junto com TLS 1.0. Não suporta cipher suites AEAD e usa construções de MAC legadas vulneráveis a timing attacks.",
        "rem":  "Desabilitar TLS 1.1: ssl_protocols TLSv1.2 TLSv1.3 (Nginx). Manter apenas TLS 1.2 (com ciphers GCM) e TLS 1.3.",
    },
    "SSLv2": {
        "name": "SSLv2 Habilitado (Protocolo Severamente Vulnerável)",
        "desc": "O servidor suporta SSLv2, protocolo completamente quebrado que usa criptografia de 40-bit, sem proteção contra replay e vulnerável ao DROWN. Deve ser desabilitado em qualquer ambiente.",
        "rem":  "Desabilitar SSLv2 imediatamente: ssl_protocols TLSv1.2 TLSv1.3 (Nginx). Se o servidor não permitir desabilitar SSLv2, trocar o servidor/biblioteca TLS.",
    },
    "SSLv3": {
        "name": "SSLv3 Habilitado (Vulnerável ao POODLE)",
        "desc": "O servidor suporta SSLv3, vulnerável ao POODLE (CVE-2014-3566) e sem suporte a TLS extensions. Todas as comunicações via SSLv3 podem ser descriptografadas por um atacante MITM.",
        "rem":  "Desabilitar SSLv3: ssl_protocols TLSv1.2 TLSv1.3 (Nginx) / SSLProtocol -SSLv3 (Apache). Não há uso legítimo para SSLv3 em 2024+.",
    },
    "HSTS": {
        "name": "HTTP Strict Transport Security (HSTS) Ausente",
        "desc": "O servidor não envia o header Strict-Transport-Security, permitindo que conexões HTTP não criptografadas sejam aceitas e que ataques de downgrade SSL stripping redirecionem usuários para HTTP.",
        "rem":  "Adicionar header HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload (Nginx: add_header Strict-Transport-Security). Após estabilidade, submeter domínio ao HSTS preload list.",
    },
    "OCSP_stapling": {
        "name": "OCSP Stapling Não Configurado",
        "desc": "O servidor não usa OCSP stapling, fazendo com que browsers consultem o servidor OCSP da CA para verificar revogação de certificado — o que pode vazar o IP do usuário à CA e adicionar latência.",
        "rem":  "Habilitar OCSP stapling: ssl_stapling on; ssl_stapling_verify on; resolver 8.8.8.8 (Nginx). Verificar se a CA suporta OCSP e que o certificado tem extensão OCSP URL.",
    },
    "DNS_CAArecord": {
        "name": "Registro CAA DNS Ausente",
        "desc": "O domínio não possui registro CAA (Certification Authority Authorization), que restringe quais CAs podem emitir certificados para o domínio. Sem CAA, qualquer CA do mundo pode emitir certificados, ampliando o risco de certificados fraudulentos.",
        "rem":  "Adicionar registro CAA no DNS: exemplo para Let's Encrypt: 0 issue letsencrypt.org; 0 issuewild letsencrypt.org; 0 iodef mailto:security@dominio.com. Verificar com: dig CAA dominio.com",
    },
    "cert_expired": {
        "name": "Certificado TLS Expirado",
        "desc": "O certificado TLS do servidor está expirado. Browsers exibirão erro de segurança para todos os usuários, potencialmente tornando a aplicação inacessível.",
        "rem":  "Renovar o certificado imediatamente. Implementar renovação automática via Let's Encrypt (certbot renew) ou monitoramento de expiração com alertas com 30+ dias de antecedência.",
    },
    "cert_notYetValid": {
        "name": "Certificado TLS Ainda Não Válido",
        "desc": "O certificado TLS tem data de início (NotBefore) no futuro. O servidor está apresentando um certificado inválido para todos os clientes.",
        "rem":  "Verificar se o relógio do sistema está sincronizado (NTP). Renegociar o certificado com datas corretas junto à CA.",
    },
    "cert_chain_of_trust": {
        "name": "Cadeia de Certificação Inválida ou Incompleta",
        "desc": "O servidor não apresenta a cadeia completa de certificados intermediários, impedindo que clientes validem o certificado corretamente. Pode causar erros de SSL em alguns clientes.",
        "rem":  "Configurar o servidor para enviar os certificados intermediários (chain): ssl_certificate /path/to/fullchain.pem (Nginx). O arquivo fullchain.pem deve conter: certificado do servidor + intermediário(s) + raiz (opcional).",
    },
}

tls_findings = []
tf = os.path.join(OUTDIR,"raw","testssl.json")
if os.path.exists(tf) and os.path.getsize(tf) > 0:
    try:
        tdata = json.load(open(tf,"r",encoding="utf-8"))
        findings_raw = tdata if isinstance(tdata,list) else \
            tdata.get("scanResult",[{}])[0].get("findings",[])
        SEV_MAP = {"CRITICAL":"critical","HIGH":"high","WARN":"medium","LOW":"low","OK":"info","INFO":"info"}
        for item in findings_raw:
            sev_raw = item.get("severity","INFO")
            sev = SEV_MAP.get(sev_raw.upper(),"info")
            _tls_id = item.get("id","")
            # scanTime é metadado do testssl (duração do scan), não uma vulnerabilidade
            if sev_raw.upper() in ("CRITICAL","HIGH","WARN","LOW") and _tls_id != "scanTime":
                _tls_raw  = item.get("finding","")  # resultado bruto do teste (ex: "offered")
                _cve_raw  = item.get("cve","") or item.get("cwe","")
                _info     = TLS_ID_INFO.get(_tls_id, {})
                _name     = _info.get("name") or f"TLS/SSL: {_tls_id}" if _tls_id else "TLS/SSL Issue"
                _desc     = _info.get("desc") or f"testssl.sh reportou '{_tls_raw}' para o teste '{_tls_id}'."
                _rem      = _info.get("rem") or "Consultar a documentação do servidor para desabilitar este recurso TLS inseguro."
                _evidence = f"testssl.sh · teste: {_tls_id} · resultado: {_tls_raw}" if _tls_raw else f"testssl.sh · teste: {_tls_id}"
                tls_findings.append({
                    "id":       _tls_id,
                    "name":     _name,
                    "severity": sev, "severity_orig": sev, "severity_reclassified": False,
                    "sev":      sev,
                    "sev_raw":  sev_raw,
                    "source":   "testssl.sh",
                    "url":      TARGET,
                    "cve":      _cve_raw, "cve_ids": [],
                    "finding":  _tls_raw,
                    "description": _desc,
                    "remediation": _rem,
                    "evidence": _evidence,
                    "param": "", "attack": "", "other": "",
                })
    except Exception as e: errors.append(f"testssl: {e}")

# ── exploit confirmations ─────────────────────────────────────
confirmations = []
cf = os.path.join(OUTDIR,"raw","exploit_confirmations.json")
if os.path.exists(cf) and os.path.getsize(cf) > 0:
    try: confirmations = json.load(open(cf,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"confirmations: {e}")

# Normalização defensiva (igual ao swarm_report.py externo)
def _norm_sev_inline(v, default="info"):
    if not v: return default
    s = str(v).strip().lower()
    if s in ("crit","critical"): return "critical"
    if s in ("hi","high"): return "high"
    if s in ("med","medium","moderate"): return "medium"
    if s in ("lo","low"): return "low"
    if s in ("informational","information","info","none","unknown"): return "info"
    return s if s in ("critical","high","medium","low","info") else default

_nc = []
for _c in (confirmations if isinstance(confirmations, list) else []):
    if not isinstance(_c, dict): continue
    _sev_raw = (_c.get("severity") or (_c.get("info") or {}).get("severity")
                or _c.get("sev") or _c.get("risk"))
    if not _sev_raw:
        _cl = str(_c.get("confidence_level","")).lower()
        if "oob" in _cl or "rce" in _cl: _sev_raw = "critical"
        elif "reflected" in _cl or "sqli" in _cl: _sev_raw = "high"
        elif "version" in _cl: _sev_raw = "medium"
        elif "probable" in _cl: _sev_raw = "low"
        else: _sev_raw = "info"
    _c["severity"] = _norm_sev_inline(_sev_raw, "info")
    _c.setdefault("confirmed", False)
    _c.setdefault("template_id", _c.get("id") or _c.get("template-id") or "—")
    _c.setdefault("url", _c.get("matched-at") or _c.get("host") or _c.get("target") or "—")
    _c.setdefault("http_status", str(_c.get("status_code") or _c.get("status") or "—"))
    _c.setdefault("confidence", _c.get("confidence_score") or 0)
    try: _c["confidence"] = int(_c["confidence"])
    except Exception: _c["confidence"] = 0
    _c.setdefault("vuln_type", _c.get("type") or _c.get("confidence_level") or "")
    _c.setdefault("poc_note", _c.get("note") or _c.get("reason") or "—")
    _c.setdefault("response_headers", _c.get("headers") or "")
    _c.setdefault("response_body", _c.get("body") or _c.get("evidence") or "")
    _c.setdefault("curl_reproducible", _c.get("curl") or "")
    _c.setdefault("curl_command", _c.get("curl") or "")
    _url_v = str(_c.get("url","")).strip()
    _tid_v = str(_c.get("template_id","")).strip()
    if (not _url_v or _url_v == "—") and (not _tid_v or _tid_v == "—"):
        continue
    _nc.append(_c)
confirmations = _nc

# Classificar cada confirmação: "exploit" (abusável diretamente) vs
# "verified" (config/hardening apenas verificado). Evita rotular header
# ausente ou config TLS como "exploit confirmado".
_EXPLOIT_VULN_TYPES = ("sqli", "rce", "command_injection", "cmdi", "auth_bypass",
                       "default_login", "default-login", "ssrf", "lfi", "rfi",
                       "xss", "deserialization", "xxe", "ssti", "idor", "path_traversal")
_TLS_EXPLOIT_KW = ("null", "anull", "rc4", "export", "des", "3des", "sweet32",
                   "logjam", "drown", "beast", "poodle", "heartbleed", "ccs",
                   "robot", "ticketbleed", "crime", "cipherlist", "obsoleted")

def _confirmation_category(c):
    """exploit = vulnerabilidade abusável; verified = apenas verificado."""
    vt   = str(c.get("vuln_type", "")).lower()
    tid  = str(c.get("template_id", "")).lower()
    blob = vt + " " + tid
    if any(t in blob for t in _EXPLOIT_VULN_TYPES):
        return "exploit"
    if "default" in tid and "login" in tid:
        return "exploit"
    if vt == "tls" or any(x in tid for x in ("tls", "ssl", "cipher")):
        return "exploit" if any(x in tid for x in _TLS_EXPLOIT_KW) else "verified"
    return "verified"

for _c in confirmations:
    _c["category"] = _confirmation_category(_c)

# Mapa: identificador confirmado (template_id / id testssl) → categoria.
# Usado para marcar os cards/linhas correspondentes.
_confirmed_cat = {}
for _c in confirmations:
    if _c.get("confirmed"):
        _k = str(_c.get("template_id", "")).strip().lower()
        if _k and _k != "—":
            _confirmed_cat[_k] = _c["category"]

def _confirmed_category(f):
    """Retorna 'exploit'/'verified' se o finding tem confirmação correspondente,
    senão None. Nuclei guarda o template-id em f['other']; testssl em f['id']."""
    cands = []
    if f.get("source") == "Nuclei":
        cands.append(f.get("other", ""))
    cands.append(f.get("id", ""))
    for c in cands:
        ck = str(c).strip().lower()
        if ck and ck in _confirmed_cat:
            return _confirmed_cat[ck]
    return None

def _is_confirmed(f):
    return _confirmed_category(f) is not None

# ── WAF & Email Security ───────────────────────────────────
email_security = {}
_esf = os.path.join(OUTDIR,'raw','email_security.json')
if os.path.exists(_esf):
    try: email_security = json.load(open(_esf))
    except Exception as e: errors.append(f'email_security: {e}')

# Converter email_security dict em lista de findings para stats/risk
email_findings = []
if email_security:
    _EMAIL_CWE   = {'spf':'CWE-349','dmarc':'CWE-349','dkim':'CWE-345'}
    _EMAIL_NAMES = {
        'spf':   'SPF Ausente — Domínio Vulnerável a E-mail Spoofing',
        'dmarc': 'DMARC Ausente — Sem Proteção Anti-Spoofing',
        'dkim':  'DKIM Não Detectado — Autenticidade de E-mail Comprometida',
    }
    for _proto, _edata in email_security.items():
        _esev = _edata.get('severity','info')
        if _esev not in ('critical','high','medium','low'): continue
        email_findings.append({
            "id":       f"email-{_proto}",
            "name":     _EMAIL_NAMES.get(_proto, _proto.upper()),
            "severity": _esev, "severity_orig": _esev, "severity_reclassified": False,
            "source":   "Email Security",
            "url":      TARGET,
            "cve":      _EMAIL_CWE.get(_proto,''), "cve_ids": [],
            "description": _edata.get('detail',''),
            "remediation": _edata.get('recommendation',''),
            "evidence": "", "param": "", "attack": "", "other": "",
        })

# ── Scan metadata (comportamento + evasão) ───────────────────
scan_meta = {}
_smf = os.path.join(OUTDIR,'raw','scan_metadata.json')
if os.path.exists(_smf):
    try: scan_meta = json.load(open(_smf))
    except Exception as e: errors.append(f'scan_metadata: {e}')

# ── Security headers data ─────────────────────────────────────
security_headers_data = []
_shf = os.path.join(OUTDIR,'raw','security_headers.json')
if os.path.exists(_shf):
    try: security_headers_data = json.load(open(_shf))
    except Exception as e: errors.append(f'security_headers: {e}')

# Convert missing security headers into pseudo-findings so they are counted
# in stats/risk_score and rendered as cards in the HTML report.
_HDR_CWE = {
    "content-security-policy":  ("CWE-693", "critical"),
    "strict-transport-security":("CWE-319", "high"),
    "x-frame-options":          ("CWE-1021","medium"),
    "x-content-type-options":   ("CWE-693", "medium"),
    "referrer-policy":          ("CWE-200", "low"),
    "permissions-policy":       ("CWE-693", "low"),
    "x-xss-protection":         ("CWE-693", "info"),
}
_HDR_REM = {
    "content-security-policy":   "Adicionar: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' — ajustar para a stack da aplicação.",
    "strict-transport-security": "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "x-frame-options":           "Adicionar: X-Frame-Options: SAMEORIGIN (ou DENY se não há iframes legítimos)",
    "x-content-type-options":    "Adicionar: X-Content-Type-Options: nosniff",
    "referrer-policy":           "Adicionar: Referrer-Policy: strict-origin-when-cross-origin",
    "permissions-policy":        "Adicionar: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    "x-xss-protection":          "Remover ou substituir por Content-Security-Policy — X-XSS-Protection é legado e ignorado em browsers modernos.",
}
header_findings = []
for _shd in security_headers_data:
    _url = _shd.get("url", TARGET)
    for _hdr, _hinfo in _shd.get("missing", {}).items():
        _cwe, _sev_default = _HDR_CWE.get(_hdr, ("CWE-693", "info"))
        _sev = _hinfo.get("severity", _sev_default)
        header_findings.append({
            "id":   f"missing-header-{_hdr}",
            "name": f"Security Header Ausente: {_hdr}",
            "severity": _sev, "severity_orig": _sev, "severity_reclassified": False,
            "source": "Security Headers",
            "url": _url,
            "cve": _cwe, "cve_ids": [],
            "description": _hinfo.get("description", f"Header {_hdr} ausente"),
            "remediation": _HDR_REM.get(_hdr, f"Configurar o header {_hdr} no servidor web ou proxy reverso."),
            "evidence": "", "param": "", "attack": "", "other": "",
        })

# ── Tech Profile ─────────────────────────────────────────────
tech_profile  = {}
tech_detected = {}
tech_categories = {}
_tp_file = os.path.join(OUTDIR, "raw", "tech_profile.json")
if os.path.exists(_tp_file) and os.path.getsize(_tp_file) > 0:
    try:
        tech_profile    = json.load(open(_tp_file, "r", encoding="utf-8"))
        tech_detected   = tech_profile.get("detected", {})
        tech_categories = tech_profile.get("categories", {})
    except Exception as e:
        errors.append(f"tech_profile: {e}")

# ── Version Fingerprint + Monitoring + Rate Limit findings ───
version_findings = []
for _vf_file, _vf_label in [
    ('version_findings.json',    'version_findings'),
    ('monitoring_findings.json', 'monitoring_findings'),
    ('ratelimit_findings.json',  'ratelimit_findings'),
    ('secscan_findings.json',    'secscan_findings'),
]:
    _vff = os.path.join(OUTDIR, 'raw', _vf_file)
    if os.path.exists(_vff):
        try:
            _vf_raw = json.load(open(_vff))
            for _vf in _vf_raw:
                _vf.setdefault("severity_orig", _vf.get("severity","info"))
                _vf.setdefault("severity_reclassified", False)
                _vf.setdefault("cve_ids", [])
                version_findings.append(_vf)
        except Exception as e:
            errors.append(f'{_vf_label}: {e}')

# ── JS Analysis ──────────────────────────────────────────────
js_analysis = {}
js_file = os.path.join(OUTDIR,"raw","js_analysis.json")
if os.path.exists(js_file) and os.path.getsize(js_file) > 0:
    try: js_analysis = json.load(open(js_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"js_analysis: {e}")
js_secrets    = js_analysis.get("secrets",[])
js_endpoints  = js_analysis.get("endpoints",[])
js_frameworks = js_analysis.get("frameworks",[])
js_files_list = js_analysis.get("js_files",[])
js_probes     = js_analysis.get("endpoint_probes",[])
js_comments   = js_analysis.get("sensitive_comments",[])

# Enriquecer tech_profile com frameworks JS detectados pelo PYJS
if js_frameworks:
    for fw in js_frameworks:
        fw_name = fw.get("framework","")
        fw_ver  = fw.get("version","")
        if fw_name and fw_name not in tech_detected:
            tech_detected[fw_name] = {
                "version":    fw_ver,
                "source":     "js_analysis",
                "confidence": "high",
                "vulnerable": fw.get("vulnerable", False),
            }

# ── CVE enrichment (NVD + EPSS) ──────────────────────────────
cve_enrichment = {}
cve_db_file = os.path.join(OUTDIR,"raw","cve_enrichment.json")
if os.path.exists(cve_db_file) and os.path.getsize(cve_db_file) > 0:
    try: cve_enrichment = json.load(open(cve_db_file,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"cve_enrichment: {e}")

# KEV matches — CVEs encontrados no catálogo CISA
kev_matches = {}
_kev_f = os.path.join(OUTDIR,"raw","kev_matches.json")
if os.path.exists(_kev_f):
    try: kev_matches = json.load(open(_kev_f,"r",encoding="utf-8"))
    except Exception as e: errors.append(f"kev_matches: {e}")
kev_count = len(kev_matches)

# Reclassificar achados Nuclei usando CVSS real do NVD quando disponível
for f in findings:
    cve_field = f.get('cve','')
    cve_ids_f = re.findall(r'CVE-\d{4}-\d{4,7}', cve_field, re.IGNORECASE)
    best_cvss = None
    for cid in [c.upper() for c in cve_ids_f]:
        ev = cve_enrichment.get(cid,{})
        cvss_val = ev.get('cvss_v3') or ev.get('cvss_v2')
        if cvss_val and (best_cvss is None or float(cvss_val) > best_cvss):
            best_cvss = float(cvss_val)
    if best_cvss is not None:
        new_sev = cvss_to_sev(best_cvss)
        if new_sev and new_sev != f['severity']:
            f['severity_orig'] = f['severity']
            f['severity'] = new_sev
            f['severity_reclassified'] = True
            f['cvss_real'] = best_cvss
        else:
            f.setdefault('severity_orig', f['severity'])
            f.setdefault('severity_reclassified', False)
    else:
        f.setdefault('severity_orig', f['severity'])
        f.setdefault('severity_reclassified', False)


# Stats — contagem de CARDS únicos por severidade (padrão relatórios profissionais)
# Cada tipo de vulnerabilidade = 1, independente de quantas URLs afeta
all_f = sorted(findings + zap_findings + header_findings + version_findings + tls_findings + email_findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5))
stats = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for f in all_f:
    if f["severity"] in stats: stats[f["severity"]] += 1
# Low/Info: cada grupo = 1 card (tipo único)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in stats: stats[sev] += 1
total = sum(stats.values())

# Ocorrências reais — usadas apenas para o risk score (reflete severidade total do ambiente)
occurrences = dict(stats)
for grp in zap_low_groups.values():
    sev = grp["finding"]["severity"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)
for grp in zap_dedup.values():
    sev = grp["sev"]
    if sev in occurrences: occurrences[sev] += (grp["count"] - 1)

# ── Risk score: KEV > EPSS > CVSS (metodologia 2026) ───────────
# Base: faixa pela severidade mais alta + quantidade com retornos decrescentes.
# Usa TIPOS ÚNICOS (stats), não ocorrências por URL — assim um mesmo alerta
# repetido em N URLs não satura o índice (o que mascarava a discriminação:
# quase todo scan batia 100/100). A severidade mais alta define a faixa-base
# (alinhada às bandas 70/40/15); a quantidade adiciona um bônus limitado.
if   stats["critical"] > 0: _risk_floor = 70   # CRÍTICO
elif stats["high"]     > 0: _risk_floor = 40   # ALTO
elif stats["medium"]   > 0: _risk_floor = 15   # MÉDIO
elif stats["low"]      > 0: _risk_floor = 5
else:                       _risk_floor = 0
_risk_qty = min(stats["critical"]*6 + stats["high"]*3
                + stats["medium"]*1 + stats["low"]*0.5, 25)
base_risk = int(_risk_floor + _risk_qty)

# Camada 1 — KEV: exploração ativa confirmada (peso máximo)
# Um CVE no KEV é automaticamente urgente independente do CVSS
kev_bonus = 0
kev_count = sum(1 for ev in cve_enrichment.values() if ev.get("in_kev"))
if kev_count > 0:
    kev_bonus = min(kev_count * 25, 50)  # +25 por CVE no KEV, cap 50

# Camada 2 — EPSS: probabilidade de exploração nos próximos 30 dias
epss_bonus = 0
for ev in cve_enrichment.values():
    epss = ev.get("epss_score") or 0
    if epss >= 0.5:    epss_bonus += 15   # exploit muito provável (>50%)
    elif epss >= 0.1:  epss_bonus += 7    # exploit provável (>10%)
    elif epss >= 0.01: epss_bonus += 2    # exploit possível (>1%)
# Bônus JS: secrets e frameworks vulneráveis agravam o risco
HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key","GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password","DB Connection String"}
js_high   = [s for s in js_secrets if s.get("type","") in HIGH_JS_TYPES]
js_medium = [s for s in js_secrets if s.get("type","") not in HIGH_JS_TYPES]
js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
js_bonus = min(len(js_high)*15 + len(js_medium)*5 + len(js_vuln_fw)*8, 30)
risk = min(base_risk + kev_bonus + epss_bonus + js_bonus, 100)
# A faixa CRÍTICO exige um achado de severidade crítica OU exploração ativa
# (CISA KEV). Bônus brandos (EPSS/JS) elevam dentro de ALTO, mas não devem
# fabricar um CRÍTICO sozinhos — evita que falsos-positivos de secrets JS ou
# probabilidade EPSS inflem a leitura executiva.
if stats["critical"] == 0 and kev_count == 0:
    risk = min(risk, 69)
# Classificação baseada no risk score (KEV+EPSS+CVSS) — não apenas contagem
# Faixas: 70-100=CRÍTICO, 40-69=ALTO, 15-39=MÉDIO, 0-14=BAIXO
if risk >= 70:
    stxt, scol = "CRÍTICO — Ação Imediata",     "#7a2e2e"
elif risk >= 40:
    stxt, scol = "ALTO — Atenção Urgente",       "#b34e4e"
elif risk >= 15:
    stxt, scol = "MÉDIO — Correção Planejada",   "#d4833a"
else:
    stxt, scol = "BAIXO — Monitoramento",        "#4a7c8c"
rdate = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
import time as _time
duration_secs = int(_time.time()) - SCAN_START_TS if SCAN_START_TS else 0
duration_str = f"{duration_secs//3600}h {(duration_secs%3600)//60}m {duration_secs%60}s" if duration_secs > 0 else "N/A"

def badge(sev):
    labels = {"critical":"CRÍTICO","high":"ALTO","medium":"MÉDIO","low":"BAIXO","info":"INFO"}
    c={"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#6e8f72"}.get(sev,"#999")
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{labels.get(sev, labels.get(sev.lower(), sev.upper()))}</span>'

def trows(items,empty="Sem resultados"):
    if not items: return f'<tr><td style="color:#999;font-style:italic">{empty}</td></tr>'
    return "".join(f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(i)}</td></tr>' for i in items[:50])

def _decode_cvss_vector(vec):
    """Decodifica os campos mais decisivos do vetor CVSS (exploitabilidade)."""
    if not vec:
        return ""
    parts = dict(p.split(":") for p in vec.split("/") if p.count(":") == 1)
    av = {"N":"Rede","A":"Adjacente","L":"Local","P":"Físico"}.get(parts.get("AV",""), "")
    ac = {"L":"Baixa","H":"Alta"}.get(parts.get("AC",""), "")
    pr = {"N":"Nenhum","L":"Baixo","H":"Alto"}.get(parts.get("PR",""), "")
    ui = {"N":"Nenhuma","R":"Requerida"}.get(parts.get("UI",""), "")
    bits = []
    if av: bits.append(f"Vetor: {av}")
    if ac: bits.append(f"Complexidade: {ac}")
    if pr: bits.append(f"Privilégio: {pr}")
    if ui: bits.append(f"Interação: {ui}")
    return " · ".join(bits)

def render_finding(f):
    # Enriquecer CVE com dados NVD/EPSS se disponível
    cve_val = f.get('cve','N/A')
    enrich_rows = ''
    # Extrair CVE IDs do campo cve
    cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', cve_val, re.IGNORECASE)
    for cve_id in [c.upper() for c in cve_ids]:
        ev = cve_enrichment.get(cve_id, {})
        if ev:
            cvss = ev.get('cvss_v3') or ev.get('cvss_v2')
            epss = ev.get('epss_score')
            epss_pct = ev.get('epss_percentile')
            sev = ev.get('severity','')
            desc_nvd = ev.get('description','')
            cvss_color = '#7a2e2e' if cvss and cvss>=9 else '#b34e4e' if cvss and cvss>=7 else '#d4833a' if cvss and cvss>=4 else '#27ae60'
            epss_color = '#7a2e2e' if epss and epss>=0.5 else '#d4833a' if epss and epss>=0.1 else '#27ae60'
            enrich_rows += f'<tr><th>{html.escape(cve_id)}</th><td>'
            _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
            sev_pt = _SEV_PT.get(str(sev).upper(), sev)
            # KEV badge — máxima prioridade, exibido antes de CVSS/EPSS
            in_kev = ev.get("in_kev", False)
            kev_info = ev.get("kev", {})
            if in_kev:
                kev_due = kev_info.get("due_date","")
                kev_added = kev_info.get("date_added","")
                kev_prod = f"{kev_info.get('vendor','')} {kev_info.get('product','')}".strip()
                enrich_rows += (f'<span style="background:#7a0000;color:white;padding:2px 10px;'
                    f'border-radius:4px;font-size:12px;font-weight:bold;'
                    f'border:2px solid #ff4444;letter-spacing:.3px">'
                    f'🔴 EXPLORAÇÃO ATIVA — CISA KEV</span> ')
                if kev_due: enrich_rows += f'<span style="background:#b34e4e;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Prazo CISA: {html.escape(kev_due)}</span> '
                if kev_prod: enrich_rows += f'<br><small style="color:#7a0000;font-weight:bold">Adicionado ao KEV em {html.escape(kev_added)} — {html.escape(kev_prod)}</small> '
            if cvss: enrich_rows += f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS {cvss} {html.escape(sev_pt)}</span> '
            if epss is not None: enrich_rows += f'<span style="background:{epss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px">EPSS {epss:.4f} ({epss_pct*100:.1f}° percentil)</span> '
            # Vetor CVSS — exibe a string e decodifica os campos de exploitabilidade
            _vec = ev.get("cvss_vector", "")
            if _vec:
                _dec = _decode_cvss_vector(_vec)
                enrich_rows += (f'<br><code style="font-size:10px;color:#666">{html.escape(_vec)}</code>'
                    + (f' <span style="font-size:10px;color:#888">({html.escape(_dec)})</span>' if _dec else ''))
            # Link direto para advisory NVD
            enrich_rows += (f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(cve_id)}" '
                f'target="_blank" style="font-size:11px;color:#388bfd;margin-left:6px">'
                f'Ver no NVD ↗</a> ')
            if desc_nvd: enrich_rows += f'<br><small style="color:#555">{html.escape(desc_nvd)}</small>'
            enrich_rows += '</td></tr>'
    # Fallback CWE sintético — quando não há CVE NVD disponível
    if not cve_ids or not enrich_rows:
        cwe_match = re.search(r'CWE-?(\d+)', cve_val, re.IGNORECASE)
        if cwe_match:
            cwe_data = cwe_enrich(cwe_match.group(1))
            if cwe_data:
                cvss = cwe_data["cvss"]
                _SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MÉDIO","LOW":"BAIXO"}
                sev_label = _SEV_PT.get(cwe_data["sev"], cwe_data["sev"])
                cwe_name = cwe_data["name"]
                cvss_color = '#7a2e2e' if cvss>=9 else '#b34e4e' if cvss>=7 else '#d4833a' if cvss>=4 else '#27ae60'
                enrich_rows += (f'<tr><th>CWE-{cwe_match.group(1)}</th><td>'
                    f'<span style="background:{cvss_color};color:white;padding:1px 6px;border-radius:3px;font-size:12px;font-weight:bold">CVSS ~{cvss} {sev_label}</span> '
                    f'<span style="background:#636e72;color:white;padding:1px 6px;border-radius:3px;font-size:11px">Estimativa baseada em CWE</span>'
                    f'<br><small style="color:#555">{html.escape(cwe_name)}</small>'
                    f'</td></tr>')
    # Badge de reclassificação — mostrar quando severidade original difere da atual
    sev_orig = f.get('severity_orig', f.get('severity',''))
    was_reclassified = f.get('severity_reclassified', False)
    reclassify_badge = ''
    if was_reclassified and sev_orig and sev_orig != f.get('severity',''):
        labels = {'critical':'CRÍTICO','high':'ALTO','medium':'MÉDIO','low':'BAIXO','info':'INFO'}
        orig_label = labels.get(sev_orig, sev_orig.upper())
        reclassify_badge = (f'<span style="background:#2d3436;color:#dfe6e9;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;margin-left:6px">'
            f'↑ Reclassificado de {orig_label} (CVE/CWE)</span>')

    rows = f"""
    <tr><th style="width:120px">CVE/CWE</th><td>{html.escape(str(f.get('cve','N/A')))}</td></tr>
    {enrich_rows}
    <tr><th>URL</th><td><code>{html.escape(f.get('url',''))}</code></td></tr>
    <tr><th>Descrição</th><td>{html.escape(f.get('description',''))}</td></tr>"""
    # Impacto prático — extrair CWE do campo cve para lookup no IMPACT_MAP
    _cwe_for_impact = re.search(r'CWE-?(\d+)', f.get("cve",""), re.IGNORECASE)
    _impact = IMPACT_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    _remediation_specific = REMEDIATION_MAP.get(_cwe_for_impact.group(1), "") if _cwe_for_impact else ""
    if _impact:
        rows += (f'\n    <tr><th style="background:#fff3cd;color:#856404">⚠ Impacto</th>'
            f'<td style="background:#fff3cd;color:#856404;font-weight:500">{html.escape(_impact)}</td></tr>')
    if _remediation_specific:
        rows += (f'\n    <tr><th style="background:#d4edda;color:#155724">✓ Como Corrigir</th>'
            f'<td style="background:#d4edda;color:#155724">{html.escape(_remediation_specific)}</td></tr>')
    if f.get('param'):
        rows += f"\n    <tr><th>Parâmetro</th><td><code>{html.escape(f['param'])}</code></td></tr>"
    if f.get('attack'):
        rows += f"\n    <tr><th>Ataque</th><td><code>{html.escape(f['attack'])}</code></td></tr>"
    # Exibir evidência dividida em blocos legíveis
    _ev_full = f.get("evidence","")
    if _ev_full:
        _req_match  = re.search(r"--- REQUISIÇÃO HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _res_match  = re.search(r"--- RESPOSTA HTTP ---\n(.*?)(?=---|$)", _ev_full, re.DOTALL)
        _ev_other   = re.sub(r"--- (REQUISIÇÃO|RESPOSTA) HTTP ---\n.*?(?=---|$)", "", _ev_full, flags=re.DOTALL).strip()
        if _ev_other:
            rows += f'\n    <tr><th>Evidência</th><td><div class="evidence-box">{html.escape(_ev_other)}</div></td></tr>'
        if _req_match:
            rows += f'\n    <tr><th>Requisição HTTP</th><td><div class="evidence-box">{html.escape(_req_match.group(1).strip())}</div></td></tr>'
        if _res_match:
            rows += f'\n    <tr><th>Resposta HTTP</th><td><div class="evidence-box">{html.escape(_res_match.group(1).strip())}</div></td></tr>'
    if f.get('affected_count', 0) > 1:
        n = f['affected_count']
        urls_sample = f.get('affected_urls', [])
        url_list = ''.join(f'<li><code>{html.escape(u)}</code></li>' for u in urls_sample)
        rows += (f'\n    <tr><th>URLs Afetadas</th>'
            f'<td><strong>{n} ocorrência(s)</strong> do mesmo tipo de alerta:<ul style="margin:6px 0 0;padding-left:18px">{url_list}</ul></td></tr>')
    other_val = f.get('other','')
    if other_val and '[URLs afetadas]' not in other_val:
        rows += f"\n    <tr><th>Detalhe</th><td>{html.escape(other_val)}</td></tr>"
    rows += f"\n    <tr><th>Recomendação</th><td>{html.escape(f.get('remediation',''))}</td></tr>"
    _src = f.get('source','')
    src_cls = ('source-nuclei'  if _src == 'Nuclei'              else
               'source-headers' if _src == 'Security Headers'    else
               'source-version' if _src == 'Version Fingerprint' else
               'source-zap')
    confirmed_badge = ''
    _cat = _confirmed_category(f)
    if _cat == "exploit":
        confirmed_badge = ('<span style="background:#7a0000;color:white;padding:2px 8px;'
            'border-radius:4px;font-size:10px;font-weight:bold;margin-left:6px;'
            'border:1px solid #ff4444">✓ EXPLOIT CONFIRMADO</span>')
    elif _cat == "verified":
        confirmed_badge = ('<span style="background:#1b5e20;color:white;padding:2px 8px;'
            'border-radius:4px;font-size:10px;font-weight:bold;margin-left:6px;'
            'border:1px solid #2e7d32">✓ VERIFICADO</span>')
    return f'''<div class="vuln {f['severity']}">
  <h3>{html.escape(f.get('name',''))} <span class="source-badge {src_cls}">{f.get('source','')}</span> {badge(f['severity'])}{reclassify_badge}{confirmed_badge}</h3>
  <table>{rows}
  </table></div>'''

# TLS e Email têm seções HTML próprias — excluir dos cards principais para não duplicar
_DEDICATED_SOURCES = {"testssl.sh", "Email Security"}
# Only render critical / high / medium as detailed cards
_main_findings = [f for f in all_f if f["severity"] in ("critical","high","medium") and f.get("source") not in _DEDICATED_SOURCES]
vhtml = (
    '<div class="info-box"><p>✅ Nenhuma vulnerabilidade encontrada no escopo analisado.</p></div>'
    if not _main_findings
    else "".join(render_finding(f) for f in _main_findings)
)

# ── Consolidated Low / Info table (all sources) ───────────────
# Collect low/info items from every source: Nuclei, Security Headers,
# Version Fingerprint, and ZAP low_groups (already grouped by name).
_low_info_findings = [f for f in all_f if f["severity"] in ("low","info") and f.get("source") not in _DEDICATED_SOURCES]

low_table_html = ""
if _low_info_findings or zap_low_groups:
    _src_color = {
        "Nuclei":              "#3498db",
        "ZAP":                 "#e74c3c",
        "Security Headers":    "#7d3c98",
        "Version Fingerprint": "#d35400",
    }
    rows_low = ""
    # Rows from all_f (low/info)
    for f in sorted(_low_info_findings, key=lambda x: ({"low":0,"info":1}.get(x["severity"],2), x.get("source",""), x.get("name",""))):
        src = f.get("source","")
        src_col = _src_color.get(src, "#636e72")
        rows_low += (
            f'<tr>'
            f'<td style="font-size:12px">{html.escape(f.get("name",""))}</td>'
            f'<td style="text-align:center">{badge(f["severity"])}</td>'
            f'<td style="text-align:center"><span style="background:{src_col};color:white;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold">'
            f'{html.escape(src)}</span></td>'
            f'<td style="font-size:11px">{html.escape(f.get("cve","—") or "—")}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(f.get("description","") or "")}</td>'
            f'<td style="font-size:11px">{html.escape(f.get("remediation","") or "")}</td>'
            f'</tr>'
        )
    # Rows from ZAP low_groups (deduplicated ZAP low/info)
    for name, grp in sorted(zap_low_groups.items()):
        src_col = _src_color.get("ZAP","#e74c3c")
        urls_str = ", ".join(grp["urls"][:3])
        if len(grp["urls"]) > 3:
            urls_str += f" (+{len(grp['urls'])-3})"
        rows_low += (
            f'<tr>'
            f'<td style="font-size:12px">{html.escape(name)}'
            f'{"<br><span style=\\'font-size:10px;color:#888\\'>" + html.escape(urls_str) + "</span>" if urls_str else ""}'
            f'</td>'
            f'<td style="text-align:center">{badge(grp.get("sev","low"))}</td>'
            f'<td style="text-align:center"><span style="background:{src_col};color:white;'
            f'padding:2px 7px;border-radius:4px;font-size:10px;font-weight:bold">ZAP</span></td>'
            f'<td style="font-size:11px">{html.escape(grp.get("cve","—") or "—")}</td>'
            f'<td style="font-size:11px;color:#555">{grp["count"]} ocorrência(s) — confiança: {html.escape(grp.get("conf","?"))}</td>'
            f'<td style="font-size:11px">{html.escape((grp["finding"].get("remediation") or ""))}</td>'
            f'</tr>'
        )
    _total_low = len(_low_info_findings) + len(zap_low_groups)
    low_table_html = f'''<h2>4. Achados Baixo / Informativo ({_total_low} item(ns))</h2>
    <p style="color:#666;font-size:13px">Itens de baixa/info prioridade consolidados. Validar e endereçar após as correções críticas.</p>
    <table>
      <tr style="background:#f5f5f5">
        <th>Achado</th><th style="width:80px">Sev</th><th style="width:120px">Fonte</th>
        <th style="width:130px">CVE / CWE</th><th>Descrição</th><th>Recomendação</th>
      </tr>
      {rows_low}
    </table>'''

# ── Gerar HTML: WAF & Email Security ────────────────────────
waf_email_html = ''

# WAF banner
if WAF_DETECTED and WAF_NAME:
    waf_email_html += (f'<div style="background:#fff3cd;border-left:5px solid #d4833a;'
        f'padding:14px 16px;border-radius:4px;margin:16px 0">'
        f'<strong style="color:#856404">🛡 WAF Detectado: {html.escape(WAF_NAME)}</strong>'
        f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
        f'O alvo está protegido por um Web Application Firewall. Achados do active scan '
        f'podem ter falsos negativos — vulnerabilidades de injeção podem ter sido bloqueadas '
        f'durante o scan sem serem detectadas.</p></div>')

# Email security
if email_security:
    sev_color = {'high':'#b34e4e','medium':'#d4833a','low':'#4a7c8c','none':'#27ae60'}
    sev_label = {'high':'ALTO','medium':'MÉDIO','low':'BAIXO','none':'OK','NOT_FOUND':'INFO'}
    email_rows = ''
    for proto, data in [('SPF', email_security.get('spf',{})),
                         ('DMARC', email_security.get('dmarc',{})),
                         ('DKIM',  email_security.get('dkim',{}))]:
        sev  = data.get('severity','none')
        stat = data.get('status','?')
        det  = data.get('detail','')
        rec  = data.get('recommendation','')
        val  = data.get('value','')
        sc   = sev_color.get(sev,'#999')
        sl   = sev_label.get(stat, sev_label.get(sev,'?'))
        email_rows += (f'<tr>'
            f'<td style="font-weight:bold;width:80px">{proto}</td>'
            f'<td style="text-align:center"><span style="background:{sc};color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{sl}</span></td>'
            f'<td>{html.escape(det)}</td>'
            f'<td style="font-size:11px;color:#555">{html.escape(rec) if rec else ("<code>"+html.escape(val)+"</code>" if val else "—")}</td>'
            f'</tr>')
    waf_email_html += (f'<h3>Segurança de Email — {html.escape(DOMAIN)}</h3>'
        '<table><tr style="background:#f5f5f5">'
        '<th>Protocolo</th><th>Status</th><th>Detalhe</th><th>Recomendação / Valor</th></tr>'
        + email_rows + '</table>')

if waf_email_html:
    waf_email_html = f'<h2>Infraestrutura & Segurança DNS</h2>' + waf_email_html

# ── Gerar HTML: Comportamento do Scan ─────────────────────────
scan_behavior_html = ""
if scan_meta:
    evasion_active = scan_meta.get("evasion_active", False)
    waf_n          = scan_meta.get("waf_name", "")
    techniques     = scan_meta.get("evasion_techniques", [])
    rl             = scan_meta.get("nuclei_rate_limit", 50)
    conc           = scan_meta.get("nuclei_concurrency", 10)
    delay          = scan_meta.get("nuclei_delay")
    ua             = scan_meta.get("user_agent", "")
    nuc_count      = scan_meta.get("nuclei_results_after_evasion")
    zap_count      = scan_meta.get("zap_results_after_evasion")

    TECH_LABELS = {
        "rate_limit_reduced":     ("🐢", "Rate limit reduzido",     f"Nuclei: {rl} req/s com delay randômico — imita tráfego humano"),
        "user_agent_rotation":    ("🔄", "User-Agent rotation",     f"UA de browser real: {ua[:60]}..." if len(ua)>60 else f"UA: {ua}"),
        "origin_spoofing":        ("🎭", "Origin spoofing",         "X-Forwarded-For: 127.0.0.1 + X-Real-IP: 127.0.0.1 injetados"),
        "payload_alterations":    ("🔀", "Payload alterations",     "Nuclei testou variações de encoding automaticamente (-pa)"),
        "waf_response_bypass":    ("⏭", "WAF response bypass",     "Respostas 403/406/429 ignoradas — scan não interrompe em bloqueios"),
        "zap_threads_reduced":    ("🧵", "ZAP threads reduzidas",   "Active scan com 2 threads — reduz assinatura de scan automatizado"),
    }

    if evasion_active:
        tech_rows = "".join(
            f'<tr>'
            f'<td style="font-size:18px;text-align:center;width:36px">{icon}</td>'
            f'<td style="font-weight:600;width:180px">{label}</td>'
            f'<td style="color:#555;font-size:13px">{desc}</td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">ATIVO</span></td>'
            f'</tr>'
            for t in techniques for icon, label, desc in [TECH_LABELS.get(t, ("","",""))]
            if label
        )

        results_row = ""
        if nuc_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{nuc_count}</div>'
                f'<div style="font-size:12px;color:#555">achados Nuclei\ncom evasão</div></div>')
        if zap_count is not None:
            results_row += (f'<div style="display:inline-block;background:#f0f7ff;'
                f'border:1px solid #388bfd;border-radius:8px;padding:12px 20px;margin:6px 8px 6px 0">'
                f'<div style="font-size:28px;font-weight:bold;color:#1a3a4f">{zap_count}</div>'
                f'<div style="font-size:12px;color:#555">alertas ZAP\ncom evasão</div></div>')

        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan & Evasão Passiva</h2>'
            f'<div style="background:#fff8e6;border-left:5px solid #d4833a;'
            f'padding:16px;border-radius:4px;margin-bottom:16px">'
            f'<strong style="color:#856404">⚠ WAF Detectado: {html.escape(waf_n)}</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O scanner detectou um WAF e ativou automaticamente o modo de evasão passiva. '
            f'As técnicas abaixo foram aplicadas para maximizar a cobertura e reduzir falsos negativos.</p></div>'
            f'<h3 style="color:#1a3a4f;margin-bottom:8px">Técnicas de Evasão Passiva Aplicadas</h3>'
            f'<table style="margin-bottom:16px"><tr style="background:#f5f5f5">'
            f'<th></th><th style="text-align:left">Técnica</th>'
            f'<th style="text-align:left">Detalhe</th><th>Status</th></tr>'
            + tech_rows +
            f'</table>'
            + (f'<h3 style="color:#1a3a4f;margin-bottom:8px">Resultados com Evasão Ativa</h3>'
               f'<div style="margin-bottom:8px">{results_row}</div>'
               f'<p style="font-size:12px;color:#888;margin:4px 0">Resultados obtidos após aplicação das técnicas de evasão. '
               f'Comparar com scans sem evasão não é aplicável pois o WAF teria bloqueado requests anteriores.</p>'
               if results_row else "")
        )
    else:
        # Sem WAF — registrar que scan foi direto
        scan_behavior_html = (
            f'<h2>🔬 Comportamento do Scan</h2>'
            f'<div style="background:#f0fff4;border-left:5px solid #27ae60;'
            f'padding:14px 16px;border-radius:4px">'
            f'<strong style="color:#1a7a4a">✓ Nenhum WAF Detectado — Scan Direto</strong>'
            f'<p style="margin:6px 0 0;font-size:13px;color:#555">'
            f'O alvo não possui WAF identificado. O scan rodou com configurações padrão '
            f'(Nuclei {rl} req/s, concurrency {conc}). '
            f'Resultados têm alta confiança — sem filtros intermediários.</p></div>'
        )

errsec = "" if not errors else \
    '<h2>⚠ Avisos de Processamento</h2><div class="info-box" style="border-left-color:#d4833a"><ul>' + \
    "".join(f"<li><code>{html.escape(e)}</code></li>" for e in errors) + "</ul></div>"

# ── Gerar HTML: Análise JS ───────────────────────────────────
js_html = ""
if js_analysis:
    HIGH_JS_TYPES = {"AWS Access Key","AWS Secret","Private Key","Stripe Live Key",
        "GitHub Token","GitLab PAT","OpenAI Key","Anthropic Key","Hardcoded Password",
        "DB Connection String","Firebase Key","Slack Token"}
    def js_sev(t): return "high" if t in HIGH_JS_TYPES else "medium"
    def js_sev_color(s): return {"high":"#b34e4e","medium":"#d4833a"}.get(s,"#4a7c8c")
    def js_badge(t):
        s=js_sev(t); c=js_sev_color(s)
        lbl={"high":"ALTO","medium":"MÉDIO"}.get(s,"BAIXO")
        return f'<span style="background:{c};color:white;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:bold">{lbl}</span>'

    # Stat bar JS
    js_accessible = [p for p in js_probes if p.get("status")==200]
    js_exposed_api = [p for p in js_probes if p.get("status")==200 and p.get("is_json")]
    js_vuln_fw = [f for f in js_frameworks if f.get("vulnerable")]
    js_html = f'''<h2>JS / Frontend — Análise de Segurança</h2>
    <div class="info-box">
      <table>
        <tr><th style="width:200px">Arquivos JS analisados</th><td>{len(js_files_list)}</td></tr>
        <tr><th>Secrets / credenciais</th><td><span style="color:#b34e4e;font-weight:bold">{sum(1 for s in js_secrets if js_sev(s["type"])=="high")}</span> alto &nbsp;|&nbsp; <span style="color:#d4833a">{sum(1 for s in js_secrets if js_sev(s["type"])=="medium")}</span> médio</td></tr>
        <tr><th>Endpoints descobertos</th><td>{len(js_endpoints)} &nbsp;|&nbsp; {len(js_accessible)} acessíveis sem autenticação</td></tr>
        <tr><th>Frameworks detectados</th><td>{len(js_frameworks)} ({len(js_vuln_fw)} com CVE conhecida)</td></tr>
        <tr><th>Comentários sensíveis</th><td>{len(js_comments)}</td></tr>
      </table>
    </div>'''

    # Secrets
    if js_secrets:
        from collections import defaultdict
        by_type = defaultdict(list)
        for s in js_secrets: by_type[s["type"]].append(s)
        js_html += "<h3>Secrets e Credenciais Detectadas</h3>"
        for stype, items in sorted(by_type.items(), key=lambda x: 0 if js_sev(x[0])=="high" else 1):
            c = js_sev_color(js_sev(stype))
            js_html += (f'<div style="border-left:5px solid {c};padding:14px 16px;margin:12px 0;'
                f'background:#ffffff;border-radius:6px;border:1px solid #e0e0e0;box-shadow:0 1px 3px rgba(0,0,0,.06)">'
                f'<div style="margin-bottom:10px">'
                f'<strong style="font-size:14px">{html.escape(stype)}</strong> {js_badge(stype)}'
                f' <span style="color:#888;font-size:12px;margin-left:6px">({len(items)} ocorrência(s))</span>'
                f'</div>'
                f'<table style="width:100%;border-collapse:collapse">'
                f'<tr>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd;width:35%">Valor / Pattern</th>'
                f'<th style="background:#f5f5f5;color:#1a3a4f;font-weight:700;font-size:12px;'
                f'padding:8px 12px;text-align:left;border:1px solid #ddd">Contexto no Código</th>'
                f'</tr>')
            for item in items:
                v    = item["value"]
                ctx  = item.get("context", "")
                furl = item.get("url", "")
                js_html += (
                    f'<tr>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top;background:#fafafa">'
                    f'<code style="font-size:11px;color:#c0392b;background:#fff5f5;padding:3px 6px;'
                    f'border-radius:3px;word-break:break-all;display:block">{html.escape(v)}</code>'
                    + (f'<div style="font-size:10px;color:#888;margin-top:5px">📄 {html.escape(furl)}</div>' if furl else "")
                    + f'</td>'
                    f'<td style="padding:8px 12px;border:1px solid #eee;vertical-align:top">'
                    f'<pre style="margin:0;font-size:10px;font-family:monospace;background:#f8f9fa;'
                    f'color:#333;padding:6px 8px;border-radius:3px;white-space:pre-wrap;'
                    f'word-break:break-all;border:1px solid #e0e0e0;max-height:160px;'
                    f'overflow-y:auto">{html.escape(ctx) if ctx else "—"}</pre>'
                    + f'</td></tr>')
            js_html += "</table></div>"

    # Frameworks
    if js_frameworks:
        seen_fw = {}
        fw_rows = ""
        for fw in js_frameworks:
            k = (fw["framework"],fw["version"])
            if k in seen_fw: continue
            seen_fw[k]=True
            vuln_html = ('<span style="color:#b34e4e;font-weight:bold">⚠ ' +
                ', '.join(v["cve"] for v in fw.get("vulns",[])) + '</span>')\
                if fw.get("vulnerable") else '<span style="color:#27ae60">✓ OK</span>'
            fw_rows += (f'<tr><td><strong>{html.escape(fw["framework"])}</strong></td>'
                f'<td><code>{html.escape(fw["version"])}</code></td>'
                f'<td>{vuln_html}</td></tr>')
        js_html += ('<h3>Frameworks Detectados</h3>'
            '<table><tr style="background:#f5f5f5"><th>Framework</th><th>Versão</th><th>Status</th></tr>'
            + fw_rows + '</table>')

    # Endpoints acessíveis
    if js_accessible:
        ep_rows = "".join(
            f'<tr><td><code style="font-size:11px;word-break:break-all">{html.escape(p["url"])}</code></td>'
            f'<td style="text-align:center"><span style="background:#27ae60;color:white;'
            f'padding:1px 6px;border-radius:3px;font-size:11px">{p["status"]}</span></td>'
            f'<td style="font-size:11px">{"JSON API" if p.get("is_json") else "HTML"}</td></tr>'
            for p in js_accessible[:15])
        js_html += ('<h3>Endpoints Acessíveis Sem Autenticação</h3>'
            '<table><tr style="background:#f5f5f5"><th>URL</th><th>HTTP</th><th>Tipo</th></tr>'
            + ep_rows + '</table>')

    # Comentários sensíveis
    if js_comments:
        comm_rows = "".join(
            f'<tr><td style="padding:6px 10px;border-bottom:1px solid #eee">'
            f'<code style="font-size:11px;background:#f8f9fa;color:#c0392b;'
            f'padding:3px 6px;border-radius:3px;display:block;white-space:pre-wrap;'
            f'word-break:break-all;border:1px solid #e0e0e0">{html.escape(c["comment"])}</code>'
            f'<div style="font-size:10px;color:#888;margin-top:3px">📄 {html.escape(c.get("url",""))}</div>'
            f'</td></tr>'
            for c in js_comments[:10])
        js_html += ('<h3>Comentários Sensíveis no Código</h3>'
            '<table style="width:100%;border-collapse:collapse;border:1px solid #eee;border-radius:6px">'
            + comm_rows + '</table>')

# ── Gerar HTML: TLS ─────────────────────────────────────────
SEV_TLS_CLASS = {"critical":"tls-critical","high":"tls-high","medium":"tls-warn","low":"tls-warn","info":"tls-ok"}
if tls_findings:
    TLS_SEV_PT = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","WARN":"AVISO","LOW":"BAIXO","OK":"OK","INFO":"INFO"}
    def _tls_problem_cell(f):
        cell = html.escape(f.get("name", f.get("finding", "")))
        _c = _confirmed_category(f)
        if _c == "exploit":
            cell += ('  <span style="background:#7a0000;color:white;padding:1px 6px;'
                'border-radius:3px;font-size:10px;font-weight:bold">✓ EXPLORÁVEL</span>')
        elif _c == "verified":
            cell += ('  <span style="background:#1b5e20;color:white;padding:1px 6px;'
                'border-radius:3px;font-size:10px;font-weight:bold">✓ VERIFICADO</span>')
        return cell
    tls_rows = "".join(
        f'<tr><td style="font-family:monospace;font-size:12px">{html.escape(f["id"])}</td>'
        f'<td class="{SEV_TLS_CLASS.get(f["sev"],"tls-ok")}">{html.escape(TLS_SEV_PT.get(f["sev_raw"].upper(),f["sev_raw"]))}</td>'
        f'<td>{_tls_problem_cell(f)}</td>'
        f'<td>{html.escape(f["cve"] or "—")}</td></tr>'
        for f in tls_findings
    )
    tls_html = f'''<h2>TLS / SSL — {len(tls_findings)} problema(s) identificado(s)</h2>
    <table>
      <tr style="background:#f5f5f5"><th>Identificador</th><th>Severidade</th><th>Problema</th><th>CVE/CWE</th></tr>
      {tls_rows}
    </table>'''
else:
    tls_html = ""

# ── Gerar HTML: Confirmação Ativa (Exploits vs Verificações) ─────────
def _conf_row(c):
    status_color = "#27ae60" if c.get("confirmed") else "#b34e4e"
    status_label = "✓ CONFIRMADO" if c.get("confirmed") else "✗ NÃO CONFIRMADO"
    sev_colors = {"critical":"#7a2e2e","high":"#b34e4e","medium":"#d4833a","low":"#4a7c8c","info":"#888"}
    sev_c = sev_colors.get(c.get("severity","info"),"#888")

    evidence_html = ""
    if c.get("response_headers"):
        evidence_html += (
            f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Headers</div>'
            f'<div class="evidence-box" style="margin-bottom:8px">{html.escape(str(c.get("response_headers","")))}</div>'
        )
    if c.get("response_body"):
        evidence_html += (
            f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Response Body</div>'
            f'<div class="evidence-box">{html.escape(str(c.get("response_body","")))}</div>'
        )
    if not evidence_html:
        evidence_html = '<span style="color:#888">—</span>'

    curl_repr = c.get("curl_reproducible") or c.get("curl_command","")
    curl_html = (
        f'<div style="font-size:11px;font-weight:600;color:#555;margin-bottom:3px">Reproduzir:</div>'
        f'<div class="evidence-box" style="background:#1e3a4f;color:#a8d8ea;font-size:11px">'
        f'{html.escape(curl_repr)}</div>'
    ) if curl_repr else ""

    conf = c.get("confidence", 0)
    vt   = c.get("vuln_type", "")
    return (
        f'<tr>'
        f'<td style="vertical-align:top">'
        f'  <code style="font-size:12px">{html.escape(str(c.get("template_id","—")))}</code><br>'
        f'  <span style="background:{sev_c};color:white;padding:1px 6px;border-radius:3px;font-size:10px">'
        f'  {str(c.get("severity","info")).upper()}</span>'
        f'</td>'
        f'<td style="vertical-align:top"><code style="font-size:11px;word-break:break-all">{html.escape(str(c.get("url","—")))}</code></td>'
        f'<td style="text-align:center;vertical-align:top">'
        f'  <span style="background:{status_color};color:white;padding:3px 8px;border-radius:4px;'
        f'  font-size:11px;font-weight:bold;white-space:nowrap">{status_label}</span><br>'
        f'  <code style="font-size:13px;font-weight:bold;color:{status_color}">{html.escape(str(c.get("http_status","—")))}</code>'
        f'</td>'
        f'<td style="text-align:center;vertical-align:top">'
        f'<div style="font-size:24px;font-weight:bold;color:{"#27ae60" if conf>=80 else ("#d4833a" if conf>=50 else "#b34e4e")}">{conf}%</div>'
        f'<div style="font-size:10px;color:#888;margin-top:2px">{html.escape(vt)}</div>'
        f'</td>'
        f'<td style="vertical-align:top">'
        f'<div style="background:#f0f7ff;border-left:3px solid #388bfd;padding:6px 10px;border-radius:3px;font-size:12px;margin-bottom:8px">'
        f'<strong>Nota:</strong> {html.escape(c.get("poc_note","—"))}</div>'
        f'{evidence_html}{curl_html}'
        f'</td>'
        f'</tr>'
    )

def _conf_table(title, subtitle, items):
    rows = "".join(_conf_row(c) for c in items)
    return (
        f'<h3>{title} ({len(items)})</h3>'
        f'<p style="color:#666;font-size:13px">{subtitle}</p>'
        f'<table><tr style="background:#f5f5f5">'
        f'<th style="width:160px">Template</th><th>URL</th>'
        f'<th style="width:110px">Status</th><th style="width:80px">Confiança</th>'
        f'<th>Evidência & Nota PoC</th></tr>' + rows + f'</table>'
    )

if confirmations:
    _exploits = [c for c in confirmations if c.get("confirmed") and c.get("category") == "exploit"]
    _verified = [c for c in confirmations if c.get("confirmed") and c.get("category") == "verified"]
    _notconf  = [c for c in confirmations if not c.get("confirmed")]
    confirm_html = (
        f'<h2>Confirmação Ativa — {len(_exploits)} exploit(s) · {len(_verified)} verificação(ões)</h2>'
        f'<p style="color:#666;font-size:13px">Cada achado foi re-executado. '
        f'<strong>Exploits</strong> são vulnerabilidades abusáveis diretamente; '
        f'<strong>verificações</strong> confirmam configurações/hardening (ex: header ausente, '
        f'config TLS) — relevantes, mas não exploráveis por si só.</p>'
    )
    if _exploits:
        confirm_html += _conf_table(
            "🔴 Exploits Confirmados",
            "Vulnerabilidades abusáveis com PoC reproduzível.", _exploits)
    if _verified:
        confirm_html += _conf_table(
            "🔵 Verificações Ativas",
            "Issues de configuração/hardening confirmados via re-execução.", _verified)
    if _notconf:
        confirm_html += _conf_table(
            "⚪ Não Confirmados",
            "Achados que não puderam ser confirmados na re-execução.", _notconf)
else:
    confirm_html = (
        f'<h2>Confirmação Ativa de Exploits</h2>'
        f'<div style="background:#f5f5f5;border-left:4px solid #888;padding:14px 16px;'
        f'border-radius:4px;color:#666;font-size:13px">'
        f'<strong>Nenhum achado elegível para confirmação ativa.</strong><br>'
        f'A confirmação ativa roda apenas em achados Nuclei com severidade '
        f'Crítica, Alta ou Média que incluam curl-command. '
        f'Se o scan usou apenas o ZAP, os achados aparecem na seção de '
        f'Vulnerabilidades Identificadas com evidência de request/response completo.'
        f'</div>'
    )


# ── Gerar HTML: Plano de Ação Priorizado ─────────────────────────
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

# Coletar todos os achados acionáveis por prazo
imediato  = [f for f in all_f if f["severity"] in ("critical","high") and f.get("source") not in _DEDICATED_SOURCES]
sprint    = [f for f in all_f if f["severity"] == "medium" and f.get("source") not in _DEDICATED_SOURCES]
backlog   = [f for f in zap_low_groups.values() if f["sev"] in ("low","info")]

def action_card(title, icon, color, bg, items, prazo, descricao):
    if not items: return ""
    rows = ""
    seen_names = set()
    for item in items[:10]:
        name = item.get("name","") if isinstance(item,dict) and "name" in item else item.get("finding",{}).get("name","")
        if name in seen_names: continue
        seen_names.add(name)
        count = item.get("affected_count",1) if isinstance(item,dict) and "affected_count" in item else item.get("count",1)
        sev_f = item.get("severity","") if "severity" in item else item.get("sev","")
        count_str = f" <span style='color:#666;font-size:11px'>({count} ocorrência(s))</span>" if count > 1 else ""
        rows += f"<li style='margin:4px 0'><strong>{html.escape(name)}</strong>{count_str}</li>"
    return f"""<div style="border-left:5px solid {color};padding:16px;margin:12px 0;background:{bg};border-radius:4px">
  <h3 style="margin:0 0 6px;color:{color}">{icon} {html.escape(title)} <span style="font-size:12px;font-weight:normal;color:#666">— Prazo: {prazo}</span></h3>
  <p style="margin:0 0 10px;font-size:13px;color:#555">{descricao}</p>
  <ul style="margin:0;padding-left:20px;font-size:13px">{rows}</ul>
</div>"""

plan_parts = []
plan_parts.append(action_card(
    "Ação Imediata","🔴","#7a2e2e","#fff0f0",
    imediato,"esta semana",
    "Vulnerabilidades críticas e altas com potencial de comprometimento direto. Paralisar deploy se necessário."
))
plan_parts.append(action_card(
    "Próximo Sprint","🟡","#d4833a","#fff8f0",
    sprint,"próximas 2 semanas",
    "Achados médios que reduzem superfície de ataque. Incluir nas próximas histórias do time."
))
plan_parts.append(action_card(
    "Backlog de Segurança","🔵","#4a7c8c","#f0f8ff",
    backlog,"próximos 30 dias",
    "Melhorias de hardening e headers. Agendar como dívida técnica de segurança."
))

action_plan_html = ""
if any(plan_parts):
    action_plan_html = f"""<h2>Plano de Ação para o Time</h2>
<div class="info-box">
  <p>Priorização baseada em CVSS + EPSS. Achados com maior probabilidade de exploração ativa foram priorizados.</p>
</div>
{"".join(plan_parts)}"""

# ── Matriz Esforço × Impacto (priorização estilo Big4) ───────────
def _estimate_effort(f):
    """Esforço de correção: baixo (config/infra) / médio / alto (código/arquitetura)."""
    cve  = str(f.get("cve", "")).upper()
    name = str(f.get("name", "")).lower()
    src  = f.get("source", "")
    _m   = re.search(r'CWE-?(\d+)', cve)
    cwe  = _m.group(1) if _m else ""
    HIGH_CWE = {"89","78","77","94","502","611","918","22","23","287","306",
                "352","384","843","917","98","434"}
    if cwe in HIGH_CWE: return "alto"
    if any(k in name for k in ("sql injection","sqli","command inject","rce",
            "remote code","deserial","ssrf","xxe","path traversal","authentication",
            "authorization","bypass","csrf","ssti","file upload","lfi")):
        return "alto"
    LOW_CWE = {"693","1021","319","614","1004","532","16"}
    if cwe in LOW_CWE: return "baixo"
    if src in ("Email Security", "testssl.sh"): return "baixo"
    if any(k in name for k in ("header","hsts","spf","dmarc","dkim","cipher","tls/ssl",
            "ssl","cookie","clickjacking","security.txt","caa","ocsp","rate limit")):
        return "baixo"
    return "médio"

def _impact_tier(sev):
    return "alto" if sev in ("critical","high") else "médio" if sev == "medium" else "baixo"

_matrix = {}
_seen_m = set()
for f in all_f:
    sev = f.get("severity", "")
    if sev not in ("critical","high","medium","low"): continue
    nm = f.get("name", "")
    if not nm or nm in _seen_m: continue
    _seen_m.add(nm)
    _matrix.setdefault((_impact_tier(sev), _estimate_effort(f)), []).append((nm, sev))

def _matrix_cell(imp, eff, highlight=False):
    items = sorted(_matrix.get((imp, eff), []), key=lambda x: SEV_ORDER.get(x[1], 9))
    if not items:
        body = '<span style="color:#ccc">—</span>'
    else:
        body = "<br>".join(f'{badge(s)} {html.escape(n[:46])}' for n, s in items[:7])
        if len(items) > 7:
            body += f'<br><span style="color:#888;font-size:11px">+{len(items)-7} mais</span>'
    bg = "#eafaf1" if highlight else "#fff"
    tag = ('<div style="font-size:10px;font-weight:bold;color:#1b5e20;margin-bottom:4px">★ QUICK WINS</div>'
           if highlight else "")
    return f'<td style="vertical-align:top;background:{bg};padding:8px;font-size:12px;border:1px solid #e0e0e0">{tag}{body}</td>'

priority_matrix_html = ""
if _seen_m:
    priority_matrix_html = f"""<h2>Matriz de Priorização — Esforço × Impacto</h2>
<div class="info-box"><p style="font-size:13px">Cruza o <strong>impacto</strong> (severidade)
com o <strong>esforço</strong> estimado de correção. O quadrante <strong>alto impacto + baixo
esforço</strong> são os <strong>quick wins</strong> — máxima prioridade de execução.</p></div>
<table style="border-collapse:collapse;width:100%">
<tr style="background:#1a3a4f;color:white">
  <th style="padding:8px;width:90px"></th>
  <th style="padding:8px">Esforço Baixo<br><span style="font-weight:normal;font-size:11px">config / infra</span></th>
  <th style="padding:8px">Esforço Médio<br><span style="font-weight:normal;font-size:11px">upgrade / tuning</span></th>
  <th style="padding:8px">Esforço Alto<br><span style="font-weight:normal;font-size:11px">código / arquitetura</span></th>
</tr>
<tr><th style="background:#7a2e2e;color:white;padding:8px">Impacto<br>Alto</th>
  {_matrix_cell("alto","baixo",highlight=True)}{_matrix_cell("alto","médio")}{_matrix_cell("alto","alto")}</tr>
<tr><th style="background:#d4833a;color:white;padding:8px">Impacto<br>Médio</th>
  {_matrix_cell("médio","baixo")}{_matrix_cell("médio","médio")}{_matrix_cell("médio","alto")}</tr>
<tr><th style="background:#4a7c8c;color:white;padding:8px">Impacto<br>Baixo</th>
  {_matrix_cell("baixo","baixo")}{_matrix_cell("baixo","médio")}{_matrix_cell("baixo","alto")}</tr>
</table>"""

# ── Gerar HTML: Inventário de Tecnologias Detectadas ─────────
tech_inventory_html = ""
if tech_detected:
    # Coletar techs desatualizadas a partir do version_findings
    outdated_names = set()
    for _vf in version_findings:
        if _vf.get("is_outdated"):
            _m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', _vf.get("name",""))
            if _m:
                outdated_names.add(_m.group(1).strip().lower())

    # Mapa de CVEs por tecnologia (de version_findings)
    tech_cve_map = {}
    for _vf in version_findings:
        _m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', _vf.get("name",""))
        if _m:
            _tn = _m.group(1).strip()
            tech_cve_map[_tn.lower()] = re.sub(r'CWE-[0-9]+\s*[—-]\s*','', _vf.get("cve",""))[:80]

    rows = ""
    for _tech_name, _info in sorted(tech_detected.items(), key=lambda x: x[0].lower()):
        _version    = _info.get("version","") or "—"
        _source     = _info.get("source","")
        _confidence = _info.get("confidence","medium")
        _is_outdated = _tech_name.lower() in outdated_names or _info.get("outdated", False)
        _is_vuln_fw  = _info.get("vulnerable", False)

        if _is_outdated:
            _sbg, _slbl = "#b34e4e", "⚠ DESATUALIZADO"
        elif _is_vuln_fw:
            _sbg, _slbl = "#d4833a", "⚠ VULNERÁVEL"
        elif _confidence == "confirmed":
            _sbg, _slbl = "#27ae60", "✓ CONFIRMADO"
        else:
            _sbg, _slbl = "#6e8f72", "✓ DETECTADO"

        _cves = tech_cve_map.get(_tech_name.lower(), "")
        _src_labels = {"httpx":"httpx","probe":"probe","path_fingerprint":"path","js_analysis":"JS"}
        _src_label = _src_labels.get(_source, _source)

        rows += (
            f'<tr>'
            f'<td style="font-weight:600">{html.escape(_tech_name)}</td>'
            f'<td><code style="font-size:12px">{html.escape(str(_version))}</code></td>'
            f'<td style="text-align:center">'
            f'<span style="background:{_sbg};color:white;padding:2px 8px;border-radius:4px;'
            f'font-size:11px;font-weight:bold;white-space:nowrap">{_slbl}</span></td>'
            f'<td style="font-size:11px;color:#555">{html.escape(_cves) if _cves else "—"}</td>'
            f'<td style="text-align:center">'
            f'<span style="background:#eee;padding:1px 6px;border-radius:3px;font-size:11px">'
            f'{html.escape(_src_label)}</span></td>'
            f'</tr>'
        )

    _outdated_count = len(outdated_names)
    _total_tech     = len(tech_detected)

    # Badges de categoria
    _cat_labels_pt = {
        "cms":"CMS","webserver":"Servidor Web","language":"Linguagem","framework":"Framework",
        "database":"Banco de Dados","cdn":"CDN","cloud":"Cloud",
        "monitoring":"Monitoramento","devops":"DevOps","security":"Segurança"
    }
    _cat_badges = "".join(
        f'<span style="background:#e8f4f8;border:1px solid #1a3a4f;padding:3px 10px;'
        f'border-radius:12px;font-size:12px;margin:3px;display:inline-block">'
        f'<strong>{_cat_labels_pt.get(_cat,_cat)}:</strong> {", ".join(_items)}</span>'
        for _cat, _items in tech_categories.items()
    )
    _cat_html = f'<div style="margin:10px 0 14px">{_cat_badges}</div>' if _cat_badges else ""

    _outdated_badge = (
        f' — <span style="color:#b34e4e;font-weight:bold">{_outdated_count} desatualizado(s)</span>'
        if _outdated_count else " — stack atualizada"
    )
    tech_inventory_html = (
        f'<h2>2.5. Inventário de Tecnologias Detectadas</h2>'
        f'<div class="info-box">'
        f'<p><strong>{_total_tech} componente(s) identificado(s)</strong>{_outdated_badge}. '
        f'Detectados via httpx tech-detect, JS analysis e fingerprinting de endpoints.</p>'
        + _cat_html +
        f'</div>'
        f'<table><tr style="background:#f5f5f5">'
        f'<th style="width:170px">Componente</th>'
        f'<th style="width:130px">Versão</th>'
        f'<th style="width:150px">Status</th>'
        f'<th>CVEs Conhecidos</th>'
        f'<th style="width:70px">Fonte</th>'
        f'</tr>' + rows + f'</table>'
    )

# ── Big4: Escopo & Metodologia (seção 1.1) ───────────────────
_auth_token  = os.environ.get("AUTH_TOKEN", "")
_auth_header = os.environ.get("AUTH_HEADER", "")
_scan_type   = ("Autenticado (token/header fornecido)"
                if (_auth_token or _auth_header)
                else "Não autenticado (caixa-preta)")

# Pipeline canônico — status derivado de raw/.phase_times + artefatos
_PIPELINE = [
    ("P1",   "Descoberta de subdomínios",     "subfinder + httpx + katana"),
    ("P2",   "Mapeamento de superfície",      "httpx + nmap + katana"),
    ("P2_5", "Detecção de WAF & headers",     "wafw00f + security headers"),
    ("P3",   "Análise TLS/SSL",               "testssl.sh"),
    ("P4",   "Varredura de vulnerabilidades", "Nuclei (tags adaptativas)"),
    ("P5",   "Confirmação ativa de exploits", "poc_validator (re-execução)"),
    ("P6",   "Enriquecimento de CVEs",        "NVD + EPSS + CISA KEV"),
    ("P8",   "Segurança de e-mail",           "SPF / DMARC / DKIM"),
    ("P9",   "Scan dinâmico",                 "OWASP ZAP (spider + active)"),
    ("P10",  "Análise de JavaScript",         "secrets + endpoints + libs"),
    ("P10_5","Fuzzing complementar",          "ffuf + scanners CMS"),
    ("P11",  "Geração de relatório",          "swarm_report.py"),
]
_phase_artifact = {"P3": "testssl.json"}  # fases que rodam sem registrar 'end' no .phase_times
_method_rows = ""
for _pid, _pname, _ptools in _PIPELINE:
    if _pid in phase_times:
        _d = phase_times[_pid]
        if _d > 0:
            _label, _dur, _color = "✓ Executada", f"{_d//60}m {_d%60:02d}s", "#1b5e20"
        else:
            _label, _dur, _color = "✓ Executada", "sem trabalho aplicável", "#4a7c8c"
    elif _pid == "P11":
        _label, _dur, _color = "✓ Executada", "—", "#1b5e20"
    elif _pid in _phase_artifact and os.path.exists(os.path.join(OUTDIR, "raw", _phase_artifact[_pid])):
        _label, _dur, _color = "✓ Executada", "—", "#1b5e20"
    else:
        _label, _dur, _color = "○ Não executada", "—", "#888"
    _method_rows += (f'<tr><td style="font-family:monospace">{_pid.replace("_",".")}</td>'
        f'<td>{html.escape(_pname)}</td>'
        f'<td style="font-size:12px;color:#555">{html.escape(_ptools)}</td>'
        f'<td style="color:{_color};font-weight:600;white-space:nowrap">{_label}</td>'
        f'<td style="white-space:nowrap">{_dur}</td></tr>')

# Narrativa de derivação do índice de risco
_total_occ = sum(occurrences.values())
_risk_narr = (f"O índice <strong>{risk}/100</strong> usa a faixa-base da severidade mais alta "
    f"presente (crítico→70, alto→40, médio→15, baixo→5) mais um bônus de quantidade com "
    f"retornos decrescentes sobre <strong>{total}</strong> tipo(s) único(s) de achado")
if _total_occ > total:
    _risk_narr += f" ({_total_occ} ocorrências no total, contadas uma vez por tipo para não saturar)"
if kev_bonus:  _risk_narr += f", soma <strong>+{kev_bonus}</strong> por CVE(s) em exploração ativa (CISA KEV)"
if epss_bonus: _risk_narr += f", <strong>+{epss_bonus}</strong> por probabilidade de exploração (EPSS)"
if js_bonus:   _risk_narr += f", <strong>+{js_bonus}</strong> por exposições em JavaScript"
_risk_narr += f". Classificação final: <strong style='color:{scol}'>{html.escape(stxt)}</strong>."

_waf_limit = (f' O alvo está protegido por WAF ({html.escape(WAF_NAME)}): o active scan pode conter '
    f'falsos negativos.' if WAF_DETECTED and WAF_NAME else '')

methodology_html = f'''<h2>1.1. Escopo &amp; Metodologia</h2>
<table>
<tr><th style="width:220px">Alvo</th><td><code>{html.escape(TARGET)}</code></td></tr>
<tr><th>Domínio</th><td>{html.escape(DOMAIN)}</td></tr>
<tr><th>Data do scan</th><td>{rdate}</td></tr>
<tr><th>Duração total</th><td>{duration_str}</td></tr>
<tr><th>Tipo de avaliação</th><td>{_scan_type}</td></tr>
<tr><th>Autorização</th><td>Execução restrita a ambiente com Rules of Engagement (RoE) assinado.</td></tr>
</table>
<div class="info-box" style="margin-top:10px">
<p><strong>Derivação do risco:</strong> {_risk_narr}</p>
</div>
<h3>Pipeline executado</h3>
<table>
<tr style="background:#f5f5f5"><th style="width:60px">Fase</th><th>Atividade</th><th>Ferramentas</th><th style="width:150px">Status</th><th style="width:120px">Duração</th></tr>
{_method_rows}
</table>
<div class="info-box" style="margin-top:10px;font-size:12px">
<p><strong>Limitações:</strong> esta é uma avaliação automatizada e não substitui um pentest manual.{_waf_limit} Achados de severidade crítica/alta devem ser validados manualmente antes da remediação.</p>
</div>'''

page = f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="UTF-8">
<title>SWARM — {html.escape(DOMAIN)}</title><style>
body{{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:#f0f2f5}}
.container{{max-width:1200px;margin:0 auto;background:white;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.1)}}
.header{{background:#1a3a4f;color:white;padding:30px;text-align:center}}.header h1{{margin:0 0 10px}}
.content{{padding:30px}}
.stats{{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}}
.stat-card{{flex:1;padding:20px;text-align:center;color:white;border-radius:8px;min-width:100px}}
.stat-card.critical{{background:#7a2e2e}}.stat-card.high{{background:#b34e4e}}
.stat-card.medium{{background:#d4833a}}.stat-card.low{{background:#4a7c8c}}.stat-card.info{{background:#6e8f72}}
.stat-card .number{{font-size:36px;font-weight:bold}}
.info-box{{background:#e8f4f8;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #1a3a4f}}
.vuln{{border:1px solid #ddd;margin:20px 0;padding:20px;border-radius:8px;background:#fafafa}}
.vuln.critical{{border-left:10px solid #7a2e2e}}.vuln.high{{border-left:10px solid #b34e4e}}
.vuln.medium{{border-left:10px solid #d4833a}}.vuln.low{{border-left:10px solid #4a7c8c}}.vuln.info{{border-left:10px solid #6e8f72}}
.vuln h3{{margin-top:0}}.source-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold;margin-left:8px}}
.source-nuclei{{background:#3498db;color:white}}.source-zap{{background:#e74c3c;color:white}}.source-headers{{background:#7d3c98;color:white}}.source-version{{background:#d35400;color:white}}
.footer{{background:#f5f5f5;padding:20px;text-align:center;font-size:12px;color:#666}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}th,td{{border:1px solid #ddd;padding:10px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5;font-weight:600}}h2{{color:#1a3a4f;border-bottom:2px solid #e0e0e0;padding-bottom:8px}}
.risk-bar-wrap{{background:#e0e0e0;border-radius:4px;height:12px;margin:8px 0}}
.risk-bar{{background:{scol};height:12px;border-radius:4px;width:{risk}%}}
code{{background:#f4f4f4;padding:1px 4px;border-radius:3px;font-size:12px}}
    .evidence-box{{background:#2d3436;color:#dfe6e9;padding:10px 14px;font-family:monospace;font-size:12px;border-radius:4px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
    .tls-ok{{color:#27ae60;font-weight:bold}}.tls-warn{{color:#d4833a;font-weight:bold}}
    .tls-high{{color:#b34e4e;font-weight:bold}}.tls-critical{{color:#7a2e2e;font-weight:bold}}
    .confirm-yes{{background:#27ae60;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
    .confirm-no{{background:#95a5a6;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold}}
</style></head><body><div class="container">
<div class="header"><h1>SWARM — Relatório de Segurança</h1>
<p>Alvo: <strong>{html.escape(TARGET)}</strong> | Domínio: {html.escape(DOMAIN)}</p>
<p>Data: {rdate} &nbsp;|&nbsp; Duração: {duration_str} &nbsp;|&nbsp; <strong>CONFIDENCIAL</strong></p></div>
<div class="content">
<h2>1. Sumário Executivo</h2>
<div class="stats">
{f'<div class="stat-card" style="background:#7a0000;border:2px solid #ff4444"><div class="number">{kev_count}</div><div>🔴 KEV</div></div>' if kev_count > 0 else ""}
<div class="stat-card critical"><div class="number">{stats['critical']}</div><div>CRÍTICO</div></div>
<div class="stat-card high"><div class="number">{stats['high']}</div><div>ALTO</div></div>
<div class="stat-card medium"><div class="number">{stats['medium']}</div><div>MÉDIO</div></div>
<div class="stat-card low"><div class="number">{stats['low']}</div><div>BAIXO</div></div>
<div class="stat-card info"><div class="number">{stats['info']}</div><div>INFO</div></div></div>
{f'<div style="background:#7a0000;color:white;padding:14px 18px;border-radius:6px;margin:12px 0;border-left:6px solid #ff4444"><strong style="font-size:14px">🔴 {kev_count} CVE(S) COM EXPLORAÇÃO ATIVA CONFIRMADA — CISA KEV</strong><br><span style="font-size:12px;opacity:.9">Estes CVEs estão no catálogo Known Exploited Vulnerabilities da CISA. Independente do score CVSS, exigem ação imediata: ' + ", ".join(f"<code style=\'background:rgba(255,255,255,.15);padding:1px 4px;border-radius:3px\'>{html.escape(cid)}</code>" for cid in list(kev_matches.keys())[:10]) + (f" e mais {len(kev_matches)-10}" if len(kev_matches)>10 else "") + "</span></div>" if kev_count > 0 else ""}
<div class="info-box">
<p><strong>Índice de Risco (0–100):</strong> {risk} <small style="color:#888;font-size:11px">(metodologia: KEV + EPSS + CVSS + JS)</small></p>
<div class="risk-bar-wrap"><div class="risk-bar"></div></div>
<p><strong>Total de Achados:</strong> {total} &nbsp;|&nbsp; <strong>Status:</strong> <span style="color:{scol};font-weight:bold">{stxt}</span></p>
<p><strong>Duração total do scan:</strong> {duration_str}</p>
<p><strong>Ferramentas:</strong> Nuclei + OWASP ZAP{"+ wafw00f" if WAF_DETECTED or os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}{"+ Katana" if KATANA_URLS > 0 else ""}{"+ JS/Secrets" if js_analysis else ""}{"+ testssl" if TLS_ISSUES >= 0 and os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}{"+ OpenAPI" if OPENAPI_FOUND else ""}</p>
<p><strong>Exploits verificados ativamente:</strong> {CONFIRMED_COUNT} re-executados com resposta capturada</p>
{'<p style="background:#fff3cd;padding:8px 12px;border-radius:4px;margin:8px 0;font-size:13px"><strong style="color:#856404">🛡 WAF: '+html.escape(WAF_NAME)+'</strong> — active scan pode ter falsos negativos.</p>' if WAF_DETECTED and WAF_NAME else ""}
{'<p style="color:#b34e4e;font-size:13px">⚠ <strong>'+str(EMAIL_ISSUES)+' problema(s) de segurança de email</strong> detectado(s).</p>' if EMAIL_ISSUES > 0 else ""}
</div>
{methodology_html}
<h2>2. Superfície de Ataque</h2>
<table>
<tr><th style="width:220px">Subdomínios descobertos</th><td>{SUB_COUNT}</td></tr>
<tr><th>Subdomínios ativos (HTTP)</th><td>{ACTIVE_COUNT}</td></tr>
<tr><th>Portas abertas</th><td><code>{html.escape(OPEN_PORTS)}</code></td></tr>
{f'<tr><th>URLs (Katana JS crawl)</th><td>{KATANA_URLS} URL(s) descobertas com rendering JS</td></tr>' if KATANA_URLS > 0 else ""}</table>
<h3>Hosts Ativos (httpx)</h3><table><tr><th>Resultado</th></tr>{trows(httpx_lines,"httpx não executado ou sem resultados detectados")}</table>
<h3>Portas Abertas e Serviços (nmap)</h3><table><tr><th>Porta / Serviço</th></tr>{trows(nmap_lines,"nmap não executado ou sem portas abertas")}</table>
{tech_inventory_html}
<h2>3. Vulnerabilidades Identificadas</h2>{vhtml}

<!-- Comportamento do Scan -->
{scan_behavior_html}

<!-- WAF + Email Security -->
{waf_email_html}

<!-- TLS Section -->
{tls_html}

<!-- Exploit Confirmations -->
{confirm_html}


<!-- JS Analysis -->
{js_html}
{errsec}
{low_table_html}

<!-- Plano de Ação -->
{action_plan_html}

<!-- Matriz de Priorização Esforço × Impacto -->
{priority_matrix_html}
<h2>5. Arquivos de Evidência</h2><div class="info-box"><ul>
<li><code>raw/subdomains.txt</code> — Subdomínios descobertos</li>
<li><code>raw/httpx_results.txt</code> — Hosts HTTP ativos e tecnologias</li>
<li><code>raw/nmap.txt</code> — Scan de portas e serviços</li>
<li><code>raw/nuclei.json</code> — Achados do Nuclei (JSONL bruto)</li>
<li><code>raw/zap_alerts.json</code> — Alertas do OWASP ZAP (JSON bruto)</li>
<li><code>raw/zap_evidencias.xml</code> — Relatório completo do ZAP (XML)</li>
{"<li><code>raw/testssl.json</code> — Análise TLS/SSL (testssl)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","testssl.json")) else ""}
{"<li><code>raw/kev_matches.json</code> — CVEs com exploração ativa confirmada (CISA KEV)</li>" if kev_matches else ""}
{"<li><code>raw/cve_enrichment.json</code> — Dados CVE (CVSS + EPSS) do NVD/FIRST</li>" if cve_enrichment else ""}
{"<li><code>raw/exploit_confirmations.json</code> — Resultados de confirmação ativa de exploits</li>" if confirmations else ""}
{"<li><code>raw/openapi_spec.json</code> — Especificação OpenAPI/Swagger importada</li>" if OPENAPI_FOUND else ""}
{"<li><code>raw/scan_metadata.json</code> — Comportamento e configuração de evasão do scan</li>" if scan_meta else ""}
{"<li><code>raw/waf.json</code> — Detecção de WAF (wafw00f)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","waf.json")) else ""}
{"<li><code>raw/email_security.json</code> — SPF/DMARC/DKIM</li>" if email_security else ""}
{"<li><code>raw/katana_urls.txt</code> — URLs descobertas pelo Katana (JS crawl)</li>" if KATANA_URLS > 0 else ""}
{"<li><code>raw/ffuf.json</code> — Endpoints descobertos por fuzzing (ffuf)</li>" if FFUF_FOUND > 0 else ""}
{"<li><code>raw/smuggler.txt</code> — Análise HTTP Request Smuggling</li>" if SMUGGLER_FOUND else ""}
{"<li><code>raw/trufflehog.json</code> — Secrets de alta confiança (trufflehog)</li>" if TRUFFLEHOG_FOUND > 0 else ""}
{"<li><code>raw/js_analysis.json</code> — Análise JS/Secrets completa</li>" if js_analysis else ""}
{"<li><code>raw/js_files/</code> — Arquivos JS para análise forense</li>" if js_files_list else ""}
{"<li><code>raw/tech_profile.json</code> — Inventário de tecnologias detectadas (httpx + JS + probes)</li>" if tech_detected else ""}
{"<li><code>raw/wpscan.json</code> — WordPress scanner (wpscan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","wpscan.json")) else ""}
{"<li><code>raw/joomscan.txt</code> — Joomla scanner (joomscan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","joomscan.txt")) else ""}
{"<li><code>raw/droopescan.txt</code> — Drupal scanner (droopescan)</li>" if os.path.exists(os.path.join(OUTDIR,"raw","droopescan.txt")) else ""}
</ul>
<p><strong>Nota:</strong> Todos os achados devem ser validados manualmente antes de reportar ao cliente ou equipe de desenvolvimento.</p></div></div>
<div class="footer"><p><strong>CONFIDENCIAL — USO INTERNO</strong></p>
<p>SWARM — Scanner Automatizado de Segurança</p></div></div></body></html>"""

out = os.path.join(OUTDIR,"relatorio_swarm.html")
open(out,"w",encoding="utf-8").write(page)
print(f"[✓] Relatório: {out}")
print(f"[✓] {total} vulnerabilidade(s) | C={stats['critical']} A={stats['high']} M={stats['medium']} B={stats['low']} I={stats['info']}")
if errors: print(f"[!] {len(errors)} aviso(s) — ver relatório")

# ── findings.json ─────────────────────────────────────────────────
try:
    risk_level = stxt.split(" — ")[0] if " — " in stxt else stxt
    findings_out = {
        "schema_version": "1.0",
        "scan": {
            "target": TARGET, "domain": DOMAIN,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "risk_score": risk, "risk_level": risk_level,
            "waf_detected": WAF_DETECTED, "waf_name": WAF_NAME,
            "phase_times": phase_times,
        },
        "summary": {
            "total": total,
            "critical": stats["critical"], "high": stats["high"],
            "medium": stats["medium"], "low": stats["low"],
            "info": stats["info"], "kev_count": kev_count,
            "confirmed": sum(1 for c in confirmations if c.get("confirmed")),
        },
        "findings": [
            {"id": f.get("id",""), "name": f.get("name",""),
             "severity": f.get("severity",""), "source": f.get("source",""),
             "url": f.get("url",""), "cve_ids": f.get("cve_ids",[]),
             "cvss": f.get("cvss"), "epss": f.get("epss_score"),
             "in_kev": f.get("in_kev",False),
             "description": f.get("description",""),
             "remediation": f.get("remediation",""),
             "risk_score": f.get("risk_score",0)}
            for f in all_f
        ],
        "confirmations": [
            {"template_id": c.get("template_id",""), "url": c.get("url",""),
             "severity": c.get("severity",""), "confirmed": c.get("confirmed",False),
             "confidence": c.get("confidence",0), "poc_note": c.get("poc_note",""),
             "http_status": c.get("http_status",""),
             "curl_reproducible": c.get("curl_reproducible","")}
            for c in confirmations
        ],
        "security_headers": security_headers_data,
    }
    fj = os.path.join(OUTDIR,"findings.json")
    json.dump(findings_out, open(fj,"w",encoding="utf-8"), ensure_ascii=False, indent=2, default=str)
    print(f"[✓] JSON estruturado: {fj}")
except Exception as _e:
    print(f"[!] findings.json: {_e}")

# ── sumario_executivo.html ────────────────────────────────────────
try:
    rc = "#7a2e2e" if risk>=70 else ("#b34e4e" if risk>=40 else ("#d4833a" if risk>=15 else "#27ae60"))
    kev_str = ", ".join(list(kev_matches.keys())[:5]) if kev_matches else "Nenhum"
    risk_level = stxt.split(" — ")[0] if " — " in stxt else stxt

    # Top findings table
    sev_bg = {"critical":"#7a2e2e","high":"#b34e4e"}
    sev_lb = {"critical":"CRÍTICO","high":"ALTO"}
    top_f = [f for f in all_f if f.get("severity") in ("critical","high")][:8]
    top_rows = ""
    for f in top_f:
        sc = sev_bg.get(f.get("severity",""), "#888")
        sl = sev_lb.get(f.get("severity",""), "?")
        name = html.escape(f.get("name",""))
        impact = html.escape(f.get("impact","") or "Ver relatório técnico")
        rem = html.escape((f.get("remediation","") or "")[:60])
        top_rows += (f'<tr><td><span style="background:{sc};color:white;padding:2px 8px;'
                     f'border-radius:4px;font-size:11px">{sl}</span></td>'
                     f'<td style="font-weight:600">{name}</td>'
                     f'<td style="color:#555;font-size:12px">{impact}</td>'
                     f'<td style="font-size:11px">{rem}</td></tr>')
    if not top_rows:
        top_rows = '<tr><td colspan="4" style="text-align:center;color:#888">Sem achados críticos ou altos</td></tr>'

    # Phase timing table
    phase_map = {"P1":"Descoberta","P2":"Superfície","P3":"TLS","P4":"Nuclei",
                 "P5":"Confirmação","P6":"CVE/EPSS","P7":"WAF","P8":"Email",
                 "P9":"ZAP","P10":"JS/Secrets","P10_5":"Complementar","P11":"Relatório"}
    phase_rows = ""
    for pid, dur in phase_times.items():
        pname = phase_map.get(pid, pid)
        phase_rows += f'<tr><td>{pname}</td><td>{int(dur)//60}m {int(dur)%60:02d}s</td></tr>'
    phase_section = ""
    if phase_rows:
        phase_section = (f'<h2>Tempo por Fase</h2>'
                        f'<table><tr><th>Fase</th><th>Duração</th></tr>'
                        f'{phase_rows}</table>')

    # Recommendations
    recs = []
    if kev_count > 0:
        recs.append(f"<li><strong>URGENTE:</strong> Remediar {kev_count} CVE(s) com exploração ativa: {html.escape(kev_str)}</li>")
    if stats["critical"] > 0:
        recs.append(f"<li>Corrigir {stats['critical']} achado(s) crítico(s) — prazo imediato</li>")
    if stats["high"] > 0:
        recs.append(f"<li>Planejar {stats['high']} achado(s) alto(s) — esta sprint</li>")
    if stats["medium"] > 0:
        recs.append(f"<li>Agendar {stats['medium']} achado(s) médio(s) — próxima sprint</li>")
    recs.append("<li>Consultar relatório técnico para evidências detalhadas</li>")
    recs_html = "\n".join(recs)

    kev_alert = ""
    if kev_count > 0:
        kev_alert = (f'<p style="background:#fff0f0;padding:10px;border-radius:6px;'
                    f'border-left:4px solid #7a0000;font-size:12px">'
                    f'<strong>⚠ Exploração Ativa (CISA KEV):</strong> {html.escape(kev_str)}</p>')

    kev_kpi = ""
    if kev_count > 0:
        kev_kpi = (f'<div class="kpi"><div class="n" style="color:#7a0000">{kev_count}</div>'
                  f'<div class="l">🔴 KEV</div></div>')

    target_esc = html.escape(TARGET)
    domain_esc = html.escape(DOMAIN)
    stxt_esc   = html.escape(stxt)
    ts_str     = datetime.now().strftime("%d/%m/%Y %H:%M")

    exec_html = f"""<!DOCTYPE html>
<html lang="pt-br"><head><meta charset="UTF-8">
<title>Sumário Executivo — {domain_esc}</title>
<style>
body{{font-family:"Segoe UI",sans-serif;max-width:850px;margin:0 auto;padding:30px;color:#333}}
h1{{color:#1a3a4f;font-size:22px;border-bottom:3px solid #1a3a4f;padding-bottom:8px}}
h2{{color:#1a3a4f;font-size:15px;margin-top:24px}}
.kpi{{display:inline-block;text-align:center;margin:0 10px;padding:10px 18px;background:#f5f5f5;border-radius:8px}}
.kpi .n{{font-size:26px;font-weight:bold}}
.kpi .l{{font-size:11px;color:#888}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}
th{{background:#1a3a4f;color:white;padding:8px;text-align:left;font-size:12px}}
td{{border:1px solid #eee;padding:8px;font-size:12px}}
.footer{{color:#aaa;font-size:10px;text-align:center;margin-top:32px;border-top:1px solid #eee;padding-top:8px}}
@media print{{body{{padding:0}}}}
</style></head><body>
<div style="background:#1a3a4f;color:white;padding:18px;border-radius:8px;margin-bottom:20px">
<h1 style="color:white;border:none;margin:0 0 4px">Sumário Executivo de Segurança</h1>
<p style="margin:0;opacity:.8;font-size:13px">{target_esc} &nbsp;·&nbsp; {ts_str} &nbsp;·&nbsp; CONFIDENCIAL</p>
</div>
<h2>Índice de Risco</h2>
<div style="margin:8px 0">
<span style="background:{rc};color:white;font-size:32px;font-weight:bold;padding:10px 22px;border-radius:6px">{risk}/100</span>
<span style="margin-left:14px;font-size:15px;font-weight:600;color:{rc}">{stxt_esc}</span>
</div>
<h2>Achados</h2>
<div style="margin:8px 0">
<div class="kpi"><div class="n" style="color:#7a2e2e">{stats["critical"]}</div><div class="l">CRÍTICO</div></div>
<div class="kpi"><div class="n" style="color:#b34e4e">{stats["high"]}</div><div class="l">ALTO</div></div>
<div class="kpi"><div class="n" style="color:#d4833a">{stats["medium"]}</div><div class="l">MÉDIO</div></div>
<div class="kpi"><div class="n" style="color:#4a7c8c">{stats["low"]}</div><div class="l">BAIXO</div></div>
{kev_kpi}
</div>
{kev_alert}
<h2>Principais Vulnerabilidades</h2>
<table><tr><th>Severidade</th><th>Vulnerabilidade</th><th>Impacto</th><th>Correção</th></tr>
{top_rows}
</table>
<h2>Recomendações</h2>
<ol style="font-size:13px;line-height:2">{recs_html}</ol>
{phase_section}
<div class="footer">Gerado por SWARM · Uso restrito a equipes de segurança autorizadas · CONFIDENCIAL</div>
</body></html>"""

    ef = os.path.join(OUTDIR,"sumario_executivo.html")
    open(ef,"w",encoding="utf-8").write(exec_html)
    print(f"[✓] Sumário executivo: {ef}")
except Exception as _e:
    print(f"[!] sumario_executivo: {_e}")

