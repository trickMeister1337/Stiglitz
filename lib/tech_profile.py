#!/usr/bin/env python3
"""
tech_profile.py — Tech Profile Builder → tech_profile.json

Extraído de stiglitz.sh (heredoc PYTECHPROFILE). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import sys, re, json, os

import httpx_parse

outdir, target = sys.argv[1], sys.argv[2].rstrip("/")

tech_inventory = {}  # { "TechName": {"version": "x.y.z", "source": "...", "confidence": "..."} }

# 1. Tech-detect do httpx. Preferimos a saída estruturada -json (raw/httpx_results.jsonl):
# ela separa `tech`/`webserver` do `title`, evitando que título HTTP ("Not Found") e
# flags (HSTS) sejam tratados como tecnologia (Bug #1). Fallback ao parse de colchetes
# do .txt legado quando o JSONL não existe (scan antigo / degradação).
jsonl_file = os.path.join(outdir, "raw", "httpx_results.jsonl")
httpx_file = os.path.join(outdir, "raw", "httpx_results.txt")
if os.path.exists(jsonl_file):
    with open(jsonl_file, errors="replace") as f:
        tech_inventory.update(httpx_parse.tech_inventory(httpx_parse.parse_jsonl(f.read())))
elif os.path.exists(httpx_file):
    for line in open(httpx_file, errors="replace"):
        line = line.strip()
        brackets = re.findall(r'\[([^\]]+)\]', line)
        for brk in brackets:
            if re.match(r'^\d{3}$', brk.strip()):
                continue  # skip status codes
            items = [x.strip() for x in brk.split(',')]
            for item in items:
                m = re.match(r'^([A-Za-z][A-Za-z0-9\s\.\-+/]+?)(?::([0-9][0-9.a-z\-]*))?$', item.strip())
                if m:
                    name = m.group(1).strip()
                    version = m.group(2) or ""
                    if 2 < len(name) < 50 and name not in ("GET", "POST", "HTTP", "HTTPS"):
                        if name not in tech_inventory or (version and not tech_inventory[name].get("version")):
                            tech_inventory[name] = {
                                "version": version,
                                "source": "httpx",
                                "confidence": "high"
                            }

# 2. Integra resultados das PROBES (version_findings.json)
vf_file = os.path.join(outdir, "raw", "version_findings.json")
if os.path.exists(vf_file):
    try:
        for f in json.load(open(vf_file)):
            m = re.match(r'^([A-Za-z][A-Za-z0-9\s\-/]+?)\s+v?[0-9]', f.get("name", ""))
            if m:
                tech_name = m.group(1).strip()
                tech_inventory[tech_name] = {
                    "version":     f.get("detected_version", ""),
                    "source":      "probe",
                    "confidence":  "confirmed",
                    "outdated":    f.get("is_outdated", False),
                    "min_version": f.get("min_version", ""),
                    "cves":        f.get("cve", ""),
                }
    except Exception as e:
        print(f"  [!] tech_profile: erro ao ler version_findings.json: {e}")

# 3. Fingerprinting por padrões de path (katana_urls.txt)
PATH_TECH_MAP = [
    (r'/wp-(?:admin|content|includes|login\.php|json)',  "WordPress",       ""),
    (r'/wp-json/wp/v2',                                  "WordPress",       ""),
    (r'/sites/(?:default|all)/',                         "Drupal",          ""),
    (r'/core/(?:CHANGELOG|modules|themes)',              "Drupal",          ""),
    (r'/administrator/',                                 "Joomla",          ""),
    (r'/components/com_',                                "Joomla",          ""),
    (r'/actuator/',                                      "Spring Boot",     ""),
    (r'/telescope',                                      "Laravel",         ""),
    (r'/horizon',                                        "Laravel",         ""),
    (r'/_debugbar/',                                     "Laravel",         ""),
    (r'/__debug__/',                                     "Django",          ""),
    (r'/static/admin/',                                  "Django",          ""),
    (r'/_next/',                                         "Next.js",         ""),
    (r'/__nuxt/',                                        "Nuxt.js",         ""),
    (r'/rails/',                                         "Ruby on Rails",   ""),
    (r'/assets/application-[a-f0-9]+\.',                "Ruby on Rails",   ""),
    (r'/struts2-',                                       "Apache Struts",   ""),
    (r'\.action(?:\?|$)',                                "Apache Struts",   ""),
    (r'/grafana',                                        "Grafana",         ""),
    (r'/kibana',                                         "Kibana",          ""),
    (r'/jenkins',                                        "Jenkins",         ""),
    (r'/phpmyadmin',                                     "phpMyAdmin",      ""),
    (r'/adminer',                                        "Adminer",         ""),
    (r'/swagger-ui',                                     "Swagger/OpenAPI", ""),
    (r'/v[0-9]+/api/',                                   "REST API",        ""),
    (r'/admin/master/console',                           "Keycloak",        ""),
    (r'/admin/realms\b',                                 "Keycloak",        ""),
    (r'/admin/serverinfo',                               "Keycloak",        ""),
    (r'/realms/[^/]+/protocol/openid-connect',           "Keycloak",        ""),
    (r'/realms/master\b',                                "Keycloak",        ""),
]

katana_file = os.path.join(outdir, "raw", "katana_urls.txt")
if os.path.exists(katana_file):
    try:
        urls_blob = open(katana_file, errors="replace").read()
        for pattern, tech_name, tech_ver in PATH_TECH_MAP:
            if re.search(pattern, urls_blob, re.IGNORECASE) and tech_name not in tech_inventory:
                tech_inventory[tech_name] = {
                    "version":    tech_ver,
                    "source":     "path_fingerprint",
                    "confidence": "medium"
                }
    except Exception as e:
        print(f"  [!] tech_profile: erro ao ler katana_urls.txt: {e}")

# 4. Categorização e mapeamento para Nuclei/ffuf
TECH_CATEGORIES = {
    "cms":        ["WordPress", "Drupal", "Joomla", "Magento", "PrestaShop", "TYPO3"],
    "webserver":  ["Nginx", "Apache", "IIS", "LiteSpeed", "Caddy", "Tomcat", "Jetty"],
    "language":   ["PHP", "Python", "Ruby", "Java", "Node.js", "Go", "ASP.NET", ".NET"],
    "framework":  ["Laravel", "Symfony", "Django", "Ruby on Rails", "Spring Boot",
                   "Express.js", "Next.js", "Nuxt.js", "Flask", "FastAPI", "Apache Struts"],
    "database":   ["MySQL", "PostgreSQL", "MongoDB", "Redis", "Elasticsearch", "CouchDB"],
    "cdn":        ["Cloudflare", "Akamai", "Fastly", "CloudFront", "Varnish"],
    "cloud":      ["AWS", "Azure", "Google Cloud", "DigitalOcean"],
    "monitoring": ["Grafana", "Prometheus", "Kibana", "Elasticsearch", "Datadog"],
    "devops":     ["Jenkins", "GitLab", "Kubernetes", "Docker", "Consul", "Vault", "Traefik"],
    "iam":        ["Keycloak"],
}

TECH_TO_NUCLEI_TAGS = {
    "WordPress":      ["wordpress", "wp"],
    "Drupal":         ["drupal"],
    "Joomla":         ["joomla"],
    "Magento":        ["magento"],
    "PrestaShop":     ["prestashop"],
    "Nginx":          ["nginx"],
    "Apache":         ["apache"],
    "IIS":            ["iis"],
    "Tomcat":         ["tomcat"],
    "PHP":            ["php"],
    "Spring Boot":    ["spring", "springboot", "actuator"],
    "Django":         ["django"],
    "Laravel":        ["laravel"],
    "Ruby on Rails":  ["ruby", "rails"],
    "Node.js":        ["node", "nodejs"],
    "Next.js":        ["nextjs", "node"],
    "Nuxt.js":        ["nuxt", "node"],
    "Redis":          ["redis"],
    "MongoDB":        ["mongodb"],
    "MySQL":          ["mysql"],
    "Elasticsearch":  ["elastic", "elasticsearch"],
    "AWS":            ["aws"],
    "Kubernetes":     ["kubernetes", "k8s"],
    "Docker":         ["docker"],
    "Jenkins":        ["jenkins"],
    "Grafana":        ["grafana"],
    "Prometheus":     ["prometheus"],
    "Kibana":         ["kibana"],
    "phpMyAdmin":     ["phpmyadmin"],
    "Traefik":        ["traefik"],
    "Consul":         ["consul"],
    "Vault":          ["vault"],
    "Apache Struts":  ["struts"],
    "Swagger/OpenAPI":["swagger", "openapi"],
    "Keycloak":       ["keycloak"],
}

CMS_FFUF_PROFILES = {
    "WordPress": "wordpress", "Drupal": "drupal", "Joomla": "joomla",
    "Laravel": "laravel", "Django": "django", "Spring Boot": "spring",
    "Next.js": "nodejs", "Ruby on Rails": "rails", "PHP": "php",
    "Apache Struts": "struts", "Magento": "magento", "Keycloak": "keycloak",
}

CMS_SCANNERS = {
    "WordPress": "wpscan",
    "Joomla":    "joomscan",
    "Drupal":    "droopescan",
}

nuclei_tags_set = set()
for tech_name in tech_inventory:
    for known, tags in TECH_TO_NUCLEI_TAGS.items():
        if known.lower() in tech_name.lower() or tech_name.lower() in known.lower():
            nuclei_tags_set.update(tags)

ffuf_profile = "generic"
cms_scanner  = None
for tech_name in tech_inventory:
    if tech_name in CMS_FFUF_PROFILES and ffuf_profile == "generic":
        ffuf_profile = CMS_FFUF_PROFILES[tech_name]
    if tech_name in CMS_SCANNERS and not cms_scanner:
        cms_scanner = CMS_SCANNERS[tech_name]

categories = {}
for cat, techs in TECH_CATEGORIES.items():
    found = [t for t in techs if t in tech_inventory]
    if found:
        categories[cat] = found

profile = {
    "detected":          tech_inventory,
    "categories":        categories,
    "nuclei_extra_tags": sorted(nuclei_tags_set),
    "ffuf_profile":      ffuf_profile,
    "cms_scanner":       cms_scanner,
    "total_detected":    len(tech_inventory),
}

out_file = os.path.join(outdir, "raw", "tech_profile.json")
with open(out_file, "w") as f:
    json.dump(profile, f, indent=2, ensure_ascii=False)

if tech_inventory:
    preview = ", ".join(
        f"{k}" + (f" {v['version']}" if v.get("version") else "")
        for k, v in list(tech_inventory.items())[:8]
    ) + (" ..." if len(tech_inventory) > 8 else "")
    print(f"  [✓] Tech profile: {len(tech_inventory)} tecnologia(s) — {preview}")
    if nuclei_tags_set:
        print(f"      → Nuclei tags extras: {', '.join(sorted(nuclei_tags_set)[:12])}")
    if ffuf_profile != "generic":
        print(f"      → ffuf profile: {ffuf_profile}")
    if cms_scanner:
        print(f"      → CMS scanner ativado: {cms_scanner}")
else:
    print("  [✓] Tech profile: nenhuma tecnologia detectada via fingerprinting")
