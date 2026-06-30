# Coverage & Blind Spots + Service Exposure — Design

> **Higienizado:** nenhum dado de CDE/cliente/alvo aqui. Snapshot de design —
> verificar contra o git antes de afirmar estado de implementação.
> **Data:** 2026-06-30. **Origem:** `project_stiglitz_coverage_roadmap` (memória local),
> derivado do caso APM (`lib/apm_probe.py`), em que um achado real (Elastic APM com
> ingestão sem auth) só apareceu após o operador questionar manualmente.

## Problema

Auditoria de cobertura identificou **dois modos de falha** pelos quais achados reais
não chegam ao relatório:

- **Modo A — Cegueira de descoberta:** o scanner nunca envia a requisição que revelaria
  o achado. A cobertura hoje = união de (spider/katana seguindo *links*) + (nuclei por
  template) + um punhado de probes hardcoded (`monitoring_check`, `version_fingerprint`,
  `secscan`, `apm_probe`). Uma API pura sem HTML/links/spec público faz spider/katana
  pararem em `/`; o serviço só é exercido se houver probe hardcoded para ele. **Hoje sem
  cobertura:** Elasticsearch, Kibana, Grafana (além de `/metrics`), Spring Boot Actuator
  completo, Consul, etcd, Docker Engine API, Kubernetes API, RabbitMQ Management, Airflow,
  Jenkins. Escrever um módulo `apm_probe`-style por serviço **não escala**.
- **Modo B — Supressão silenciosa:** o achado/lacuna existe mas não é declarado na capa,
  podendo transmitir falsa sensação de segurança ("0 High" sobre uma superfície não
  exercida). Recorte deste design: **declarar lacunas de cobertura**, sem mexer nas demais
  supressões (Email fora do stats, DOMAIN vazio→fail-open) que ficam como follow-up.

## Objetivo

Entregar os **dois itens P0** do roadmap de cobertura, juntos:

1. **`lib/service_exposure.py`** — probe config-driven que generaliza o padrão do
   `apm_probe` num **catálogo** de serviços. Serviço novo = uma entrada de dados, não um
   módulo novo.
2. **Seção "Coverage & Blind Spots"** no relatório — declara automaticamente o que **não**
   foi exercido (port scan ausente/truncado, host vivo sem superfície, serviço
   fingerprintado não sondado, API autenticada não testada), transformando achado-oculto
   em lacuna-declarada.

## Decisões de design

| Decisão | Escolha | Justificativa |
|---|---|---|
| Escopo de sondagem (1º corte) | **(A)** HTTP(S) contra `$TARGET`; campo `port` opcional no catálogo | YAGNI no port-scan frágil (nmap é pulado sob proxy/edge e dá timeout — o "agravante de rede" do Modo A); cobertura de portas é responsabilidade do naabu (P1), não deste módulo |
| Formato do catálogo | **dict Python embutido** (`SERVICE_CATALOG`) | Catálogo é *conhecimento da ferramenta* (versionado, testável puro, sem I/O), não *config de engagement* como o `bizlogic.yaml`. PyYAML existe (6.0.1) mas não é a escolha certa aqui |
| Relação com probes atuais | **Aditivo** | Não reescreve `apm_probe` (POST NDJSON custom) nem `monitoring_check` (já funciona); cobertura nova sem risco de regressão. Migração deles ao catálogo = follow-up |
| Seção Coverage | **Seção HTML dedicada**, **fora** de `severity_counts` | Modo B pede declarar lacunas sem *inflar* a contagem com `info` |
| `coverage_gap_finding` (API-auth-sem-token) | **Migra** de finding `info` para dimensão da seção | Elimina inflação de `info` e duplicação futura; função pura permanece e é reusada pela seção (teste segue válido). **Aprovado pelo usuário em 2026-06-30.** |

## Componente 1 — `lib/service_exposure.py`

Espelha a arquitetura de `apm_probe.py`: **núcleo puro** (catálogo + fingerprint +
classificadores, testável sem rede) + **orquestração de rede fina** (`send_fn` injetável,
curl via `netproxy`/`mtls`) + **CLI**. Findings em EN (deliverable); console/comentários PT-BR.

### Contrato de invocação (idêntico aos probes da Fase 3)
```
python3 lib/service_exposure.py <scan_dir> <target_url>   → raw/service_exposure.json
```

### Estrutura do catálogo (`SERVICE_CATALOG`, dict)
Cada entrada:
```python
"<service_key>": {
    "name": "Elasticsearch",                # nome legível (EN)
    "fingerprint": [                         # ≥1 sonda que CONFIRMA o serviço
        {"path": "/", "markers": ["you know, for search", "lucene_version", "cluster_name"]},
    ],
    "probes": [                              # endpoints sensíveis a testar (só GET)
        {"path": "/_cat/indices?format=json", "finding_class": "elasticsearch_unauth_data",
         "severity": "high", "cwe": "CWE-306",
         "name": "Elasticsearch indices readable without authentication",
         "auth_contrast": False},            # opcional: se True, reforça com 2ª sonda c/ token inválido
    ],
    "port": 9200,                            # opcional — reservado p/ evolução (C)/naabu
}
```
O `auth_contrast` é **opcional por probe** (default `False`): quando `True`, o `run` faz
uma segunda sonda do mesmo path com `Authorization: Bearer <inválido>` e passa a resposta
como `auth_resp` ao `classify_exposure` (reforça CONFIRMED quando 200-sem-auth vs 401-com-token,
padrão `apm_probe`). Serviços que não validam token (200 em ambos) não usam contraste.

### Catálogo do primeiro corte (markers reais, todos GET)
| Serviço | Fingerprint (path → markers) | Probe sensível | Sev | CWE |
|---|---|---|---|---|
| Elasticsearch | `/` → `you know, for search`, `lucene_version` | `/_cat/indices?format=json` 200 | high | 306 |
| Kibana | `/api/status` → `kibana`, `"version"` | `/api/status` 200 | medium | 306 |
| Grafana | `/api/health` → `"database"`, `"version"` | `/api/org` 200 (anon org) | medium | 306 |
| Spring Boot Actuator | `/actuator` → `_links`, `self` | `/actuator/env` 200; `/actuator/heapdump` 200 | high | 200 |
| Consul | `/v1/agent/self` → `Config`, `Member` | `/v1/catalog/services` 200 | high | 306 |
| etcd | `/version` → `etcdserver`, `etcdcluster` | `/v2/keys/` 200 | high | 306 |
| Docker Engine API | `/version` → `ApiVersion`, `"Os"`, `Components` | `/containers/json` 200 | critical | 306 |
| Kubernetes API | `/version` → `gitVersion`, `"major"`, `"minor"` | `/api` 200 (anon) | high | 306 |
| RabbitMQ Management | `/api/overview` → `rabbitmq_version`, `management_version` | `/api/overview` 200 sem auth | medium | 306 |
| Airflow | `/api/v1/health` → `metadatabase`, `scheduler` | `/api/v1/dags` 200 sem auth | high | 306 |
| Jenkins | `/api/json` → `hudson.model.Hudson` (ou header `X-Jenkins`) | `/script` 200 (Groovy console) | critical | 306 |

> **Não** inclui `/metrics` nem `/actuator/prometheus` — já cobertos por `monitoring_check`.
> Sobreposição residual é absorvida pelo dedup semântico.

### Funções puras
- `fingerprint_service(probe_results) -> service_key | None` — confirma qual serviço
  (ou nenhum) com base em status+markers. Markers comparados case-insensitive; corpo com
  `<html` desqualifica (anti-catch-all SPA, padrão `js_chunks.is_js_payload`).
- `classify_exposure(probe_resp, auth_resp=None) -> {state, evidence}` —
  `CONFIRMED` (200 sem auth no endpoint sensível; se `auth_check` disponível, reforça com
  contraste vs token inválido), `REJECTED` (401/403), `INCONCLUSIVE` (resto).
- `build_findings(service_key, verdicts, target) -> [finding]` — schema igual ao
  `apm_probe._finding` (tool/type/source/name/url/severity/description/remediation/
  evidence/cwe + `fingerprint`). URL aponta o endpoint exato.

### Orquestração e fail-safe
- `send_request(method, url, headers, data, timeout)` — curl `-sk`, herda
  `netproxy.curl_proxy_args()` + `mtls.curl_cert_args()`; **só GET** (não-destrutivo).
- `run(scan_dir, target, send_fn=send_request)` — para cada serviço: sonda fingerprint;
  **só prossegue se o serviço for confirmado**; sonda os endpoints sensíveis; emite finding
  **só com veredito CONFIRMED**. Grava `raw/service_exposure.json` (lista de findings).
  Sem serviço confirmado → no-op silencioso (lista vazia).

### Pegadinha de wiring (herdada do APM, ver memória)
No ingest do report, **não** setar `vuln_class` no finding → senão `criticality` aplica o
catálogo e o environmental rebaixa High→Medium (e some o painel de repro). Deixar
**`estimated`**: o piso preserva a severidade do catálogo, igual ao APM/TLS.

## Componente 2 — `lib/coverage.py` + seção "Coverage & Blind Spots"

Núcleo **puro** que declara pontos cegos a partir de sinais **já computados** (todos
passados como input → testável sem rede). Renderização HTML separada da lógica.

### `blind_spots(inputs) -> [dimensão]`
`inputs` (dict) traz sinais que o `stiglitz_report.py` já deriva hoje:
- `nmap_ran` / `nmap_truncated` — de `.phase_times` + presença de `raw/nmap.txt`
  (nmap pulado sob proxy/edge, ou timeout 1800s).
- `live_hosts_no_surface` — hosts em `httpx_results.txt` com 0 endpoints além de `/` e
  sem spec OpenAPI descoberto. **(o sinal que teria pego o APM)**
- `fingerprinted_unprobed` — serviços em `tech_profile.json` (Grafana/ES/Actuator/etc.)
  sem finding/probe correspondente.
- `authed_api_untested` — o atual `.coverage_gap_authed_api` (`openapi_count`, `has_token`).

Cada dimensão = `{area, status, not_exercised, how_to_close}`. `status ∈
{not_run, partial, ok}`. Dimensão com `status == ok` não é renderizada (só lacunas
aparecem). Lista vazia ⇒ seção omitida (cobertura completa).

### Render
- `render_section_html(dimensions) -> str` — tabela **Área | Status | Não exercido |
  Como fechar**. Inserida em `stiglitz_report.py` após `:2443` (junto de OWASP Coverage /
  Deferred). **Não** entra em `severity_counts`.

## Integração (wiring)

1. **`stiglitz.sh` Fase 3** (~`:1099`, junto do `apm_probe`):
   `python3 "$SCRIPT_DIR/lib/service_exposure.py" "$OUTDIR" "$TARGET" || true`.
2. **`stiglitz_report.py`** (~`:925-950`, padrão `apm_probe`): ingest de
   `raw/service_exposure.json` → `service_findings`, agregados em `_all_f_raw` (`:1119`),
   sem `vuln_class` (estimated).
3. **`stiglitz_report.py`** (`:1106-1119` e `:2443`): substitui a emissão de
   `coverage_gap_finding` como finding `info` pela montagem da seção via `lib/coverage.py`
   (a função pura segue sendo chamada — agora alimenta uma dimensão da seção).

## Tratamento de erro
- `service_exposure`: rede falha/timeout → `(0, "")`, serviço não confirmado, no-op. Falha
  ao gravar JSON → aviso em stderr, não aborta (padrão `apm_probe`). `|| true` no wiring.
- `coverage`: input ausente/malformado → dimensão tratada como desconhecida (não acende
  falso "ok"); render tolera listas vazias/campos ausentes sem quebrar.

## Testes (TDD)
- `tests/test_service_exposure.py`: fingerprint acerta/erra por serviço (markers
  presentes/ausentes; corpo HTML desqualifica); `classify_exposure`
  CONFIRMED/REJECTED/INCONCLUSIVE; **fail-safe** (sem fingerprint → 0 findings);
  **não-destrutivo** (probe usa só GET); `build_findings` schema+CWE+fingerprint;
  dois serviços/endpoints distintos não colapsam.
- `tests/test_coverage.py`: cada dimensão acende/apaga conforme input; `ok` não renderiza;
  lista vazia ⇒ sem seção; render robusto a campos ausentes.
- Caracterização: `service_exposure.json` chega ao `findings.json` com `fingerprint`;
  seção Coverage aparece no HTML; **`severity_counts` não muda** ao introduzir a seção.

## Validação
- `python3 -m pytest tests/` (suíte completa verde; baseline atual 943+).
- `python3 -m py_compile stiglitz_report.py lib/service_exposure.py lib/coverage.py`.
- `bash -n stiglitz.sh` + `shellcheck --severity=warning stiglitz.sh`.
- CLI manual: `python3 lib/service_exposure.py /tmp/x http://host` (sem alvo real, valida
  no-op gracioso).

## Fora de escopo (YAGNI / follow-ups)
- Port-aware probing (escopo C) e integração **naabu** (P1).
- Migração de `apm_probe`/`monitoring_check` para o catálogo.
- Descoberta ativa de endpoints (ffuf/kiterunner, P3).
- Demais supressões do Modo B: Email no stats da capa, DOMAIN vazio → fail-closed (P2).
