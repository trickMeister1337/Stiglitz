# Stiglitz — Roadmap Black-box findings + CDE-driven

> Higienizado para versionamento: **nenhum dado de CDE/cliente/alvo** aqui.
> Estado snapshot — verificar contra o git antes de afirmar. **Criado: 2026-06-28.**

**Origem:** análise focada (2026-06-28) do `stiglitz.sh` para o caso de uso **principal** —
scan **black-box** de ambientes **CDE** (API de pagamento), **quase sempre zero-credencial**,
com escopo CDE **declarado** (`cde_targets.txt`).

**Sintoma observado (scans reais recentes de uma API de pagamento):** ~13 findings por scan,
**zero High/Critical**. A saída é dominada por headers ausentes, higiene TLS, email (SPF/DKIM)
e info-disclosure (security.txt, Swagger público). Todo o arsenal de alto impacto
(BOLA/BFLA P9.5, biz-logic P9.7, GraphQL authz P9.8) **degradou a zero** por depender de
`--token-a/--token-b` ausentes. O achado mais valioso disponível — **Swagger público
documentando endpoints de pagamento** — foi apenas semeado no ZAP, não explorado.

**Tese:** as duas maiores alavancas **não exigem credencial nem licença de ferramenta** —
(1) transformar o **OpenAPI/Swagger no motor** do scan (broken-auth, method-aware) e
(2) ligar **detecção cega OOB** por padrão (self-host). `cde_targets` deve **dirigir** a
metodologia (profundidade/prioridade), não só gatear PAN/Magecart.

---

## Potencial ocioso das ferramentas (black-box/CDE)

| Ferramenta | Como está | Não aproveitado |
|---|---|---|
| **httpx** (`stiglitz.sh:863`) | `-status-code -title -tech-detect` | `-favicon` (hash mmh3→produto→CVE), `-jarm`, `-asn`/`-cdn`, body/header hash |
| **katana** (`:961`) | só `-u $TARGET` (1 host raiz), `-d 5` | não recebe **todos os hosts vivos** do httpx; sem `-aff`/`-fx`; sem fontes passivas (gau/waymore) |
| **ffuf** (`:2658`) | só `${TARGET}/FUZZ`, 1 passada | sem `-recursion`, sem `-e` (extensões), sem auto-calibração `-ac`, wordlist não derivada do OpenAPI/JS |
| **nuclei** | tags adaptativas + `-dast` + custom (bom) | OAST `-no-interactsh` por padrão → SSRF/RCE/SSTI/XXE **cegos invisíveis**; sem `-as` |
| **OpenAPI** (`lib/openapi_seed.py`) | spec → URL semeada no ZAP | descarta **método** + `security:`; sem broken-auth, sem fuzz por schema, sem mass-assignment |
| **Authz** (`lib/bola.py`) | exige 2 tokens | sem IDOR tokenless (ID sequencial + body-diff), sem method/verb tampering |

---

## P0 — Maior alavanca (ataca o sintoma "só headers", zero-cred)

| Item | Esf | Impacto | O quê | Tools / arquivos |
|---|---|---|---|---|
| **P0.1 OpenAPI como motor** | M | **Muito alto** | Por operação documentada: **broken-auth** (endpoint com `security:` que responde 2xx/dados **sem token** → High confirmável), request method-aware, fuzz de params por schema → `nuclei -dast`. Reusa canário do `bola.py`. | novo `lib/openapi_probe.py`; consome `raw/openapi_spec.json`; netproxy/mtls; resolve o `⏳ OpenAPI seeding mutante` do ROADMAP.md |
| **P0.2 OOB cego on-by-default (self-host)** | M | **Alto** | Subir/usar **interactsh self-hosted automaticamente** (callbacks na própria infra, sem vazar p/ terceiros); OOB ligado por padrão. Desbloqueia classe inteira de blind SSRF/RCE/SSTI/XXE. | `lib/oob.py`, `NUCLEI_OAST_FLAGS` em `stiglitz.sh`; resolve o `⏳ OAST always-on` |
| **P0.3 CDE como lente que dirige** | M | **Alto** | Host ∈ `cde_targets` **escala** o scan: ffuf recursivo, katana fundo, OOB on, broken-auth probe, method tampering, severidade com contexto de negócio. + auto-detecção de superfície de pagamento (campos cartão/checkout/tech PCI) p/ candidatos não-declarados. | `lib/cde_scope.py` (vira driver, não só gate); orquestração no `stiglitz.sh` |

## P1 — Forte; preenche potencial ocioso das ferramentas

| Item | Esf | Impacto | O quê | Tools / arquivos |
|---|---|---|---|---|
| **P1.1 favicon-hash → CVE** | S | Médio-alto | `-favicon`/`-jarm`/`-asn` no httpx; hash mmh3 → produto → seleção de template nuclei + CVE conhecida | `stiglitz.sh:863`, `lib/httpx_parse.py` |
| **P1.2 ffuf de verdade** | S-M | Médio-alto | `-recursion -recursion-depth 2`, `-e` por tech-profile, `-ac` (mata ruído 401/403), wordlist semeada de OpenAPI/JS | `stiglitz.sh:2658` |
| **P1.3 katana full-surface** | M | Médio-alto | Alimentar **todos os hosts vivos** do httpx; `-aff`/`-fx`; endpoints históricos (gau/waymore) → acha versões de API esquecidas | `stiglitz.sh:961` |
| **P1.4 method/verb tampering** | M | Médio-alto | Zero-cred: 403 num método → 200 noutro; `X-HTTP-Method-Override`; trailing-slash/case → bypass de authz | novo `lib/method_tamper.py` |

## P2 — Profundidade/qualidade

| Item | Esf | Impacto | O quê | Tools / arquivos |
|---|---|---|---|---|
| **P2.1 IDOR/BOLA tokenless** | M | Médio | IDs sequenciais/UUID descobertos unauth + body-diff canário (reusa `bola.verdict`), GET-only não-destrutivo | `lib/bola.py` (modo tokenless) |
| **P2.2 nuclei `-as` + fuzzing** | S | Médio | Auto-seleção por wappalyzer + fuzzing templates agressivo, passada complementar nos hosts CDE | `stiglitz.sh` (P4) |
| **P2.3 pivot por secret vazado** | M | Médio | Key viva achada por trufflehog/JS re-autentica e **expande** a superfície autenticada automaticamente | `lib/js_analysis.py` → feedback no pipeline |
| **P2.4 GraphQL black-box sem token** | M | Médio | Enumeração via introspection; field-suggestion attack quando introspection off | `lib/graphql_authz.py` (modo unauth) |

---

## Decisões registradas (2026-06-28)

- **Caso dominante = zero-credencial.** Centro de gravidade do roadmap é extrair High/Critical
  **sem** conta de teste. Capacidades token-dependentes (P9.5/9.7/9.8) permanecem, mas não são
  o caminho principal.
- **CDE é declarado** (`cde_targets.txt`) → deve **dirigir** profundidade e prioridade (P0.3),
  não só anexar detectores PAN/Magecart.
- **OOB (P0.2): self-host auto-gerenciado, on por padrão.** Callbacks ficam na própria infra —
  sem egress p/ servidor público de terceiros (preserva RoE em produção).

## Sequenciamento sugerido

1. **P0.1** (OpenAPI motor) — maior conversão de "0 High" → findings reais, isolado e testável.
2. **P0.3** (CDE driver) — amarra o resto à lente CDE; barato depois do P0.1.
3. **P0.2** (OOB self-host) — exige infra; rodar em paralelo ao P0.1.
4. **P1.1/P1.2** (favicon, ffuf) — ganhos rápidos de superfície (esforço S).
5. **P1.3/P1.4 → P2.\*** conforme orçamento.

## Não-objetivos

- Não substituir as capacidades token-dependentes existentes — complementá-las p/ o caso zero-cred.
- Não versionar dado de cliente/CDE (memória local apenas).
- Não ligar OOB público por padrão (decisão P0.2).
