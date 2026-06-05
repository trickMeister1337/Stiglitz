# Spec — Cobertura PCI DSS no CDE (porte seletivo)

**Data:** 2026-06-04
**Status:** aprovado para planejamento
**Autor:** Stiglitz / sessão de design

> ⚠️ **Sensibilidade:** o escopo CDE real (hosts/URLs) é confidencial e vive **apenas** em `cde_targets.txt` (gitignored), lido em runtime. Este spec e todo o código usam **somente exemplos fictícios** (`example.com`). Nenhum domínio real entra em código/teste/spec/commit.

## 1. Contexto e objetivo

A empresa é uma fintech certificada PCI DSS 4.0.1. O Stiglitz já cobre boa parte da superfície técnica (TLS, headers, nuclei/ZAP, serviços via nmap+vulners, email, criticality KEV>EPSS>CVSS). Faltam três capacidades específicas de PCI, hoje existentes apenas no scanner dedicado separado `swarm-pci/pci_scan.sh`. A decisão (ver memória `pci-coverage-in-stiglitz`) é **portar seletivamente** essas capacidades para o Stiglitz — sem orquestrar o scanner inteiro (evita duplicar network/TLS/vuln scan e dependências pesadas como prowler/trivy/kube-bench).

Objetivo: detectar, **apenas nas URLs declaradas como CDE**, os achados PCI de maior valor e marcá-los com o requisito correspondente, integrados ao relatório e à metodologia de risco já existentes.

## 2. Escopo

**Incluído:**
- Helper de escopo CDE lendo `cde_targets.txt`.
- Detector de PAN exposto (Req 3.5.1).
- Integridade de scripts em páginas de checkout / anti-Magecart (Req 6.4.3 + 11.6.1).
- Campo `pci_req` nos findings + seção "PCI DSS CDE Coverage" no relatório.
- Vereditos PCI derivados de dados já coletados (TLS 4.2.1, serviços 2.2.5, cookies/cache 3.2) — tag PCI só em ativos do CDE.
- Testes unitários por módulo.

**Fora de escopo (YAGNI):**
- Cloud posture (prowler/trivy/kube-bench), relatório PCI formal e SLA tracking — permanecem no `swarm-pci` standalone.
- Inferência de escopo CDE por heurística — o escopo é **explícito** via `cde_targets.txt`.
- Export QSA dedicado (CSV/SARIF PCI) — só seção no relatório + tag.
- Requisitos organizacionais (segmentação, políticas, logging).

## 3. Arquitetura

Quatro unidades novas/estendidas, seguindo o padrão dos coletores do Stiglitz (módulo Python real em `lib/`, fetch próprio, grava `raw/*_findings.json`, agregado pelo `stiglitz_report.py`):

```
cde_targets.txt (gitignored)
        │  parse
        ▼
lib/cde_scope.py  ──> in_cde_scope(url) / cde_class(url) / is_checkout(url)
        │
        ├── lib/pan_scanner.py            (Req 3.5.1)        → raw/pan_findings.json
        ├── lib/payment_page_monitor.py   (Req 6.4.3/11.6.1) → raw/payment_findings.json + baseline
        └── (vereditos)                    derivados de testssl/service_findings/security_headers
                                           → tag pci_req nos findings existentes
        ▼
stiglitz_report.py: agrega *_findings.json + seção "PCI DSS CDE Coverage"
```

Regra de ouro: **detecção dedicada (PAN, Magecart) e tag `pci_req` rodam exclusivamente em URLs que `in_cde_scope()` confirma**. Fora do CDE declarado, nada de fetch extra nem tag PCI.

## 4. `lib/cde_scope.py` — fonte de escopo

**Entrada:** `cde_targets.txt`. Caminho resolvido por env `STIGLITZ_CDE_TARGETS`, senão `<SCRIPT_DIR>/cde_targets.txt`. Ausente ⇒ módulos PCI são pulados silenciosamente (sem CDE declarado = sem scan dedicado).

**Formato (portado do pci_scan):** uma entrada por linha, `#` comentário; colunas `tipo alvo [label] [checkout=true]`; `tipo ∈ {web, infra, both}`.

```
# exemplo FICTÍCIO
web    https://checkout.example.com   checkout-app   checkout=true
web    https://api.example.com
infra  10.0.0.5                       db-node
both   https://gateway.example.com
```

**API:**
- `load_targets(path) -> {web:[], infra:[], checkout:[], labels:{}}`
- `in_cde_scope(url) -> bool` — host (e host/path por glob) casa alguma entrada.
- `cde_class(url) -> "cde"|None` — para alimentar overrides do `asset_classifier` (data_class=cde).
- `is_checkout(url) -> bool` — entrada marcada `checkout=true`.

Matching por host normalizado (e glob de host/path), reutilizando a mesma semântica do `asset_classifier.classify_asset`.

## 5. `lib/pan_scanner.py` — exposição de PAN (Req 3.5.1)

**Alvos:** URLs in-scope (katana) que `in_cde_scope()` confirma + `js_files/` já baixados (sem novos fetches quando possível) + páginas de erro.

**Pipeline:** regex de candidatos por bandeira (Visa/MC/Amex/Discover) → **validação Luhn** → filtro de contexto (proximidade de `card/cvv/pan/expiry` ou BIN conhecido) para cortar falso-positivo. Detecta também CVV/track data em claro.

**Mascaramento obrigatório:** persiste só `BIN(6)…last4` (`h[:6]+"*"*(n-10)+h[-4:]`). Nunca grava/loga o PAN inteiro.

**Saída:** `raw/pan_findings.json` — findings `severity=critical`, `pci_req="3.5.1"`, `cwe="CWE-359"`, evidência mascarada.

## 6. `lib/payment_page_monitor.py` — integridade de checkout / Magecart (Req 6.4.3 + 11.6.1)

**Alvos:** apenas `is_checkout()` (entradas `checkout=true`); fallback: web in-scope com formulário de cartão detectado.

**Lógica:** fetch HTML → inventaria `<script src>` → classifica 1ª/3ª parte → para cada script baixa e calcula **SHA-384** → flags: script de 3ª parte, ausência de **SRI** (`integrity=`), **CSP** ausente/permissiva. Grava `raw/payment_baseline/<host>.json`. Se houver baseline anterior (`--previous`/`stiglitz_diff.py`): script novo/alterado ⇒ finding `high` (potencial skimmer).

**Saída:** `raw/payment_findings.json` — `pci_req="6.4.3, 11.6.1"`; baseline para diff entre scans.

## 7. Vereditos PCI + `pci_req` + relatório

**Vereditos** (reaproveitam dados já coletados; sem novo scan):
- TLS < 1.2 / cipher fraco / cert inválido (do `testssl.json`) → `pci_req="4.2.1"`.
- Serviço inseguro exposto — telnet/ftp/snmp/smbv1/rdp/db (do `service_findings.json`/nmap) → `pci_req="2.2.5"`.
- Cookie de sessão sem `Secure/HttpOnly/SameSite` + `Cache-Control: no-store` ausente (do `security_headers`) → `pci_req="3.2"`.

**Regra:** o `pci_req` só é anexado quando o ativo do finding está `in_cde_scope()`. Findings fora do CDE seguem como hoje, sem tag.

**Relatório (`stiglitz_report.py`):**
- Adicionar `pan_findings.json` e `payment_findings.json` ao loop de agregação (junto de `service_findings.json` etc.).
- Nova seção **"PCI DSS CDE Coverage"**: findings em ativos CDE agrupados por `pci_req`, com a classe do ativo.
- Reusar `criticality.py`/`asset_classifier.py`: o `cde_targets` alimenta overrides `data_class=cde` → boost de severidade no CDE via CVSS Environmental.

## 8. Integração nas fases do `stiglitz.sh`

- Coletores (`pan_scanner`, `payment_page_monitor`) na **Fase 3** (junto a security_headers/version_fingerprint/secscan), guardados por `cde_scope` não-vazio.
- Vereditos PCI na **Fase 6/11** (pós-testssl/serviços).
- Automático, focado no CDE; sem flag obrigatória. Sem `cde_targets.txt` ⇒ no-op.

## 9. Segurança

- `cde_targets.txt` permanece **gitignored**; lido só em runtime.
- Exemplos/fixtures sempre fictícios (`example.com`); testes não contêm hosts reais.
- PAN sempre mascarado antes de persistir; nada de PAN em log.
- `git grep` por termos do cliente faz parte do checklist antes de qualquer push.

## 10. Testes (`tests/`)

- `test_cde_scope.py` — parsing (tipos/comentários/checkout), `in_cde_scope`/`is_checkout`, ausência de arquivo.
- `test_pan_scanner.py` — Luhn (válido/inválido), mascaramento, contexto/BIN, sem falso-positivo em números aleatórios.
- `test_payment_monitor.py` — inventário de scripts, SRI/CSP, baseline/diff (script novo).
- Estender `test_stiglitz_modules.py`/report para a seção PCI e o campo `pci_req`.

## 11. Validação

`bash -n` + `shellcheck --severity=warning` + `py_compile` + suíte do CI (`tests/...`). Sem regressões; novos módulos cobertos.

## 12. Riscos / decisões em aberto

- Falso-positivo de PAN: mitigado por Luhn + contexto; ajustável.
- Gateways de mercado no `asset_classifier` foram generalizados na sanitização — confirmar que a heurística residual ainda serve (escopo real vem do `cde_targets`).
- Cobertura de PAN limitada ao conteúdo acessível por GET não-autenticado (igual ao resto do DAST).
