# Dedup semântico — design (P2)

> **Higienizado:** nenhum dado de CDE/cliente/alvo aqui. Design de ferramenta genérica.
> Decisões tomadas via brainstorming em 2026-06-09. Primeiro item do backlog P2.

## Problema

O Stiglitz tem dedup **sintático e por-fonte**, espalhado, que não colapsa o mesmo
problema quando ele aparece de formas levemente diferentes:

- `lib/evidence.py` (path do RED): chave `(tool, type, target[:60])` — **exata por
  ferramenta**. Mesma vuln achada por nuclei *e* ZAP = 2 findings (tools diferentes).
- `stiglitz_report.py` (path do scan): nuclei por `(template-id, host)`; ZAP por `name`;
  testssl por `id`. Tudo dentro de cada fonte, nunca cross-fonte.
- `lib/fingerprint.py`: já deriva identidade estável `hash(classe, host, path-template,
  param)` e o docstring diz **"Base para dedup semântico"** — mas hoje só alimenta
  `finding_state`/SARIF cross-scan, **não** o dedup in-scan.

**Lacuna:** colapsar findings que são *o mesmo problema* mas escapam por diferença
sintática — duplicatas **cross-tool** (nuclei+ZAP+retire+service_versions reportando o
mesmo CWE/CVE no mesmo lugar) e **variantes de path/param** (`/user/1`, `/user/2` →
`/user/{id}`).

## Decisões de design (travadas no brainstorming)

| Dimensão | Decisão |
|---|---|
| Critério de merge | **Cross-tool + fuzzy** — além do fingerprint, mescla por similaridade de título/evidência/CVE |
| Segurança do fuzzy | **Auto-merge agressivo, score único** (CVE+título+evidência) acima de threshold. Sem artefato de auditoria separado, sem gate de revisão manual |
| Proveniência | Mantida **no próprio finding** (campos intrínsecos do merge), não em relatório à parte |
| Onde aplica | **Módulo compartilhado `lib/dedup.py`**, atuando no path do **scan** (a montante de SARIF/state/trackers/HTML) **e** no path do **RED** (`evidence.py`) |

## Arquitetura

### Módulo `lib/dedup.py`
Módulo **puro** (sem rede), padrão `fingerprint.py`/`bola.py`: **lógica + CLI primeiro**,
integração depois. Reusa `fingerprint.py` (`vuln_class`, `normalize_path`, `fingerprint`)
— não reimplementa normalização de path/classe.

**Interface pública:**
```python
def dedupe(findings: list[dict], threshold: float = DEFAULT_THRESHOLD) -> list[dict]:
    """Colapsa findings semanticamente equivalentes. Determinístico, sem rede.
    Tolera as duas formas de finding do projeto (scan e RED)."""
```
Entrada tolerante: lê `url` (scan) ou `target`/`matched_at` (RED) para host/path; classe
via `vuln_class` (já cobre `cwe`/`cve`/`type`/`name`). Saída: lista deduplicada, cada
finding com proveniência de merge anexada.

**CLI:**
```bash
python3 lib/dedup.py <findings.json>     # imprime deduplicado + resumo "N → M (K merges)"
```
Aceita `[...]` ou `{"findings": [...]}`. Útil standalone e para validação ao vivo.

### Algoritmo (score único, agressivo)

**Estágio 1 — bucket exato por fingerprint** — O(n):
agrupa por `fingerprint(finding)` = `(classe, host, path-template, param)`. Todos no mesmo
bucket mesclam (score = 1.0). Resolve cross-tool idêntico + variantes `/user/1`≡`/user/2`
de graça, já que `normalize_path` templatiza segmentos numéricos/UUID.

**Estágio 2 — fuzzy entre representantes de bucket** — *blocado por host*:
só compara representantes do **mesmo host** (evita merge cross-host e limita o O(n²) ao
tamanho de cada bloco-host). Score combinado único, soma ponderada de:
- **CVE compartilhado** — sinal forte (maior peso): se dois findings citam o mesmo CVE,
  são quase-certamente o mesmo problema (mesmo com mapeamento CWE divergente).
- **Mesma `vuln_class`** — (host já garantido pelo bloco).
- **Similaridade de título** — `difflib.SequenceMatcher` ratio ou Jaccard de tokens sobre
  títulos normalizados (lowercase, sem pontuação, sem números de versão).
- **Similaridade de evidência** — peso menor, sobre snippet/`evidence` normalizado.

`score ≥ threshold` → mescla os buckets. `DEFAULT_THRESHOLD` é constante do módulo,
overridável por env `STIGLITZ_DEDUP_THRESHOLD`. Pesos são constantes nomeadas no topo do
módulo (fáceis de tunar).

> **Nota de risco aceita:** auto-merge agressivo sem gate de revisão pode, em teoria,
> colapsar dois findings genuinamente distintos (sub-reporte). Mitigação intrínseca: o
> bloqueio por host + exigência de classe/CVE/título concordantes; e a proveniência
> preservada no finding permite auditoria *a posteriori* e o `STIGLITZ_DEDUP=0` permite
> desligar. Não há `dedup_report` separado nem workflow de revisão (decisão explícita).

### Finding mesclado (representação)

O finding resultante carrega proveniência **intrínseca** (insumo do próprio merge — não é
artefato de auditoria à parte):

| Campo | Valor no merge |
|---|---|
| `severity` | máximo dos constituintes (por `sev_order`) |
| `count` | soma dos `count` (default 1 cada) |
| `endpoints` / `urls` | união |
| `param` | união (ou representante) |
| `cve` | união |
| `sources` (ou `tools`) | união ordenada das ferramentas que corroboraram |
| evidência | a mais rica/não-vazia preservada |
| `merged_from` | lista de fingerprints/ids constituintes |
| `merge_score` | score que disparou o merge (1.0 = bucket exato) |
| `fingerprint` | **representante determinístico** — o do bucket exato; em merge fuzzy cross-fingerprint, o de maior severidade (desempate: menor lexicográfico) |

A estabilidade do `fingerprint` representante é **requisito** para o `finding_state`
reconciliar a linhagem cross-scan corretamente (ver Integração).

## Integração

### Path do scan — `stiglitz_report.py`
Ponto único de inserção: deduplica a lista consolidada `all_f` **logo após sua montagem e
ANTES de**:
- `apply_state(all_f, TARGET, _scan_id)` (~linha 1034 → `raw/state_summary.json`)
- `build_sarif(all_f, TARGET)` (~linha 2349 → `findings.sarif`, consumido por
  DefectDojo/Jira)
- renderização do HTML

Assim, **um único call-site** garante que state, SARIF, HTML e trackers vejam o set
deduplicado — contagem consistente em todos os artefatos. Como o dedup roda **antes** do
`apply_state`, e o finding mesclado adota fingerprint representante estável, a
reconciliação NEW/PERSISTENT/RESOLVED cross-scan permanece correta.

### Path do RED — `lib/evidence.py`
Substitui o bloco de dedup cru em `collect_and_consolidate()` (linhas ~391-397, chave
`(tool, type, target[:60])`) por `dedup.dedupe(findings)`. O `report_generator.py`
consome a saída sem mudança de contrato.

### Config & degradação
- `STIGLITZ_DEDUP=0` desliga o dedup (debug / quando over-merge suspeito).
- `STIGLITZ_DEDUP_THRESHOLD=<float>` ajusta o limiar fuzzy.
- Falha no `dedupe()` é capturada nos **dois** call-sites → fallback para a lista
  não-deduplicada (scan) ou o dedup-cru legado (RED). **Nunca aborta o scan** (padrão do
  `try/except` de `criticality` já existente no `evidence.py`).

## Testes (TDD) — `tests/test_dedup.py`

Escritos antes da implementação (RED → GREEN). Casos:

1. **Merge cross-tool exato:** nuclei+ZAP mesmo CWE/host/path → 1 finding, `sources`
   contém ambos, `count = 2`.
2. **Colapso de path-variant:** `/user/1`, `/user/2`, `/user/3` mesma classe → 1 finding,
   `endpoints` = união.
3. **Merge fuzzy por CVE compartilhado:** mesmo CVE, mapeamento CWE divergente → mescla.
4. **Similaridade de título no limiar:** par logo acima do threshold mescla; logo abaixo
   **não** mescla (teste de boundary).
5. **Guard de não-merge (anti-sub-reporte):** host distinto / classe distinta / baixa
   similaridade → permanecem **separados**.
6. **Representação:** `severity` = máx; `count` = soma; `merged_from` populado;
   `fingerprint` representante determinístico e estável.
7. **Degradação:** finding malformado (campos ausentes) não derruba o `dedupe`.
8. **Forma de entrada do RED:** finding com `target` (não `url`) é tratado igual.

## Validação ao vivo

Conforme disciplina do projeto (validar caminhos críticos):
- Rodar `python3 lib/dedup.py` num `findings.json` real de `~/scans/` → observar redução
  N→M e **inspecionar os merges** (sanidade: nenhum merge cross-host/cross-classe óbvio).
- Rodar o path do RED num scan dir existente e conferir o relatório HTML.

## Fora de escopo (YAGNI)

- Boost de confiança na corroboração cross-tool (mencionado, não habilitado — pode entrar
  depois se desejado).
- `dedup_report` separado / workflow de revisão manual (decisão explícita contra).
- Dedup cross-scan (já é responsabilidade do `finding_state` por fingerprint).

## Disciplina de entrega

TDD (teste→RED→GREEN), commits pequenos com `bash -n`/`shellcheck` limpos onde aplicável
e `python3 -m py_compile` nos módulos. Módulo novo = lógica pura + CLI primeiro,
integração depois (padrão `bola.py`/`takeover.py`).
