# Subdomain Takeover via nuclei (osint.sh) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Substituir a detecção frágil de subdomain takeover do `osint.sh` (string-match + status-code) por um fluxo híbrido CNAME-externo → confirmação por `nuclei -tags takeover`, com avisos de dependência sempre no terminal e preflight completo.

**Architecture:** Lógica pura e testável em `lib/takeover.py` (4 funções + CLI fina); o `osint.sh` (fase 8 `phase_cloud_surface`) orquestra `dnsx` (coleta de CNAME) → filtro Python (externos ao `BASE_DOMAIN`) → `nuclei` (confirma por fingerprint de body) → parse Python (CSV). Toda ausência/falha de ferramenta vira `warn` no terminal sem abortar a fase.

**Tech Stack:** Python 3 (stdlib: `json`, `csv`, `io`), pytest, bash. Ferramentas: `dnsx`, `nuclei` (ambas opt-in, degradam com aviso).

---

## Referências de assinaturas reais (do código atual)

- Helpers de log em `osint.sh`: `phase()`, `info()` (`[✓]`), `warn()` (`[!]`), `fail()` (`[✗]`), `step()` (`[→]`), `has()` (= `command -v "$1" &>/dev/null`). Linhas 92–101.
- Fase 8 = `phase_cloud_surface()` (linha 837), opt-in via `ACTIVE_CLOUD=true`. O sub-passo de takeover atual ocupa as **linhas 903–947**.
- `validate_tools()` linhas 210–241: `required=(curl dig python3)`, `optional=(whois subfinder amass dnsx theHarvester waybackurls gau trufflehog jq)`; avisos de API key linhas 235–238 (Hunter na 238 usa `|| true` silencioso).
- Apex do alvo já disponível em `BASE_DOMAIN` (osint.sh:202). Subdomínios vivos em `$OUTDIR/subdomains_live.txt`.
- O relatório consome `cloud/takeover_candidates.csv` via `count_lines` e `section2` (4 colunas: `subdomain,cname,service,status`). **Schema não muda.**
- Convenção de testes: `tests/test_*.py`, `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))`.
- `osint.sh` **não** define `SCRIPT_DIR` nem usa `lib/*.py` hoje — a Task 6 introduz ambos.

---

## Task 1: `lib/takeover.py` — `is_external_cname`

**Files:**
- Create: `lib/takeover.py`
- Test: `tests/test_takeover.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_takeover.py
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import takeover as T


def test_is_external_cname_distinguishes_third_party_from_apex():
    b = "target.com"
    assert T.is_external_cname("x.target.com.s3.amazonaws.com", b) is True
    assert T.is_external_cname("myorg.github.io", b) is True
    assert T.is_external_cname("cdn.target.com", b) is False   # interno
    assert T.is_external_cname("target.com", b) is False       # apex
    assert T.is_external_cname("TARGET.COM.", b) is False      # apex (case/dot)
    assert T.is_external_cname("", b) is False
    assert T.is_external_cname("anything.io", "") is False      # sem apex
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'takeover'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/takeover.py
#!/usr/bin/env python3
"""
takeover.py — detecção de subdomain takeover (P1).

Fluxo híbrido: o CNAME filtra candidatos (apontam para terceiro), o nuclei
(-tags takeover) confirma por fingerprint de body. Lógica pura + CLI fina que o
osint.sh chama. Sem rede, sem domínio hardcoded (testável e seguro p/ versionar).
"""
import sys
import json
import csv
import io


def _norm(host):
    return (host or "").strip().rstrip(".").lower()


def is_external_cname(cname, base_domain):
    """True se o CNAME aponta para fora do apex do alvo (candidato a takeover)."""
    c, b = _norm(cname), _norm(base_domain)
    if not c or not b:
        return False
    return c != b and not c.endswith("." + b)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/takeover.py tests/test_takeover.py
git commit -m "feat(takeover): is_external_cname — CNAME externo ao apex (P1)"
```

---

## Task 2: `select_external` + `cname_map`

**Files:**
- Modify: `lib/takeover.py`
- Test: `tests/test_takeover.py`

- [ ] **Step 1: Write the failing test**

```python
def _recs():
    # forma do dnsx -cname -json: host + cname (lista)
    return [
        {"host": "ok.target.com", "cname": ["myorg.github.io"]},
        {"host": "cdn.target.com", "cname": ["edge.target.com"]},   # interno
        {"host": "novo.target.com", "cname": ["d1.cloudfront.net", "x.target.com"]},
        {"host": "semcname.target.com"},                            # sem cname
        {"host": "strform.target.com", "cname": "app.herokuapp.com"},  # cname string
    ]


def test_select_external_keeps_only_third_party_first_match():
    out = T.select_external(_recs(), "target.com")
    hosts = [h for h, _c in out]
    assert "ok.target.com" in hosts
    assert "novo.target.com" in hosts
    assert "strform.target.com" in hosts
    assert "cdn.target.com" not in hosts
    assert "semcname.target.com" not in hosts
    d = dict(out)
    assert d["novo.target.com"] == "d1.cloudfront.net"   # primeiro externo


def test_cname_map_picks_first_cname_normalized():
    m = T.cname_map(_recs())
    assert m["ok.target.com"] == "myorg.github.io"
    assert m["strform.target.com"] == "app.herokuapp.com"
    assert "semcname.target.com" not in m
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: FAIL — `AttributeError: module 'takeover' has no attribute 'select_external'`

- [ ] **Step 3: Implement**

Adicionar a `lib/takeover.py`:

```python
def _cnames_of(rec):
    cl = rec.get("cname") or []
    if isinstance(cl, str):
        cl = [cl]
    return [c for c in cl if c]


def select_external(cnames, base_domain):
    """cnames: lista de dicts {host, cname:[...]}. Retorna [(host, cname_externo)],
    o primeiro CNAME externo de cada host."""
    out = []
    for rec in cnames:
        host = _norm(rec.get("host"))
        if not host:
            continue
        for c in _cnames_of(rec):
            if is_external_cname(c, base_domain):
                out.append((host, _norm(c)))
                break
    return out


def cname_map(cnames):
    """Mapa host -> primeiro CNAME (normalizado). Hosts sem CNAME são omitidos."""
    m = {}
    for rec in cnames:
        host = _norm(rec.get("host"))
        cl = _cnames_of(rec)
        if host and cl:
            m[host] = _norm(cl[0])
    return m
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/takeover.py tests/test_takeover.py
git commit -m "feat(takeover): select_external + cname_map (filtro CNAME externo) (P1)"
```

---

## Task 3: `parse_nuclei`

**Files:**
- Modify: `lib/takeover.py`
- Test: `tests/test_takeover.py`

- [ ] **Step 1: Write the failing test**

```python
def test_parse_nuclei_extracts_confirmed_takeovers():
    jsonl = "\n".join([
        '{"template-id":"github-takeover","host":"https://ok.target.com",'
        '"matched-at":"https://ok.target.com","info":{"name":"GitHub Takeover","severity":"high"}}',
        '   ',  # linha em branco ignorada
        'not-json-line',  # ignorada
        '{"template-id":"heroku-takeover","host":"app.target.com:443",'
        '"info":{"severity":"medium"}}',
        '{"info":{"name":"sem host"}}',  # sem host → ignorada
    ])
    res = T.parse_nuclei(jsonl)
    assert len(res) == 2
    a = next(r for r in res if r["host"] == "ok.target.com")
    assert a["service"] == "github-takeover"
    assert a["severity"] == "high"
    assert a["matched_at"] == "https://ok.target.com"
    b = next(r for r in res if r["host"] == "app.target.com")  # porta removida
    assert b["severity"] == "medium"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: FAIL — `AttributeError: ... 'parse_nuclei'`

- [ ] **Step 3: Implement**

Adicionar a `lib/takeover.py`:

```python
def _host_only(s):
    s = (s or "").replace("https://", "").replace("http://", "")
    s = s.split("/")[0].split(":")[0]
    return _norm(s)


def parse_nuclei(jsonl_text):
    """Extrai takeovers confirmados de um JSONL do nuclei.
    Retorna lista de {host, service, severity, matched_at}. Linhas inválidas
    ou sem host são ignoradas."""
    results = []
    for line in (jsonl_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        host = _host_only(obj.get("host") or obj.get("matched-at"))
        if not host:
            continue
        info = obj.get("info") or {}
        results.append({
            "host": host,
            "service": obj.get("template-id") or info.get("name") or "unknown",
            "severity": info.get("severity") or "unknown",
            "matched_at": obj.get("matched-at") or obj.get("host") or "",
        })
    return results
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/takeover.py tests/test_takeover.py
git commit -m "feat(takeover): parse_nuclei — extrai takeovers confirmados do JSONL (P1)"
```

---

## Task 4: `build_candidates_csv`

**Files:**
- Modify: `lib/takeover.py`
- Test: `tests/test_takeover.py`

- [ ] **Step 1: Write the failing test**

```python
import csv as _csv, io as _io


def test_build_candidates_csv_schema_and_join():
    confirmed = [
        {"host": "ok.target.com", "service": "github-takeover"},
        {"host": "app.target.com", "service": "heroku-takeover"},
    ]
    cmap = {"ok.target.com": "myorg.github.io", "app.target.com": "app.herokuapp.com"}
    text = T.build_candidates_csv(confirmed, cmap)
    rows = list(_csv.reader(_io.StringIO(text)))
    assert rows[0] == ["subdomain", "cname", "service", "status"]
    assert ["ok.target.com", "myorg.github.io", "github-takeover", "CONFIRMED"] in rows
    assert ["app.target.com", "app.herokuapp.com", "heroku-takeover", "CONFIRMED"] in rows


def test_build_candidates_csv_empty_is_header_only():
    text = T.build_candidates_csv([], {})
    rows = list(_csv.reader(_io.StringIO(text)))
    assert rows == [["subdomain", "cname", "service", "status"]]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: FAIL — `AttributeError: ... 'build_candidates_csv'`

- [ ] **Step 3: Implement**

Adicionar a `lib/takeover.py`:

```python
def build_candidates_csv(confirmed, cname_map):
    """Monta o CSV (schema legado: subdomain,cname,service,status=CONFIRMED).
    Junta o CNAME pelo mapa host->cname."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["subdomain", "cname", "service", "status"])
    for c in confirmed:
        host = c.get("host", "")
        w.writerow([host, cname_map.get(host, ""),
                    c.get("service", "unknown"), "CONFIRMED"])
    return buf.getvalue()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/takeover.py tests/test_takeover.py
git commit -m "feat(takeover): build_candidates_csv — CSV compatível com o relatório (P1)"
```

---

## Task 5: CLI `main(argv)` — `select-external` / `build-csv`

**Files:**
- Modify: `lib/takeover.py`
- Test: `tests/test_takeover.py`

- [ ] **Step 1: Write the failing test**

```python
def test_cli_select_external_prints_hosts(tmp_path, capsys):
    cn = tmp_path / "cnames.json"
    cn.write_text(
        '{"host":"ok.target.com","cname":["myorg.github.io"]}\n'
        '{"host":"cdn.target.com","cname":["edge.target.com"]}\n'
    )
    rc = T.main(["takeover.py", "select-external", str(cn), "target.com"])
    out = capsys.readouterr().out.split()
    assert rc == 0
    assert "ok.target.com" in out
    assert "cdn.target.com" not in out


def test_cli_build_csv_joins_nuclei_and_cnames(tmp_path, capsys):
    cn = tmp_path / "cnames.json"
    cn.write_text('{"host":"ok.target.com","cname":["myorg.github.io"]}\n')
    nu = tmp_path / "nuclei.jsonl"
    nu.write_text('{"template-id":"github-takeover","host":"ok.target.com",'
                  '"info":{"severity":"high"}}\n')
    rc = T.main(["takeover.py", "build-csv", str(nu), str(cn)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ok.target.com,myorg.github.io,github-takeover,CONFIRMED" in out


def test_cli_unknown_command_returns_2(capsys):
    assert T.main(["takeover.py", "bogus"]) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: FAIL — `AttributeError: ... 'main'`

- [ ] **Step 3: Implement**

Adicionar a `lib/takeover.py`:

```python
def _load_jsonl(path):
    recs = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                continue
    return recs


def main(argv):
    if len(argv) < 2:
        print("uso: takeover.py <select-external CNAMES BASE | build-csv NUCLEI CNAMES>",
              file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "select-external":
        cnames = _load_jsonl(argv[2])
        for host, _c in select_external(cnames, argv[3]):
            print(host)
        return 0
    if cmd == "build-csv":
        with open(argv[2], encoding="utf-8") as fh:
            confirmed = parse_nuclei(fh.read())
        cmap = cname_map(_load_jsonl(argv[3]))
        sys.stdout.write(build_candidates_csv(confirmed, cmap))
        return 0
    print(f"comando desconhecido: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_takeover.py -q`
Expected: PASS

- [ ] **Step 5: Verify module compiles**

Run: `python3 -m py_compile lib/takeover.py`
Expected: sem saída (ok)

- [ ] **Step 6: Commit**

```bash
git add lib/takeover.py tests/test_takeover.py
git commit -m "feat(takeover): CLI select-external/build-csv p/ o osint.sh (P1)"
```

---

## Task 6: Wire no `osint.sh` — substituir o sub-passo de takeover

**Files:**
- Modify: `osint.sh` (adicionar `SCRIPT_DIR`; substituir linhas 903–947 dentro de `phase_cloud_surface`)

- [ ] **Step 1: Adicionar `SCRIPT_DIR` próximo aos helpers (após a linha `has()`, ~linha 101)**

Localizar a linha `has()    { command -v "$1" &>/dev/null; }` (linha 101) e inserir logo abaixo:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
```

- [ ] **Step 2: Localizar o bloco atual do takeover**

Run:
```bash
grep -n "Subdomain Takeover — CNAMEs para serviços cloud mortos\|info \"Buckets S3/Azure" osint.sh
```
Expected: identifica o início (comentário ~903) e a linha `info "Buckets S3/Azure → ${BUCKETS_FOUND}"` (~944) que **permanece**. Substituiremos da linha do comentário até imediatamente antes desse `info "Buckets...`.

- [ ] **Step 3: Substituir o bloco (903–943) pelo fluxo híbrido**

Remover o bloco antigo (lista `takeover_services`, loop `dig CNAME` + `grep` + `curl` status-code) e colocar no lugar:

```bash
    # ── Subdomain Takeover — CNAME externo confirmado por nuclei ──
    step "Subdomain takeover — coleta de CNAME (dnsx) + confirmação (nuclei)"
    echo "subdomain,cname,service,status" > "$OUTDIR/cloud/takeover_candidates.csv"
    local tk_cnames="$OUTDIR/cloud/cnames.json"
    local tk_targets="$OUTDIR/cloud/takeover_targets.txt"
    local tk_nuclei="$OUTDIR/cloud/takeover_nuclei.jsonl"

    if ! has dnsx; then
        warn "takeover: dnsx indisponível — confirmação de takeover pulada"
    elif ! dnsx -l "$OUTDIR/subdomains_live.txt" -cname -json -silent > "$tk_cnames" 2>/dev/null \
            || [ ! -s "$tk_cnames" ]; then
        warn "takeover: coleta de CNAME (dnsx) falhou ou sem CNAMEs"
    else
        if ! python3 "$SCRIPT_DIR/lib/takeover.py" select-external "$tk_cnames" "$BASE_DOMAIN" \
                > "$tk_targets" 2>/dev/null; then
            warn "takeover: filtro de CNAME externo falhou"
        elif [ ! -s "$tk_targets" ]; then
            info "takeover: nenhum candidato externo"
        elif ! has nuclei; then
            warn "takeover: nuclei indisponível — confirmação pulada (defina/instale nuclei)"
        else
            nuclei -l "$tk_targets" -tags takeover -jsonl -silent -o "$tk_nuclei" 2>/dev/null
            local nuc_rc=$?
            if [ "$nuc_rc" -eq 0 ]; then
                python3 "$SCRIPT_DIR/lib/takeover.py" build-csv "$tk_nuclei" "$tk_cnames" \
                    > "$OUTDIR/cloud/takeover_candidates.csv" 2>/dev/null \
                    || warn "takeover: parse do resultado nuclei falhou"
            else
                warn "takeover: nuclei retornou erro (código $nuc_rc)"
            fi
        fi
    fi

    local takeover_count
    takeover_count=$(( $(wc -l < "$OUTDIR/cloud/takeover_candidates.csv") - 1 ))
    [ "$takeover_count" -lt 0 ] && takeover_count=0
```

> O `info "Buckets S3/Azure → ${BUCKETS_FOUND}"` e o resumo final permanecem logo abaixo,
> mas troque a mensagem do resumo de takeover para refletir confirmação:
> ```bash
>     [ "$takeover_count" -gt 0 ] && \
>         warn "Subdomain takeover CONFIRMADO → ${takeover_count}" || \
>         info "Subdomain takeover → nenhum confirmado"
> ```

- [ ] **Step 4: Validar sintaxe e lint**

Run:
```bash
bash -n osint.sh
shellcheck --severity=warning osint.sh
```
Expected: sem erros de sintaxe; shellcheck limpo (sem novos warnings introduzidos pelo bloco).

- [ ] **Step 5: Smoke — degradação sem nuclei/dnsx**

Run:
```bash
grep -n "select-external\|build-csv\|takeover: nuclei indisponível\|SCRIPT_DIR=" osint.sh
```
Expected: confirma o wiring (CLI chamada nos dois pontos, mensagem de degradação presente, `SCRIPT_DIR` definido).

- [ ] **Step 6: Commit**

```bash
git add osint.sh
git commit -m "feat(osint): subdomain takeover híbrido (dnsx + nuclei) com avisos no terminal (P1)"
```

---

## Task 7: Preflight completo — `validate_tools` (+nuclei/+shodan, fix API keys)

**Files:**
- Modify: `osint.sh` (`validate_tools`, linhas 214 e 235–238)

- [ ] **Step 1: Adicionar `nuclei` e `shodan` ao array `optional` (linha 214)**

Trocar:
```bash
    local optional=(whois subfinder amass dnsx theHarvester waybackurls gau trufflehog jq)
```
por:
```bash
    local optional=(whois subfinder amass dnsx theHarvester waybackurls gau trufflehog jq nuclei shodan)
```

- [ ] **Step 2: Acrescentar notas específicas após o loop `optional` (logo após o `done` da linha ~232)**

Inserir, antes do `echo ""` da linha 234:
```bash
    has nuclei || warn "  ↳ sem nuclei: confirmação de subdomain takeover (Fase 8) será pulada"
    has dnsx   || warn "  ↳ sem dnsx: coleta de CNAME p/ takeover indisponível (Fase 8)"
```

- [ ] **Step 3: Tornar o aviso do Shodan e do Hunter consistentes (linhas 235 e 238)**

Trocar a linha 235:
```bash
    [ -n "$SHODAN_KEY" ]   && info "Shodan API key   → configurada" || warn "Shodan API key   → não configurada (fase ignorada)"
```
por (distingue binário ausente de chave ausente):
```bash
    if ! has shodan; then
        warn "Shodan CLI       → binário ausente (fase Shodan ignorada)"
    elif [ -z "$SHODAN_KEY" ]; then
        warn "Shodan API key   → não configurada (fase Shodan ignorada)"
    else
        info "Shodan           → CLI + key OK"
    fi
```

Trocar a linha 238 (remove o `|| true` silencioso):
```bash
    [ -n "$HUNTER_KEY" ]   && info "Hunter.io key    → configurada" || true
```
por:
```bash
    [ -n "$HUNTER_KEY" ]   && info "Hunter.io key    → configurada" || warn "Hunter.io key    → não configurada (fase ignorada)"
```

- [ ] **Step 4: Validar e confirmar cobertura**

Run:
```bash
bash -n osint.sh
shellcheck --severity=warning osint.sh
grep -n "nuclei shodan)" osint.sh
grep -n "Hunter.io key.*não configurada\|Shodan CLI.*binário ausente" osint.sh
```
Expected: sintaxe ok; shellcheck limpo; `optional` inclui `nuclei`/`shodan`; avisos de Hunter e Shodan presentes.

- [ ] **Step 5: Commit**

```bash
git add osint.sh
git commit -m "feat(osint): preflight completo — nuclei/shodan + avisa toda dep/API key ausente (P1)"
```

---

## Task 8: Validação final + docs

**Files:**
- Modify: `CLAUDE.md` (registrar takeover via nuclei + `lib/takeover.py`)

- [ ] **Step 1: Suite completa verde**

Run: `python3 -m pytest tests/ -q`
Expected: PASS (sem regressões; inclui `tests/test_takeover.py`).

- [ ] **Step 2: Compilar módulo e validar bash**

Run:
```bash
python3 -m py_compile lib/takeover.py
bash -n osint.sh && shellcheck --severity=warning osint.sh
```
Expected: sem saída do py_compile; bash/shellcheck limpos.

- [ ] **Step 3: Atualizar CLAUDE.md**

- Na descrição da **Fase 8 / Cloud Surface** do `osint.sh` (ou na seção do `osint.sh`), registrar que o subdomain takeover passou a ser **híbrido**: `dnsx` (CNAME externo ao apex) + `nuclei -tags takeover` (confirmação por fingerprint de body), com degradação avisada no terminal quando `dnsx`/`nuclei` faltam.
- Acrescentar `takeover.py` na tabela de módulos `lib/`: *"Detecção de subdomain takeover — filtro de CNAME externo + parse do JSONL do nuclei → `cloud/takeover_candidates.csv` (schema legado, status CONFIRMED). Lógica pura + CLI; opt-in via fase active-cloud."*
- Registrar que `validate_tools` agora cobre `nuclei`/`shodan` e avisa toda dependência/chave de API ausente.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: subdomain takeover via nuclei (osint), lib/takeover.py, preflight (P1)"
```

---

## Self-review (preenchido pelo autor do plano)

- **Cobertura do spec:** `lib/takeover.py` 4 funções (T1–T4) + CLI (T5); wiring osint.sh com error-handling sempre-avisa (T6); preflight completo +nuclei/+shodan e fix API keys Hunter/Shodan (T7); docs + suite (T8). Filtro "CNAME externo ao BASE_DOMAIN" em T1/T2; CSV schema legado `subdomain,cname,service,status` em T4; raw `takeover_nuclei.jsonl` gerado em T6. ✓ todos os itens do spec mapeados.
- **Placeholders:** nenhum "TODO/TBD"; todo passo de código mostra o código real.
- **Consistência de tipos:** `is_external_cname(cname, base_domain)`, `select_external(cnames, base_domain)->[(host,cname)]`, `cname_map(cnames)->dict`, `parse_nuclei(jsonl)->[{host,service,severity,matched_at}]`, `build_candidates_csv(confirmed, cname_map)->str`, `main(argv)->int` — usados com as mesmas assinaturas em T1–T6 (CLI e bash). `BASE_DOMAIN`, `OUTDIR`, `SCRIPT_DIR`, helpers `has/info/warn/step` conferidos contra o código real.

## Pendência operacional (pré-push)

Política mantida: trabalho **local** até autorização explícita. Antes de QUALQUER `git push`,
permanece pendente o shred seguro de `scan_pos.example.com_20260606_144522/` + `scan_pos_full.log`
(dados CDE de cliente). Nenhum artefato de alvo deste plano é versionado — `cloud/*.json|csv|txt`
ficam no `OUTDIR` gitignored; testes usam `target.com` sintético.
