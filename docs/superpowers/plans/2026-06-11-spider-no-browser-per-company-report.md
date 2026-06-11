# Spider — Descontinuar navegador + relatório por empresa + Axur SOLVED — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remover navegador/modo assistido do Spider, reservar `bloqueado` para o que não dá pra validar automaticamente, gerar um PDF por empresa (vulneráveis + bloqueadas + pendentes) e, na Axur, fechar as bloqueadas como `SOLVED` somente após a extração.

**Architecture:** Refatoração in-place do projeto Spider (Python, `/home/trick/Spider`). A validação diferencial por canário (HTTP) é preservada; toda a camada de navegador sai. `spider_report.py` passa a gerar um PDF por empresa (empresa derivada do domínio) e reordena o push da Axur para fechar bloqueadas só depois do PDF. Validação por testes (`pytest`).

**Tech Stack:** Python 3.12, `requests`, `beautifulsoup4`, `wkhtmltopdf` (render PDF), `pytest`.

**Diretório de trabalho:** todos os caminhos são relativos a `/home/trick/Spider` salvo indicação. Commits no repo `/home/trick/Spider/.git`.

**Spec:** `docs/superpowers/specs/2026-06-11-spider-no-browser-per-company-report-design.md`

---

## Task 0: Branch de trabalho

**Files:** nenhum (git).

- [ ] **Step 1: Criar branch a partir do estado atual**

```bash
cd /home/trick/Spider
git rev-parse --abbrev-ref HEAD          # anota a branch atual
git checkout -b feat/no-browser-per-company-report
```

- [ ] **Step 2: Sanity da suíte antes de mexer**

Run: `cd /home/trick/Spider && python3 -m pytest -q`
Expected: suíte passa (baseline verde antes da refatoração).

---

## Task 1: Remover módulos de navegador

**Files:**
- Delete: `browser.py`
- Delete: `browser_nodriver.py`
- Delete: `test_browser_nodriver.py`

- [ ] **Step 1: Apagar os arquivos de navegador e o teste**

```bash
cd /home/trick/Spider
git rm browser.py browser_nodriver.py test_browser_nodriver.py
```

- [ ] **Step 2: Confirmar que nada mais importa os módulos apagados**

Run: `cd /home/trick/Spider && grep -rn -E 'import +browser(_nodriver)?\b|browser_nodriver|make_browser_attempt' --include='*.py' .`
Expected: **apenas** ocorrências em `spider_report.py` e `differential.py` (serão removidas nas Tasks 2 e 4). Nenhuma em outros arquivos.

- [ ] **Step 3: Commit**

```bash
cd /home/trick/Spider
git commit -m "refactor(spider): remove engines de navegador (browser.py/browser_nodriver.py)"
```

---

## Task 2: `differential.py` — remover navegador/assistido; login dinâmico → `bloqueado`

**Files:**
- Modify: `differential.py`
- Test: `test_differential.py`

### Mudanças de teste primeiro (TDD)

- [ ] **Step 1: Apagar os testes de navegador/assistido obsoletos**

Em `test_differential.py`, **remova por completo** estas funções de teste (não serão mais válidas sem navegador):

```
test_validate_batch_dynamic_uses_browser
test_validate_batch_static_form_falls_back_to_http_when_browser_fails
test_validate_batch_browser_unreachable_but_http_alive_is_verificar
test_validate_batch_browser_reprobe_rescues_blocked
test_validate_batch_browser_reprobe_confirms_blocked
test_validate_batch_static_form_uses_browser_when_enabled
test_fingerprint_passes_assisted
test_compare_blocked_assisted_mfa_marker_ignored
test_compare_blocked_assisted_success_marker_ignored
test_compare_blocked_assisted_auth_cookie_still_vulnerable
test_compare_blocked_but_assisted_judges_by_result
test_compare_blocked_assisted_still_gated_is_blocked
test_compare_blocked_not_assisted_is_blocked
```

- [ ] **Step 2: Adaptar os testes que mencionavam `assisted`/`--assist`/engine**

Substitua estas 4 funções existentes pelas versões abaixo (sem `assisted`, com evidência "manual"):

```python
def test_compare_random_cookie_is_not_vulnerable():
    # canário e real só diferem no sufixo aleatório, e a página está bloqueada → bloqueado
    base = dict(_BASE, cookies=frozenset({'signinmessage', 'cf_clearance'}),
                paths=frozenset({'/core/login'}), login_path='/core/login')
    fp = _fp(blocked=True, body='turnstile',
             cookies=frozenset({'signinmessage', 'cf_clearance'}), final_path='/core/login')
    st, _ = compare(fp, base)
    assert st != 'vulneravel'

def test_compare_real_auth_cookie_still_vulnerable():
    # ganho de cookie de auth REAL (idsrv) numa página não-bloqueada → vulnerável
    base = dict(_BASE, cookies=frozenset({'signinmessage', 'cf_clearance'}),
                paths=frozenset({'/core/login'}), login_path='/core/login')
    fp = _fp(blocked=False, body='welcome',
             cookies=frozenset({'signinmessage', 'cf_clearance', 'idsrv'}), final_path='/account')
    st, ev = compare(fp, base)
    assert st == 'vulneravel' and 'idsrv' in ev

def test_compare_offline_evidence_by_error():
    assert compare(_fp(reachable=False, error='connection'), _BASE)[1] == 'host inalcançável'
    assert 'timeout' in compare(_fp(reachable=False, error='timeout'), _BASE)[1]
    assert compare(_fp(reachable=False, error=None), _BASE)[1] == 'host inalcançável'

def test_compare_blocked_captcha_evidence():
    fp = _fp(blocked=True, status=403, body='turnstile challenge-platform')
    st, ev = compare(fp, _BASE)
    assert st == 'bloqueado' and 'manual' in ev.lower()
```

- [ ] **Step 3: Adaptar `test_validate_batch_uses_rewrite_fn_for_entry` para HTTP (sem navegador)**

Substitua a função existente por:

```python
def test_validate_batch_uses_rewrite_fn_for_entry():
    # URL bloqueada reescrita p/ entrada limpa; probe e logins vão pela entrada,
    # mas o veredito reporta a URL ORIGINAL.
    seen = {'probe': [], 'attempt': []}
    def probe(url, timeout):
        seen['probe'].append(url)
        return {'reachable': True, 'status': 200, 'final_url': url,
                'body': '<form><input type=text name=u><input type=password name=p></form>',
                'had_form': True, 'blocked': False}
    def http(url, user, senha, timeout):
        seen['attempt'].append(url)
        if user.startswith('canary_'):
            return {'reachable': True, 'had_form': True, 'status': 200, 'final_url': url,
                    'cookie_names': frozenset(), 'body': 'invalid credentials'}
        return {'reachable': True, 'had_form': True, 'status': 200, 'final_url': 'https://app/home',
                'cookie_names': frozenset({'auth'}), 'body': 'welcome dashboard'}
    creds = [{'usuario': 'r', 'senha': 'p', 'url': 'https://auth.x.com/blocked', 'empresa': 'X'}]
    rewrite = lambda u: 'https://app.x.com' if 'auth.x.com' in (u or '') else u
    out = validate_batch(creds, http_attempt=http, probe_fn=probe, delay=0, rewrite_fn=rewrite)
    assert seen['probe'] and all(u == 'https://app.x.com' for u in seen['probe'])
    assert seen['attempt'] and all(u == 'https://app.x.com' for u in seen['attempt'])
    assert out[0]['url'] == 'https://auth.x.com/blocked'
    assert out[0]['status'] == 'vulneravel'
```

- [ ] **Step 4: Adicionar o teste novo — login dinâmico vira `bloqueado`**

Adicione (perto dos demais `test_validate_batch_*`):

```python
def test_validate_batch_dynamic_is_blocked():
    # SPA/login JS sem <form> e não bloqueado por WAF → bloqueado (validação manual)
    probe = lambda url, timeout: {'reachable': True, 'status': 200, 'final_url': url,
        'body': '<div id="root"></div><script src=a></script><script src=b></script><script src=c></script>',
        'had_form': False, 'blocked': False}
    called = []
    creds = [{'usuario': 'a', 'senha': 'p', 'url': 'https://x/core/login', 'empresa': 'Acme'}]
    out = validate_batch(creds, http_attempt=lambda *a: called.append(1), probe_fn=probe, delay=0)
    assert out[0]['status'] == 'bloqueado'
    assert 'manual' in out[0]['evidencia'].lower() and called == []
```

- [ ] **Step 5: Rodar os testes de differential e ver que FALHAM**

Run: `cd /home/trick/Spider && python3 -m pytest test_differential.py -q`
Expected: FAIL — `validate_batch`/`compare` ainda têm a assinatura/lógica antiga (ex.: `test_validate_batch_dynamic_is_blocked` falha; `compare` ainda referencia `assisted`).

### Implementação

- [ ] **Step 6: Atualizar as constantes de evidência (`_EV_BLOCK`/`_EV_UNREACHABLE`)**

Em `differential.py`, substitua os dois blocos:

```python
_EV_BLOCK = {'captcha': 'desafio interativo (Turnstile) — validação manual',
             'ip': 'bloqueio por reputação de IP (1020) — validação manual',
             'generic': 'WAF/Cloudflare — validação manual'}


_EV_UNREACHABLE = {
    'timeout': 'timeout na navegação/login',
    'connection': 'host inalcançável',
}
```

- [ ] **Step 7: Remover `assisted` do `fingerprint`**

Em `fingerprint(result)`, apague a linha:

```python
        'assisted': bool(result.get('assisted')),
```

- [ ] **Step 8: Reescrever `compare` sem `assisted` (bloqueado sempre curto-circuita)**

Substitua a função `compare` inteira por:

```python
def compare(real, base):
    """Compara a impressão real contra o baseline → (status, evidencia)."""
    if not real['reachable']:
        return 'offline', _EV_UNREACHABLE.get(real.get('error'), 'host inalcançável')
    if real.get('blocked'):
        return 'bloqueado', _EV_BLOCK[classify_block(real.get('status') or 0, real.get('body'))]
    if not base['had_form']:
        return 'sem_login', 'página sem formulário de senha'
    if not base['usable']:
        return 'verificar', 'baseline (canário) indisponível'
    if real.get('inconclusive'):
        return 'verificar', 'não foi possível dirigir o formulário de login'

    # Só cookies de auth/sessão contam como ganho — tracking/analytics não.
    cookie_gain = {c for c in (real['cookies'] - base['cookies']) if not _is_tracking_cookie(c)}
    mfa_gain = real['mfa'] - base['mfa']
    success_gain = real['success'] - base['success']
    path_new = (real['final_path'] not in base['paths']
                and real['final_path'] != base['login_path'])
    _error_hints = ('erro', 'error', '404', '403', '500', 'denied', 'forbidden',
                    'invalid', 'unknown', 'fail')
    path_looks_clean = not any(h in real['final_path'].lower() for h in _error_hints)
    path_gain = path_new and path_looks_clean
    has_fail = bool(real['fail'])
    strong_gain = bool(cookie_gain or success_gain)

    if has_fail:
        return 'seguro', 'sinal de falha explícito (%s)' % ', '.join(sorted(real['fail']))
    if mfa_gain:
        # 2º fator só confirma a credencial se o 1º foi aceito (cookie de auth ou sucesso).
        if strong_gain:
            return 'vulneravel_mfa', 'MFA exigido (%s)' % ', '.join(sorted(mfa_gain))
        return 'verificar', ('tela de 2º fator (%s) sem cookie de auth nem sinal de sucesso — '
                             '1º fator não confirmado (possível enumeração de usuário/template '
                             'latente)' % ', '.join(sorted(mfa_gain)))
    if strong_gain:
        ev = []
        if cookie_gain:
            ev.append('cookie novo: ' + ', '.join(sorted(cookie_gain)))
        if success_gain:
            ev.append('sinal de sucesso: ' + ', '.join(sorted(success_gain)))
        if path_gain:
            ev.append('redirect %s (canário em %s)'
                      % (real['final_path'], '/'.join(sorted(base['paths'])) or '?'))
        return 'vulneravel', '; '.join(ev) or 'cookie de auth novo'
    if path_gain:
        return 'verificar', ('redirect para %s sem cookie de auth nem sinal de sucesso '
                             '(inconclusivo)' % real['final_path'])
    if real['final_path'] in base['paths'] or real['final_path'] == base['login_path']:
        return 'seguro', 'resposta idêntica ao login falho (canário)'
    return 'verificar', 'resposta não casa com falha nem com sucesso'
```

- [ ] **Step 9: Remover `_with_http_fallback` por completo**

Em `differential.py`, apague a função `_with_http_fallback(primary, secondary)` inteira (não é mais usada sem navegador).

- [ ] **Step 10: Reescrever `validate_batch` sem navegador (dinâmico→bloqueado)**

Substitua a função `validate_batch` inteira por:

```python
def validate_batch(creds, http_attempt=None, probe_fn=None, timeout=12, delay=0.4,
                   progress=None, canary_count=2, rand=None, rewrite_fn=None):
    """Classifica cada endpoint e roteia o grupo para a estratégia certa (100% HTTP).

    rewrite_fn(url)->url reescreve a URL de ENTRADA (probe/login) — ex.: endpoint de auth
    acessível só via redirect do app. O veredito continua reportando a URL original.
    """
    http_attempt = http_attempt or _default_attempt
    probe_fn = probe_fn or _default_probe
    _rw = rewrite_fn or (lambda u: u)
    rng = rand or random.Random()
    groups = {}
    for c in creds:
        groups.setdefault(endpoint_key(c['url']), []).append(c)

    results, counter, total = [], {'n': 0}, len(creds)

    def emit(item):
        results.append(item)
        counter['n'] += 1
        if progress:
            progress(counter['n'], total, item)

    for group in groups.values():
        login_url = group[0]['url']
        entry_url = _rw(login_url)             # URL de entrada efetiva (pode diferir da reportada)
        entry_eff = _normalize_url(entry_url) or entry_url
        http_pr = probe_fn(entry_eff, timeout)
        ptype = classify_login_page(http_pr)

        if ptype == 'offline':
            for c in group:
                emit(_verdict(c, 'offline', 'host inalcançável'))
            continue
        if ptype == 'dead':
            for c in group:
                emit(_verdict(c, 'sem_login', 'URL sem formulário de login (combolist com URL antiga?)'))
            continue
        if ptype == 'blocked':
            sub = classify_block(http_pr.get('status') or 0, http_pr.get('body'))
            for c in group:
                emit(_verdict(c, 'bloqueado', _EV_BLOCK[sub]))
            continue
        if ptype == 'dynamic':
            for c in group:
                emit(_verdict(c, 'bloqueado', 'login dinâmico/JS — validação manual'))
            continue

        # ptype == 'static_form' → valida por HTTP (canário + real)
        attempt = http_attempt
        login_path = urlsplit(entry_eff).path or '/'
        canary_fps = []
        for _ in range(canary_count):
            cu = 'canary_%d@example.invalid' % rng.randrange(10 ** 8)
            cp = 'x%d!' % rng.randrange(10 ** 8)
            canary_fps.append(fingerprint(attempt(entry_eff, cu, cp, timeout)))
            if delay:
                time.sleep(delay)
        base = build_baseline(canary_fps, login_path)
        for c in group:
            real_url = _normalize_url(_rw(c['url'])) or _rw(c['url'])
            status, ev = compare(fingerprint(attempt(real_url, c['usuario'], c['senha'], timeout)), base)
            emit(_verdict(c, status, ev))
            if delay:
                time.sleep(delay)
    return results
```

- [ ] **Step 11: Rodar os testes de differential e ver que PASSAM**

Run: `cd /home/trick/Spider && python3 -m pytest test_differential.py -q`
Expected: PASS (todos). Se algum teste antigo remanescente referenciar `assisted`/`browser_attempt`/`use_browser`, ele foi esquecido no Step 1 — remova-o.

- [ ] **Step 12: Compilar o módulo**

Run: `cd /home/trick/Spider && python3 -m py_compile differential.py`
Expected: sem saída (compila).

- [ ] **Step 13: Commit**

```bash
cd /home/trick/Spider
git add differential.py test_differential.py
git commit -m "refactor(spider): differential 100% HTTP; login dinâmico→bloqueado; evidência 'validação manual'"
```

---

## Task 3: `spider_report.py` — funções de relatório por empresa (sem tocar `main`)

**Files:**
- Modify: `spider_report.py` (adicionar funções + import)
- Test: `test_spider_report.py` (adicionar testes)

- [ ] **Step 1: Escrever os testes das novas funções (que FALHAM)**

Adicione ao fim de `test_spider_report.py`:

```python
from spider_report import _slug, group_by_company, build_company_html, render_company_pdfs

def test_slug_normalizes():
    assert _slug('Acme Hotéis') == 'acme_hoteis'
    assert _slug('Acme2Go') == 'acme2go'
    assert _slug('') == 'outros'

def test_group_by_company_only_actionable():
    validated = [
        {'usuario': 'a', 'empresa': 'Acme', 'status': 'vulneravel'},
        {'usuario': 'b', 'empresa': 'Acme', 'status': 'bloqueado'},
        {'usuario': 'c', 'empresa': 'Acme', 'status': 'verificar'},
        {'usuario': 'd', 'empresa': 'Acme', 'status': 'seguro'},
        {'usuario': 'e', 'empresa': 'Globex', 'status': 'offline'},
    ]
    grupos = group_by_company(validated)
    assert set(grupos.keys()) == {'Acme'}
    assert {r['status'] for r in grupos['Acme']} == {'vulneravel', 'bloqueado', 'verificar'}

def test_build_company_html_sections_and_password():
    rows = [
        {'usuario': 'alice', 'senha': 's3nh@', 'url': 'https://a', 'status': 'vulneravel', 'data': ''},
        {'usuario': 'bob', 'senha': 'p4ss', 'url': 'https://b', 'status': 'bloqueado', 'data': ''},
        {'usuario': 'cy', 'senha': 'p5', 'url': 'https://c', 'status': 'verificar', 'data': ''},
    ]
    out = build_company_html('Acme', rows, {'gerado_em': '2026-06-11 10:00:00'})
    assert 'Credenciais para Reset — Acme' in out
    assert 'Vulneráveis (1)' in out and 'Bloqueadas' in out and 'Pendentes (1)' in out
    assert 's3nh@' in out and 'p4ss' in out and 'p5' in out          # senhas completas
    assert 'Login / E-mail' in out

def test_build_company_html_omits_empty_sections():
    rows = [{'usuario': 'x', 'senha': 's', 'url': 'u', 'status': 'bloqueado', 'data': ''}]
    out = build_company_html('Acme', rows, {'gerado_em': 'y'})
    assert 'Bloqueadas' in out
    assert 'Vulneráveis' not in out and 'Pendentes' not in out

def test_render_company_pdfs_one_per_company(monkeypatch, tmp_path):
    written = []
    monkeypatch.setattr(spider_report, 'render_pdf', lambda html, out: written.append(out))
    grupos = {
        'Acme': [{'usuario': 'a', 'senha': 's', 'url': 'u', 'status': 'vulneravel', 'data': ''}],
        'Acme2Go': [{'usuario': 'b', 'senha': 't', 'url': 'v', 'status': 'bloqueado', 'data': ''}],
    }
    paths = render_company_pdfs(grupos, {'gerado_em': 'y'}, out_dir=str(tmp_path), ts='20260611_100000')
    assert len(paths) == 2
    assert any('Relatorio_acme_20260611_100000.pdf' in p for p in paths)
    assert any('Relatorio_acme2go_20260611_100000.pdf' in p for p in paths)
    assert written == paths

def test_render_company_pdfs_skips_empty(monkeypatch, tmp_path):
    monkeypatch.setattr(spider_report, 'render_pdf', lambda html, out: None)
    paths = render_company_pdfs({}, {'gerado_em': 'y'}, out_dir=str(tmp_path), ts='t')
    assert paths == []
```

- [ ] **Step 2: Rodar e ver que FALHAM**

Run: `cd /home/trick/Spider && python3 -m pytest test_spider_report.py -q -k 'slug or group_by_company or company_html or company_pdfs'`
Expected: FAIL com `ImportError`/`AttributeError` (funções ainda não existem).

- [ ] **Step 3: Adicionar `import unicodedata`**

Em `spider_report.py`, junto aos imports do topo (perto de `import re`), adicione:

```python
import unicodedata
```

- [ ] **Step 4: Adicionar as novas funções**

Em `spider_report.py`, logo **depois** da definição de `_badge(status)` (e antes de `build_html`), adicione:

```python
def _slug(label):
    """Slug de empresa p/ nome de arquivo: minúsculas, sem acento, [^a-z0-9]→_."""
    norm = unicodedata.normalize('NFKD', label or '').encode('ascii', 'ignore').decode('ascii')
    norm = re.sub(r'[^a-zA-Z0-9]+', '_', norm).strip('_').lower()
    return norm or 'outros'


ACTIONABLE_STATUS = ('vulneravel', 'vulneravel_mfa', 'bloqueado', 'verificar')

# (título da seção, statuses que entram nela) — ordem de exibição no PDF da empresa
REPORT_SECTIONS = [
    ('Vulneráveis', ('vulneravel', 'vulneravel_mfa')),
    ('Bloqueadas — validação manual', ('bloqueado',)),
    ('Pendentes', ('verificar',)),
]


def group_by_company(validated):
    """Agrupa as credenciais ACIONÁVEIS (vuln/bloqueado/verificar) por empresa."""
    grupos = {}
    for r in validated:
        if r.get('status') in ACTIONABLE_STATUS:
            grupos.setdefault(r.get('empresa') or 'Outros', []).append(r)
    return grupos


def build_company_html(empresa, rows, meta):
    """HTML de um PDF de uma empresa: seções Vulneráveis / Bloqueadas / Pendentes."""
    p = ['<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><style>',
         _CSS, '</style></head><body>']
    p.append('<div class="hdr"><h1>Credenciais para Reset — %s</h1>'
             '<div class="m">Gerado em: %s &middot; Credenciais: %d</div></div>'
             % (_esc(empresa), _esc(meta.get('gerado_em')), len(rows)))
    p.append('<div class="bd">')
    for titulo, statuses in REPORT_SECTIONS:
        sec = [r for r in rows if r.get('status') in statuses]
        if not sec:
            continue
        p.append('<h2>%s (%d)</h2>' % (_esc(titulo), len(sec)))
        p.append('<table><thead><tr><th>Login / E-mail</th><th>Senha</th><th>URL</th>'
                 '<th>Status</th><th>Data</th></tr></thead><tbody>')
        for r in sec:
            p.append('<tr><td class="usr">%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
                     % (_esc(r.get('usuario')), _esc(r.get('senha')), _esc(r.get('url')),
                        _badge(r.get('status')), _esc(r.get('data'))))
        p.append('</tbody></table>')
    p.append('<div class="ft">Uso autorizado sob RoE &middot; confidencial &middot; '
             'contém senhas em texto claro</div>')
    p.append('</div></body></html>')
    return ''.join(p)


def render_company_pdfs(grupos, meta, out_dir='.', ts=None):
    """Gera um PDF por empresa (só as com credenciais acionáveis). Devolve a lista de caminhos."""
    ts = ts or datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for empresa in sorted(grupos):
        rows = grupos[empresa]
        if not rows:
            continue
        out_path = os.path.join(out_dir, 'Relatorio_%s_%s.pdf' % (_slug(empresa), ts))
        render_pdf(build_company_html(empresa, rows, meta), out_path)
        paths.append(out_path)
    return paths
```

- [ ] **Step 5: Rodar e ver que PASSAM**

Run: `cd /home/trick/Spider && python3 -m pytest test_spider_report.py -q -k 'slug or group_by_company or company_html or company_pdfs'`
Expected: PASS (6 testes).

- [ ] **Step 6: Compilar**

Run: `cd /home/trick/Spider && python3 -m py_compile spider_report.py`
Expected: sem saída.

- [ ] **Step 7: Commit**

```bash
cd /home/trick/Spider
git add spider_report.py test_spider_report.py
git commit -m "feat(spider): relatório por empresa (vulneráveis/bloqueadas/pendentes) com senha completa"
```

---

## Task 4: `spider_report.py` — reescrever `main` (sem navegador; PDF por empresa; bloqueado→SOLVED pós-extração)

**Files:**
- Modify: `spider_report.py` (`main`, remover `select_engine`/`build_html`/`group_vulnerable`/`_default_out`/constantes mortas)
- Test: `test_spider_report.py` (remover testes obsoletos, adaptar testes de `main`/push)

### Limpeza de testes obsoletos (TDD: derrubar o que não vale mais)

- [ ] **Step 1: Remover testes obsoletos de `test_spider_report.py`**

Apague por completo estas funções de teste:

```
test_group_vulnerable_only_vulnerable_by_company
test_build_html_groups_and_shows_password
test_build_html_escapes_html
test_build_html_zero_vulnerable
test_status_label_has_sem_login
test_build_html_has_evidence_column
test_status_label_has_bloqueado
test_build_html_shows_bucket_summary
test_default_out_uses_csv_basename
test_build_html_executive_and_appendix
test_stale_offline_not_in_appendix
test_build_html_big4_debranded
test_build_html_username_nowrap
test_default_out_debranded
test_select_engine_auto_prefers_nodriver
test_select_engine_auto_falls_back_to_playwright
test_select_engine_explicit_missing_raises
test_select_engine_none_available_raises
```

Também remova os imports agora órfãos no topo dos blocos correspondentes:
`from spider_report import build_html`, `from spider_report import select_engine`,
e o `from spider_report import validate_all, group_vulnerable` → troque por
`from spider_report import validate_all` (mantém `validate_all`; remove `group_vulnerable`).

- [ ] **Step 2: Substituir o helper `_mk` e os testes de push pela versão nova**

Em `test_spider_report.py`, substitua `_mk` e os testes de push/dry-run/offline pelas versões abaixo (URLs com domínio para a empresa sair do host; `--out` → `--out-dir`; bloqueado agora vira SOLVED):

```python
def _mk(monkeypatch, tmp_path, fetched, verdict_by_url):
    monkeypatch.setattr(spider_report.axur_client, 'fetch_credentials',
                        lambda since, limit=None: [dict(x) for x in fetched])
    monkeypatch.setattr(spider_report.differential, 'validate_batch',
                        lambda c, **k: [dict(x, status=verdict_by_url[x['url']], evidencia='e') for x in c])
    monkeypatch.setattr(spider_report, 'render_pdf', lambda html, out: open(out, 'w').close())
    monkeypatch.setattr(spider_report, 'STATE_PATH', str(tmp_path / 's.json'))
    calls = {}
    monkeypatch.setattr(spider_report.axur_client, 'set_status',
                        lambda ids, value, **k: calls.setdefault(value, []).extend(ids) or len(ids))
    monkeypatch.setattr(spider_report.axur_client, 'add_tag',
                        lambda ids, tag, **k: calls.setdefault('tag:' + tag, []).extend(ids) or len(ids))
    return calls

def test_push_status_workflow(monkeypatch, tmp_path):
    fetched = [
        {'usuario': 'v', 'senha': 'p', 'url': 'https://vuln.acme.com', 'data': '', 'axur_id': 'IDV'},
        {'usuario': 's', 'senha': 'p', 'url': 'https://safe.acme.com', 'data': '', 'axur_id': 'IDS'},
        {'usuario': 'b', 'senha': 'p', 'url': 'https://blk.acme.com',  'data': '', 'axur_id': 'IDB'},
        {'usuario': 'v', 'senha': 'p2', 'url': 'https://vuln.acme.com', 'data': '', 'axur_id': 'IDDUP'},
    ]
    calls = _mk(monkeypatch, tmp_path, fetched,
                {'https://vuln.acme.com': 'vulneravel_mfa', 'https://safe.acme.com': 'seguro',
                 'https://blk.acme.com': 'bloqueado'})
    spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes', '--push',
                        '--out-dir', str(tmp_path)])
    assert calls.get('DISCARDED') == ['IDDUP']
    assert calls.get('IN_TREATMENT') == ['IDV']
    assert sorted(calls.get('SOLVED')) == ['IDB', 'IDS']      # bloqueada vira SOLVED após extração
    assert calls.get('tag:vulneravel_mfa') == ['IDV']
    assert calls.get('tag:seguro') == ['IDS']
    assert calls.get('tag:bloqueado') == ['IDB']

def test_blocked_not_solved_when_pdf_fails(monkeypatch, tmp_path):
    fetched = [{'usuario': 'b', 'senha': 'p', 'url': 'https://blk.acme.com', 'data': '', 'axur_id': 'IDB'}]
    calls = _mk(monkeypatch, tmp_path, fetched, {'https://blk.acme.com': 'bloqueado'})
    def boom(html, out):
        raise RuntimeError('wkhtmltopdf indisponível')
    monkeypatch.setattr(spider_report, 'render_pdf', boom)
    rc = spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes', '--push',
                             '--out-dir', str(tmp_path)])
    assert 'IDB' not in calls.get('SOLVED', [])               # não fecha sem extrair
    assert calls.get('tag:bloqueado') == ['IDB']              # mas continua taggeada
    assert rc == 4

def test_verificar_stays_new(monkeypatch, tmp_path):
    fetched = [{'usuario': 'q', 'senha': 'p', 'url': 'https://amb.acme.com', 'data': '', 'axur_id': 'IDQ'}]
    calls = _mk(monkeypatch, tmp_path, fetched, {'https://amb.acme.com': 'verificar'})
    spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes', '--push',
                        '--out-dir', str(tmp_path)])
    assert 'IDQ' not in (calls.get('SOLVED', []) + calls.get('IN_TREATMENT', []) + calls.get('DISCARDED', []))
    assert calls.get('tag:verificar') == ['IDQ']

def test_push_dedup_in_treatment_once(monkeypatch, tmp_path):
    fetched = [{'usuario': 'v', 'senha': 'p', 'url': 'https://vuln.acme.com', 'data': '', 'axur_id': 'IDV'}]
    calls = _mk(monkeypatch, tmp_path, fetched, {'https://vuln.acme.com': 'vulneravel'})
    spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes', '--push', '--out-dir', str(tmp_path)])
    assert calls.get('IN_TREATMENT') == ['IDV'] and calls.get('tag:vulneravel') == ['IDV']

def test_dry_run_writes_nothing(monkeypatch, tmp_path):
    fetched = [{'usuario': 'v', 'senha': 'p', 'url': 'https://vuln.acme.com', 'data': '', 'axur_id': 'IDV'}]
    calls = _mk(monkeypatch, tmp_path, fetched, {'https://vuln.acme.com': 'vulneravel'})
    spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes', '--out-dir', str(tmp_path)])
    assert calls == {}

def test_offline_persistent_discarded(monkeypatch, tmp_path):
    import json as _json
    from state import cache_key
    fetched = [{'usuario': 'o', 'senha': 'p', 'url': 'https://down.acme.com', 'data': '', 'axur_id': 'IDO'}]
    calls = _mk(monkeypatch, tmp_path, fetched, {'https://down.acme.com': 'offline'})
    _json.dump({cache_key({'usuario': 'o', 'url': 'https://down.acme.com', 'senha': 'p'}):
                {'status': 'offline', 'offline_count': 2}}, open(str(tmp_path / 's.json'), 'w'))
    spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes', '--push', '--out-dir', str(tmp_path)])
    assert calls.get('DISCARDED') == ['IDO']

def test_offline_not_yet_discarded(monkeypatch, tmp_path):
    fetched = [{'usuario': 'o', 'senha': 'p', 'url': 'https://down.acme.com', 'data': '', 'axur_id': 'IDO'}]
    calls = _mk(monkeypatch, tmp_path, fetched, {'https://down.acme.com': 'offline'})
    spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes', '--push', '--out-dir', str(tmp_path)])
    assert 'IDO' not in (calls.get('DISCARDED', []) + calls.get('IN_TREATMENT', []) + calls.get('SOLVED', []))
```

- [ ] **Step 3: Adaptar `test_main_axur_source_ingests` para `--out-dir`**

Substitua a função existente por:

```python
def test_main_axur_source_ingests(monkeypatch, tmp_path):
    fetched = [{'usuario': 'a', 'senha': 'p', 'url': 'https://x.globex.com.br', 'data': '', 'axur_id': 'ID1'}]
    monkeypatch.setattr(spider_report.axur_client, 'fetch_credentials',
                        lambda since, limit=None: list(fetched))
    monkeypatch.setattr(spider_report.differential, 'validate_batch',
                        lambda creds, **k: [dict(c, status='seguro', evidencia='') for c in creds])
    monkeypatch.setattr(spider_report, 'render_pdf', lambda html, out: open(out, 'w').close())
    monkeypatch.setattr(spider_report, 'STATE_PATH', str(tmp_path / 's.json'))
    rc = spider_report.main(['--source', 'axur', '--since', '2026-05-01', '--yes',
                             '--out-dir', str(tmp_path)])
    assert rc == 0
```

- [ ] **Step 4: Rodar a suíte e ver as FALHAS de `main` (esperado)**

Run: `cd /home/trick/Spider && python3 -m pytest test_spider_report.py -q`
Expected: FAIL — `main` ainda usa `--out`/`--browser`/single-PDF e ainda não fecha bloqueado como SOLVED (ex.: `test_push_status_workflow`, `test_blocked_not_solved_when_pdf_fails`). Não deve haver erro de import (os testes obsoletos já saíram no Step 1).

### Implementação no `spider_report.py`

- [ ] **Step 5: Remover `select_engine`**

Apague a função `select_engine(name, nodriver_ok, playwright_ok)` inteira (topo do arquivo).

- [ ] **Step 6: Remover funções e constantes mortas do relatório antigo**

Apague por completo: `build_html`, `group_vulnerable`, `_default_out`, e as constantes
`VULN_STATUS`, `STATUS_LABEL`, `BUCKET_LABEL`. (Mantenha `_CSS`, `_esc`, `_BADGE`, `_badge`,
`render_pdf`, `validate_all`, e as funções novas da Task 3.)

- [ ] **Step 7: Substituir os argumentos de CLI de browser por `--out-dir`**

No `argparse` de `main`, **remova** os argumentos `--out`, `--browser`, `--engine`, `--assist`,
`--headful` e **adicione**:

```python
    ap.add_argument('--out-dir', default='.', help='diretório de saída dos PDFs por empresa')
```

(Mantenha `planilha`, `--source`, `--since`, `--limit`, `--push`, `--timeout`, `--delay`,
`--yes`, `--recheck`.)

- [ ] **Step 8: Remover o bloco de navegador e simplificar a chamada de validação**

Em `main`, **substitua todo o intervalo** que começa na linha
`use_browser = args.browser or args.assist or args.headful` e vai **até o fim do loop**
`for item in validated: _log_evidence(item)` (inclusive — isto é, todo o bloco de TTY/`_imp`/
`select_engine`/profile/`browser_*`, o `try/finally` da validação, o `state.update_state`/
`save_state`, o `validated = cached + tested` e o loop de `_log_evidence`) pelo código abaixo.
A definição `def progress(...)` fica **acima** desse intervalo e deve ser preservada:

```python
    rewrites = load_url_rewrites()
    rewrite_fn = (lambda u: rewrite_entry_url(u, rewrites)) if rewrites else None
    if rewrites:
        sys.stderr.write('[*] reescrita de URL de entrada: %d regra(s)\n' % len(rewrites))
    tested = differential.validate_batch(
        to_test, timeout=args.timeout, delay=args.delay, progress=progress, rewrite_fn=rewrite_fn)
    if to_test:
        sys.stderr.write('\n')
    state.update_state(state_obj, tested)
    state.save_state(STATE_PATH, state_obj)
    validated = cached + tested

    for item in validated:
        _log_evidence(item)
```

- [ ] **Step 9: Reescrever o trecho de relatório + push (da geração de `novas` até o `return`)**

Substitua todo o restante de `main` (a partir de `novas = state.unreported_vulnerable(...)`
até o `return 0`) por:

```python
    novas = state.unreported_vulnerable(state_obj, validated)

    # ── relatório: um PDF por empresa (vulneráveis + bloqueadas + pendentes) ──
    grupos = group_by_company(validated)
    meta = {'gerado_em': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'validado': len(validated)}
    pdf_paths, pdf_ok = [], False
    try:
        pdf_paths = render_company_pdfs(grupos, meta, out_dir=args.out_dir)
        pdf_ok = True
    except RuntimeError as e:
        sys.stderr.write('[x] Falha ao gerar PDF(s): %s\n' % e)

    # ── classificação de status na Axur ──
    AXUR_SOLVED = ('seguro', 'sem_login')
    vuln_ids = [r['axur_id'] for r in validated if r['status'] in state.VULN_STATUSES and r.get('axur_id')]
    solved_ids = [r['axur_id'] for r in validated if r['status'] in AXUR_SOLVED and r.get('axur_id')]
    blocked_ids = [r['axur_id'] for r in validated if r['status'] == 'bloqueado' and r.get('axur_id')]
    stale_offline_ids = [r['axur_id'] for r in validated
                         if r['status'] == 'offline' and r.get('axur_id')
                         and (state_obj.get(state.cache_key(r)) or {}).get('offline_count', 0) >= state.OFFLINE_DISCARD_AFTER]
    discard_ids = dup_ids + stale_offline_ids

    if not args.push:
        if args.source == 'axur':
            n_tags = sum(1 for r in validated if r.get('axur_id'))
            sys.stderr.write('[dry-run] faria na Axur: IN_TREATMENT=%d · SOLVED(seguro/sem_login)=%d · '
                             'SOLVED(bloqueado, pós-extração)=%d · DISCARDED=%d · tags(por status)=%d\n'
                             % (len(vuln_ids), len(solved_ids), len(blocked_ids), len(discard_ids), n_tags))
    else:
        def _safe(fn, label):
            try:
                n = fn()
                sys.stderr.write('[+] Axur %s: %d\n' % (label, n))
                return True
            except RuntimeError as e:
                sys.stderr.write('[x] Axur %s falhou: %s\n' % (label, e))
                return False
        if args.source == 'csv':
            sys.stderr.write('[!] Fonte CSV: sem axur_id — nada a mudar na Axur.\n')
        if discard_ids:
            _safe(lambda: axur_client.set_status(discard_ids, 'DISCARDED'),
                  'DISCARDED (duplicadas + offline persistente)')
        if solved_ids:
            _safe(lambda: axur_client.set_status(solved_ids, 'SOLVED'), 'SOLVED (confirmadas seguras)')
        if vuln_ids:
            ok = _safe(lambda: axur_client.set_status(vuln_ids, 'IN_TREATMENT'), 'IN_TREATMENT (vulneráveis)')
            if ok:
                state.mark_reported(state_obj, novas, datetime.datetime.now().isoformat(timespec='seconds'))
                state.save_state(STATE_PATH, state_obj)
        # bloqueadas: só fecham (SOLVED) APÓS extraídas para o PDF
        if blocked_ids:
            if pdf_ok:
                _safe(lambda: axur_client.set_status(blocked_ids, 'SOLVED'),
                      'SOLVED (bloqueadas extraídas p/ PDF)')
            else:
                sys.stderr.write('[!] PDF não gerado — %d bloqueada(s) mantidas (não fechadas).\n'
                                 % len(blocked_ids))
        # tags = o status do veredito (por grupo de status); garante a tag `bloqueado`
        by_status = {}
        for r in validated:
            if r.get('axur_id'):
                by_status.setdefault(r['status'], []).append(r['axur_id'])
        for st in sorted(by_status):
            ids_st = by_status[st]
            _safe(lambda ids=ids_st, s=st: axur_client.add_tag(ids, s), 'tag %s' % st)

    n_cred = sum(len(v) for v in grupos.values())
    buckets = dict(Counter(r['status'] for r in validated))
    if pdf_ok:
        sys.stderr.write('[+] %d PDF(s) por empresa (%d credenciais acionáveis em %d empresa(s))\n'
                         % (len(pdf_paths), n_cred, len(grupos)))
    sys.stderr.write('[*] Resumo: ' + ' · '.join('%s=%d' % (k, v) for k, v in sorted(buckets.items())) + '\n')
    for pth in pdf_paths:
        print(pth)
    return 0 if pdf_ok else 4
```

- [ ] **Step 10: Rodar a suíte completa do report e ver que PASSA**

Run: `cd /home/trick/Spider && python3 -m pytest test_spider_report.py -q`
Expected: PASS. Se algum teste antigo remanescente referenciar `--out`/`select_engine`/`build_html`,
ele escapou do Step 1 — remova-o.

- [ ] **Step 11: Compilar**

Run: `cd /home/trick/Spider && python3 -m py_compile spider_report.py`
Expected: sem saída.

- [ ] **Step 12: Commit**

```bash
cd /home/trick/Spider
git add spider_report.py test_spider_report.py
git commit -m "feat(spider): main sem navegador, PDF por empresa, bloqueado→SOLVED após extração na Axur"
```

---

## Task 5: Atualizar `deploy/run_daily.sh` e `README.md`

**Files:**
- Modify: `deploy/run_daily.sh`
- Modify: `README.md`

- [ ] **Step 1: Reescrever `deploy/run_daily.sh` (sem `--browser`/WSLg)**

Substitua o conteúdo de `deploy/run_daily.sh` por:

```bash
#!/usr/bin/env bash
# Spider — run diário (Axur → validar → PDF por empresa → status). Para cron/systemd.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p "$HOME/spider_logs"
LOG="$HOME/spider_logs/spider_$(date +%F).log"
PY="python3"
[ -x "$(dirname "$0")/../.venv/bin/python" ] && PY="$(dirname "$0")/../.venv/bin/python"
echo "=== $(date -Is) iniciando (py=$PY) ===" >>"$LOG"
"$PY" spider_report.py --source axur --push --yes "$@" >>"$LOG" 2>&1
rc=$?
echo "=== $(date -Is) fim (rc=$rc) ===" >>"$LOG"
exit $rc
```

- [ ] **Step 2: Validar a sintaxe do script**

Run: `cd /home/trick/Spider && bash -n deploy/run_daily.sh && echo OK`
Expected: `OK`.

- [ ] **Step 3: Atualizar o `README.md`**

Primeiro leia o arquivo (`Read README.md`) para localizar os trechos. Faça estas edições
(remoções e ajustes), preservando o resto:

1. **Instalação:** remova os passos de browser — as linhas que instalam `playwright`/`chromium`
   (passos "3", "3b", `python3 -m playwright install ...`) e a menção a `nodriver`.
   Em `pip install requests beautifulsoup4 pytest playwright` → remova `playwright`.
2. **Uso/flags:** remova as descrições de `--browser`, `--engine`, `--headful`, `--assist`
   e o trecho "Pré-requisitos do `--browser`". Troque qualquer `--out <arquivo>` por
   `--out-dir <dir>` (PDF por empresa). Remova o exemplo `... testecred.csv --browser`.
3. **Roteamento (passo "3"):** substitua a descrição "sem `--browser`: ... `dynamic`/`blocked`
   ficam como não-testáveis. Com `--browser`: ..." por: "rota 100% HTTP — `static_form` é
   validado por POST; `dynamic` (SPA/JS) e `blocked` (WAF/Cloudflare) viram **`bloqueado`**
   (validação manual via PDF por empresa)."
4. **Tabela de status:** na linha de `bloqueado`, troque a evidência que cita `--assist` por
   "WAF/Cloudflare ou login dinâmico — **não testável** automaticamente → validação manual".
   Na tabela veredito→status da Axur, mude a linha de `bloqueado`: de "fica `NEW`" para
   "**`SOLVED`** (após extração para o PDF) + tag `bloqueado`". Mantenha `verificar`/`offline`
   como "fica `NEW`".
5. **Seção "Cloudflare/WAF — bloqueadas":** reescreva para refletir que não há mais navegador/
   `--assist`; as bloqueadas saem no **PDF por empresa** para reset manual pelo time e são
   fechadas como `SOLVED` na Axur após a extração.
6. **Wrapper diário / arquivos:** atualize a menção ao comando do `run_daily.sh`
   (`spider_report.py --source axur --push --yes`) e **remova** as linhas que descrevem
   `browser_nodriver.py` e `browser.py` na lista de arquivos, além da nota de WSLg/`DISPLAY`.

- [ ] **Step 4: Conferir que sobrou nenhuma referência a navegador no README**

Run: `cd /home/trick/Spider && grep -n -iE 'browser|nodriver|playwright|--assist|--headful|--engine' README.md || echo 'LIMPO'`
Expected: `LIMPO` (ou só ocorrências históricas que você decidiu manter conscientemente — idealmente nenhuma).

- [ ] **Step 5: Commit**

```bash
cd /home/trick/Spider
git add deploy/run_daily.sh README.md
git commit -m "docs(spider): README + run_daily sem navegador; bloqueado→SOLVED/PDF por empresa"
```

---

## Task 6: Validação final

**Files:** nenhum (verificação).

- [ ] **Step 1: Suíte de testes completa**

Run: `cd /home/trick/Spider && python3 -m pytest -q`
Expected: PASS (sem falhas, sem erros de coleta/import). Nenhum teste referenciando
`select_engine`/`browser`/`assisted`/`build_html`.

- [ ] **Step 2: Compilar todos os módulos**

Run: `cd /home/trick/Spider && python3 -m py_compile spider_report.py differential.py spider_validator.py pagetype.py state.py axur_client.py`
Expected: sem saída.

- [ ] **Step 3: Sintaxe dos scripts de deploy**

Run: `cd /home/trick/Spider && bash -n deploy/run_daily.sh && echo OK`
Expected: `OK`.

- [ ] **Step 4: Smoke do dry-run da CLI (sem rede, sem token)**

Run: `cd /home/trick/Spider && printf '%s\n' 'Usuário,Senha,Data de detecção,URL de acesso da credencial' 'a,b,01/01/2026 10:00:00,https://exemplo.invalid/login' > /tmp/smoke.csv && python3 spider_report.py /tmp/smoke.csv --yes --out-dir /tmp/spider_smoke --timeout 2 --delay 0; echo "rc=$?"`
Expected: roda sem stacktrace; imprime resumo no stderr. (O host `exemplo.invalid` é offline → `offline`, sem credencial acionável → 0 PDFs, `rc=0`.) Limpe depois: `rm -rf /tmp/spider_smoke /tmp/smoke.csv`.

- [ ] **Step 5: Confirmar que nenhum artefato sensível entrou no git**

Run: `cd /home/trick/Spider && git status --porcelain && git ls-files | grep -E '\.pdf$|companies\.conf$|\.csv$|spider_state\.json$' || echo 'sem artefatos sensíveis trackeados'`
Expected: árvore limpa (tudo commitado) e `sem artefatos sensíveis trackeados`.

---

## Notas de revisão (self-review do plano)

- **Cobertura do spec:** remoção de navegador (Tasks 1,2,4) · `bloqueado` = não-verificável incl.
  dinâmico (Task 2) · PDF por empresa com login/senha/url (Task 3) · empresa pelo domínio
  (`group_by_company` usa `r['empresa']`, que `main` deriva via `classify_company`→`_company_from_host`)
  · Axur bloqueado→tag+SOLVED-pós-extração, verificar→NEW (Task 4) · README/run_daily (Task 5).
- **Empresa pelo domínio:** `main` já popula `empresa` via `classify_company(url)` no ingest
  (modo axur) e `parse_credentials` (modo csv); sem `companies.conf`, cai em `_company_from_host`
  (domínio). Nenhum nome de cliente entra no código.
- **`validate_all`** permanece (função/legado com teste próprio); não é usada por `main` e não
  depende de nada removido.
- **Ordem "PDF antes de SOLVED":** `render_company_pdfs` roda antes do bloco de push; `pdf_ok`
  gateia o `SOLVED` das bloqueadas. Falha de render → `rc=4` e bloqueadas intocadas.
