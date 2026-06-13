# Frente 5 — Hardening (Design)

> Higienizado: nenhum dado de CDE/cliente/alvo. Estado snapshot — verificar contra o git.

**Origem:** item "Frente 5 — hardening" do roadmap de maturidade (memória `project-stiglitz-melhorias`).
Quatro reforços independentes de robustez/segurança, agrupados numa spec só (decisão do operador).

**Disciplina de entrega:** TDD (teste→RED→GREEN), commits pequenos com `bash -n`+`shellcheck`
limpos nos `.sh`, suíte `pytest tests/` verde. Subagent-driven-development, uma task por unidade.

---

## Objetivos

1. Eliminar mascaramento de erros inesperados (bare `except:`) sem perder a degradação intencional.
2. Tornar o `audit.log` (RED) **inforjável sem a chave** — autenticidade além da integridade.
3. Aplicar o escopo (`in_scope`) de forma **consistente** nas fases ofensivas do RED, e tornar
   visível/auditável o caso sem escopo.
4. Impedir que o checkpoint marque uma fase como concluída quando ela **não produziu saída**.

## Não-objetivos (YAGNI)

- Não trocar o esquema do hash-chain existente do `audit.log` (só acrescenta um selo).
- Não implementar fail-closed/bloqueio de fases sem escopo (decisão: fail-open + warn; escalar
  para fail-closed fica como follow-up se desejado).
- Não introduzir infra de chave assimétrica (GPG/PEM) — selo é HMAC simétrico.
- Não refatorar `parsers.py`/`js_analysis.py`/etc. além de estreitar os `except`.

---

## Unidade A — `bare except:` → tipos específicos

**Arquivos:** `lib/parsers.py` (9: linhas 154,164,204,222,234,256,283,300,321),
`lib/js_analysis.py` (2: 181,211), `lib/cve_enrich.py` (2: 36,78), `lib/security_headers.py`
(1: 152). Total: 14 sites em 4 arquivos (reconfirmar na implementação com
`grep -rEn "except\s*:" lib/`, pois números de linha deslocam).

**O quê:** cada `except:` vira `except (Tipo, ...)` com os tipos que o bloco realmente pode lançar
(`json.JSONDecodeError`, `ValueError`, `KeyError`, `TypeError`, `AttributeError`, `OSError`,
`IndexError`, `UnicodeDecodeError` — conforme o `try` correspondente). O comportamento observável
**não muda** para o erro esperado (continua degradando: `pass`/fallback/`continue`). O ganho:
`KeyboardInterrupt`/`SystemExit` e erros de programação deixam de ser engolidos.

**Interface:** nenhuma mudança de API. Cada site é uma edição local.

**Erros:** se um site capturava genericamente por razão legítima (ex.: parser tolerante a entrada
arbitrária de terceiros), manter amplo MAS trocar `except:` por `except Exception:` (não captura
`BaseException`) + comentário do porquê.

**Teste:** a suíte atual (`pytest tests/`) deve permanecer verde. Onde o estreitamento muda o
conjunto capturado, adicionar/garantir um caso que confirma que a entrada malformada esperada
ainda degrada (não levanta). `python3 -m py_compile` em cada arquivo tocado.

---

## Unidade B — Selo HMAC no `audit.log`

**Arquivos:** `stiglitz_red.sh` (funções `audit*` ~linhas 66-91, finalize/`trap EXIT`),
`tests/verify_audit.py`, `tests/test_lib.py` (helpers de audit).

**Contexto:** o `audit.log` já é hash-chain (`seq | ts | event | prev:hash`); `verify_audit.py`
valida que cada entrada encadeia na anterior. O chain é **prev-dependente** (a cabeça liga
transitivamente toda a cadeia), mas é forjável: quem tem o arquivo recomputa todos os hashes.

**O quê:**
- Nova função `audit_seal()` invocada no finalize (no mesmo `trap EXIT` que já encerra o run).
  Lê a chave de `STIGLITZ_AUDIT_KEY` (env). Computa `HMAC-SHA256(chave, <hash-cabeça do chain>)`
  via `openssl dgst -sha256 -hmac` (ou `python3 -c`/`hmac` como fallback se `openssl` ausente).
  Grava `audit.log.seal` (uma linha: `HMAC-SHA256 <hex> head=<hash-cabeça>`), `chmod 600`.
- Sem `STIGLITZ_AUDIT_KEY` → **não sela**; emite `warn`/`audit "SEAL_SKIPPED reason=no_key"` e
  segue (degrada para o comportamento atual; backward-compatible).
- `verify_audit.py`: novo modo `--seal <audit.log.seal> --key <chave>` (ou env) que (1) valida o
  chain como hoje, (2) recomputa a cabeça, (3) recomputa o HMAC e compara com o selo. Falha se o
  selo não bate (re-encadeamento pós-fato detectado) ou se a cabeça divergir.

**Interface:** `audit_seal()` é interna ao `stiglitz_red.sh`. O contrato externo é o par
(`audit.log`, `audit.log.seal`) + a chave fornecida out-of-band.

**Erros:** `openssl`/`python3` ausentes → `warn` e não sela (não aborta o run). Chave vazia →
trata como ausente. O selo nunca contém a chave (só o HMAC e a cabeça).

**Segurança/limites:** ameaça coberta = adulteração pós-fato por quem tem acesso ao arquivo mas
NÃO à chave. Não cobre quem tem a chave (mesma máquina/env durante o run). Documentar essa
fronteira no header do `verify_audit.py` e no CLAUDE.md.

**Teste (TDD):** unit do cálculo do selo (entrada conhecida → HMAC conhecido); `verify_audit.py`
aceita selo válido e **rejeita** selo de log adulterado (mudar uma entrada → cabeça muda → selo
não bate); ausência de chave → selo pulado sem erro.

---

## Unidade C — Escopo consistente nas fases ofensivas (Opção A)

**Arquivos:** `stiglitz_red.sh` (helper `in_scope`/uso em brute, e seleção de alvos de sqli/xss),
`lib/brute.sh`.

**Contexto:** `in_scope(url)` existe inline no scoring do ingest (fail-open quando
`SCOPE_DOMAINS` vazio). Não é re-aplicado aos alvos consumidos por brute (`open_services.txt`,
`base_url` do HTTP-form), sqli e xss.

**O quê (Opção A):**
- Extrair `in_scope` para um helper reutilizável (bash `in_scope_host`/filtro, ou um pequeno
  `lib/scope.py` puro + CLI consumido pelas fases). Preferir um único ponto de verdade.
- Quando `SCOPE_DOMAINS`/`SCOPE_FILE` **definido**: filtrar in_scope os alvos de **brute, sqli,
  xss** antes de executar (descarta out-of-scope; `audit "SCOPE_FILTERED phase=<x> dropped=<n>"`).
- Quando **não há escopo**: manter fail-open, mas emitir `warn` alto + `audit "SCOPE_NONE
  phase=brute"` (e nas demais ofensivas) ANTES de executar. Não-bloqueante.

**Interface:** helper de escopo com contrato claro: `in_scope(url, scope_domains) -> bool`
(igualdade de host ou subdomínio do escopo; fail-open só com `scope_domains` vazio). Reusado por
todas as fases ofensivas.

**Erros:** URL malformada → `in_scope` retorna `False` (não in-scope) quando há escopo; helper
nunca levanta.

**Teste:** unit do helper (`in_scope`): host igual/subdomínio/out-of-scope/sem-escopo(fail-open)/
URL malformada; teste de que brute/sqli/xss aplicam o filtro quando escopo definido (no nível do
helper/seleção de alvos — bash difícil de unitar, focar no filtro Python testável); `shellcheck`
limpo.

---

## Unidade D — Validação de saída pós-fase no checkpoint

**Arquivos:** `stiglitz.sh` (`phase_done`/checkpoint ~linha 460 e os call-sites das fases).

**Contexto:** `phase_done "FASE_N"` (e `checkpoint_done` no RED) marca conclusão sem verificar
que a fase produziu artefato. No resume, `checkpoint_skip`/`phase_done` pula a fase mesmo que ela
tenha falhado e gerado nada.

**O quê:**
- Helper `phase_output_ok <nome_fase> <artefato...>`: retorna sucesso se TODOS os artefatos
  esperados existem e são não-vazios (`-s`).
- Nos call-sites, antes de `phase_done`: se `phase_output_ok` falhar → `warn "FASE_N: saída
  ausente/vazia — não marcando como concluída (resume re-executará)"` e **não** chama `phase_done`.
- Mapa fase→artefato esperado (ex.: FASE_1 → arquivo de subdomínios; FASE_4 → nuclei JSONL;
  FASE_9 → dump ZAP). Fases sem artefato obrigatório (ex.: as que podem legitimamente não achar
  nada) ficam de fora do mapa ou usam um artefato-sentinela de "fase rodou".

**Interface:** `phase_output_ok` puro (só lê o filesystem, sem efeito colateral além do retorno).

**Erros:** não-bloqueante por design — uma fase sem saída não aborta o scan, só não é marcada
concluída (será re-tentada no resume). Distinguir "rodou e não achou nada" (legítimo) de "falhou
sem produzir" exige escolher artefatos que sempre existem quando a fase roda OK (ex.: um log da
fase, não só os findings).

**Teste:** unit do `phase_output_ok` (todos presentes+não-vazios→ok; um ausente→falha; um
vazio→falha). Caracterização: marcar como done só quando o artefato existe; `bash -n`/`shellcheck`.

---

## Entrega

Uma spec (este doc) → um plano multi-task (`docs/superpowers/plans/2026-06-11-hardening.md`)
com 4 unidades independentes (A/B/C/D), cada uma uma task TDD. Ordem sugerida: A (mecânico,
desbloqueia confiança na suíte) → D (helper isolado) → C (helper de escopo) → B (selo, mais
design). Execução via subagent-driven-development. Docs ao fim: CLAUDE.md (seção Validação +
audit seal) e ROADMAP (marca Frente 5).

## Higiene de dados

Nenhum alvo/cliente/token nos commits ou na spec. `audit.log.seal` nunca contém a chave.
Varrer antes do push (política `feedback-no-client-names-repos`).
