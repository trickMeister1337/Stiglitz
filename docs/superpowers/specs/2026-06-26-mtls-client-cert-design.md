# Spec — mTLS client-cert no `stiglitz.sh`

**Data:** 2026-06-26
**Escopo:** `stiglitz.sh` (osint.sh/stiglitz_red.sh reaproveitam depois, padrão `netproxy`)
**Status:** design aprovado, aguardando plano de implementação

---

## 1. Motivação

Alvos fintech BR (Open Banking / PIX, APIs ICP-Brasil) frequentemente exigem **mutual TLS**:
o cliente precisa apresentar um certificado no handshake TLS, senão a conexão é recusada
**antes** de qualquer requisição. Hoje o Stiglitz não apresenta client-cert, então contra um
alvo mTLS **toda** ferramenta falha o handshake e o scan não alcança nada — superfície de maior
valor (APIs autenticadas) fica invisível.

Item da seção "Especialização fintech / API-heavy" do `docs/ROADMAP.md`, marcado como próximo
da fila.

## 2. Requisitos

- **R1** — Apresentar um par certificado/chave de cliente (PEM) em todo tráfego ao alvo que
  suporte client-cert nativamente.
- **R2** — Opt-in via env (`STIGLITZ_MTLS_CERT`/`STIGLITZ_MTLS_KEY`) e CLI
  (`--mtls-cert`/`--mtls-key`). Sem configuração → comportamento **idêntico** ao atual.
- **R3** — Cobrir o `stiglitz.sh` inteiro: curl subprocess, curl-ao-alvo (bash), urllib dos
  módulos Python, nuclei, ffuf e ZAP.
- **R4** — **Fail-closed**: mTLS configurado mas material inválido → abortar cedo com mensagem
  clara (sem rodar um scan cego).
- **R5** — Coexistir com `--proxy` (ortogonais: identidade TLS × rota de transporte).
- **R6** — Não vazar o conteúdo do material sensível em logs.

## 3. Não-objetivos (YAGNI / follow-up)

- **Chave protegida por senha** — exigir chave PEM já decriptada; detectar `ENCRYPTED` e abortar.
- **PKCS#12 como input** — input é PEM cert+key separados. (P12 só é gerado *internamente* e
  efêmero para o ZAP — ver §6.)
- **CA customizada p/ validar o servidor** — verificação do servidor segue como hoje
  (skip-verify/insecure, padrão de scanner). mTLS cobre só a identidade do cliente.
- **httpx / katana** — não têm suporte a client-cert (ver §7). Ficam de fora do MVP.
- **Proxy autenticado** — já não suportado pelo `netproxy`; herdamos a limitação.
- **osint.sh / stiglitz_red.sh** — fora do MVP; reaproveitam `lib/mtls.py` depois.

## 4. Interface

### Env
- `STIGLITZ_MTLS_CERT` — caminho do certificado de cliente (PEM).
- `STIGLITZ_MTLS_KEY` — caminho da chave privada (PEM, **sem senha**).

### CLI (`stiglitz.sh`, espelha o parse de `--proxy`)
- `--mtls-cert <file>`
- `--mtls-key <file>`

Regras: os dois juntos ou nenhum; só um → aborta. Validação acontece cedo, junto do bloco de
validação do `--proxy`.

## 5. `lib/mtls.py` — API (lógica pura + CLI, padrão `netproxy.py`/`bola.py`)

| Função | Retorno / efeito |
|---|---|
| `is_enabled()` | `True` se `STIGLITZ_MTLS_CERT` **e** `STIGLITZ_MTLS_KEY` estão setados |
| `cert_path()` / `key_path()` | valor do env, ou `''` |
| `key_is_encrypted(path)` | `True` se o PEM contém marcador `ENCRYPTED` (puro, sem rede) |
| `validate()` | confere existência+legibilidade dos dois e key não-encriptada; levanta `MtlsConfigError` (mensagem clara, com comando `openssl` de decript) se inválido. No-op se não-enabled |
| `client_ssl_context()` | `ssl.SSLContext` com `load_cert_chain(cert, key)`, ou `None` se não-enabled. **Consumido pelo `netproxy`** |
| `curl_cert_args()` | `['--cert', cert, '--key', key]` ou `[]` |

CLI: `python3 lib/mtls.py check` (valida e reporta status), `... curl-args` (emite os args) —
espelha o padrão de CLI dos outros módulos.

`MtlsConfigError` é exceção própria do módulo (não subclasse de `URLError`: ao contrário do
`ProxyUnavailable`, não queremos que o tratamento de rede a engula — é erro de configuração que
deve abortar).

## 6. Integração por subsistema

| Subsistema | Mecanismo | Arquivos tocados |
|---|---|---|
| **urllib (16 módulos)** | `netproxy.make_opener/urlopen/build_opener` passam a fazer `ssl_context = ssl_context or mtls.client_ssl_context()` | **só `lib/netproxy.py`** (0 nos call sites) |
| **curl subprocess (5 módulos)** | adicionar `*mtls.curl_cert_args()` ao lado do já existente `*netproxy.curl_proxy_args()` | `bola.py`, `cors_check.py`, `oauth_audit.py`, `poc_validator.py`, `security_headers.py` |
| **curl-ao-alvo (bash)** | `_MTLS_CURL=(--cert <cert> --key <key>)` montado junto dos arrays de proxy (linha ~333); espalhado nos curls ao alvo | `stiglitz.sh` |
| **nuclei** | `_MTLS_NUCLEI=(-client-cert <cert> -client-key <key>)` | `stiglitz.sh` |
| **ffuf** | `_MTLS_FFUF=(-cc <cert> -ck <key>)` | `stiglitz.sh` |
| **ZAP** | converte PEM→`.p12` efêmero (`openssl pkcs12 -export ... -passout pass:`) em arquivo temp `chmod 600`; carrega via API `network/action/addPkcs12ClientCertificate` (filePath, password vazia) + `network/action/setUseClientCertificate` (use=true), **antes** do spider (junto de `zap_inject_auth_headers`, ~linha 1597); apaga o `.p12` no cleanup/trap | `stiglitz.sh` |
| **httpx, katana** | sem suporte → `warn` + pulado (ver §7) | `stiglitz.sh` (mensagem) |
| **testssl, nmap** | sem suporte de client-auth; nmap já é pulado sob proxy | — |

### Detalhe urllib (o gancho central)
`netproxy.make_opener()` já tem o parâmetro `ssl_context` (hoje sempre `None` nos 16 call
sites). A mudança é uma linha em cada um dos três construtores do `netproxy`:
`ssl_context = ssl_context or mtls.client_ssl_context()`. Quando mTLS não está configurado,
`client_ssl_context()` retorna `None` e o comportamento é byte-idêntico ao atual. Import tardio
(`import mtls` dentro da função) evita ciclo e mantém o `netproxy` standalone.

### Coexistência com proxy
- curl: `-x <proxy>` + `--cert/--key` — compatíveis.
- Python: o `SSLContext` do mtls vai para `make_opener(ssl_context=...)`; no caminho SOCKS o
  `netproxy` já entrega o context ao `SocksiPyHandler(context=...)`.
- nuclei: `-proxy` + `-client-cert/-client-key` — compatíveis.
- ZAP: upstream proxy via `-config network...` + client-cert via API — independentes.

## 7. Fail-closed & validação

No `stiglitz.sh`, no bloco de validação de flags (junto do `--proxy`):
- só um de cert/key → `exit 1` com mensagem ("forneça --mtls-cert **e** --mtls-key").
- `python3 lib/mtls.py check` falha (arquivo ausente/ilegível ou key `ENCRYPTED`) → `exit 1`,
  ecoando a mensagem (inclui `openssl rsa -in key.enc.pem -out key.pem` p/ decriptar).

Diferença em relação ao `--proxy` (que **pula** a sondagem): aqui abortamos, porque sem o
client-cert o handshake falha e o scan inteiro fica cego — um relatório "0 findings" seria
enganoso. Log de ativação: `[…] mTLS ativo: cert=<path> key=<path>` (caminhos, nunca conteúdo).

## 8. Testes (TDD)

`tests/test_mtls.py`:
- `is_enabled` (ambos / nenhum / parcial)
- `validate`: ok; arquivo ausente; key `ENCRYPTED`; só um dos dois
- `key_is_encrypted` (PEM encriptado vs limpo)
- `curl_cert_args` (enabled → 4 tokens; disabled → `[]`)
- `client_ssl_context` (enabled → carrega par PEM de fixture; disabled → `None`)

`tests/test_netproxy*.py` (fiação): `make_opener`/`build_opener` injetam o context do `mtls`
quando enabled, e **não** quando disabled (monkeypatch de `mtls.client_ssl_context`).

**Fixture:** par cert/key PEM auto-assinado gerado em `conftest.py` (via `cryptography` ou
`openssl` em tmp) — nenhum material real versionado.

Validação de bash: `bash -n stiglitz.sh` + `shellcheck --severity=warning`. Compilar:
`python3 -m py_compile lib/mtls.py lib/netproxy.py`.

## 9. Limitações conhecidas (documentar no CLAUDE.md)

- **httpx (Fase 2 surface map) e katana (Fase 10 crawl)** não têm flag de client-cert →
  limitados contra alvo mTLS. A superfície autenticada é coberta por **ZAP spider + nuclei +
  módulos urllib**. Follow-up possível: proxy local de injeção de client-cert.
- **ZAP** só aceita client-cert em PKCS#12 → conversão efêmera PEM→P12 (sem senha).
- **Chave com senha** não suportada (fail-closed com instrução de decript).

## 10. Arquivos afetados (resumo)

- **Novo:** `lib/mtls.py`, `tests/test_mtls.py`
- **Editados:** `lib/netproxy.py` (gancho ssl_context); `lib/bola.py`, `lib/cors_check.py`,
  `lib/oauth_audit.py`, `lib/poc_validator.py`, `lib/security_headers.py` (curl args);
  `stiglitz.sh` (parse CLI, validação fail-closed, arrays nuclei/ffuf/curl, injeção ZAP,
  cleanup do P12); `CLAUDE.md` (Fase 9 + tabela de módulos + limitações); `docs/ROADMAP.md`
  (mover mTLS p/ feito); `CHANGELOG.md` (entrada Unreleased)
- **conftest:** fixture de par PEM de teste
