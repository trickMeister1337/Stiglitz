# Design — Suporte a proxy HTTP/SOCKS (stiglitz.sh)

**Data:** 2026-06-12
**Escopo:** Item 2 do roadmap fintech — proxy configurável para o scanner `stiglitz.sh` e os módulos `lib/` que ele usa.
**Status:** Aprovado, pronto para plano de implementação.

## Contexto e motivação

Hoje nenhuma ferramenta do `stiglitz.sh` roteia tráfego por proxy. Para engajamentos
fintech sob RoE, é necessário poder rotear o tráfego que toca o alvo por um proxy
HTTP/SOCKS (Burp/mitmproxy para captura de evidência, ou redirector/jump host para
controle de atribuição). O risco central não é "passar a flag", é o **vazamento de
atribuição**: se uma ferramenta que toca o alvo não honra o proxy e roda direto, o IP
real do operador chega ao alvo — um incidente de OPSEC.

## Decisões travadas

1. **Escopo de tráfego: só o alvo.** O proxy aplica-se às ferramentas/requests que
   tocam o ALVO. Tráfego de controle (ZAP API em localhost) e de serviços terceiros
   (enriquecimento NVD/EPSS/KEV; notificações Telegram/Slack/Teams; DNS passivo do
   subfinder) vai DIRETO.
2. **Ferramenta-alvo sem proxy (nmap): pular + avisar.** Em modo proxy, qualquer
   ferramenta que toca o alvo e não suporta proxy é PULADA com aviso claro — nunca roda
   direto. Garante zero vazamento; aceita-se perder o port scan/vulners sob proxy.
3. **Escopo de entry points: só `stiglitz.sh`** (+ os módulos `lib/` que ele usa). O
   helper Python é compartilhado, então `osint.sh`/`stiglitz_red.sh` reaproveitam depois.
4. **Interface:** flag `--proxy <url>` → env `STIGLITZ_PROXY`. Aceita `http://`,
   `https://`, `socks5://`, `socks5h://`. URL malformada → erro claro e aborta.

## Classificação de tráfego

| Categoria | Itens | Comportamento |
|-----------|-------|---------------|
| **Proxiado (toca o alvo)** | httpx, nuclei, katana, ffuf, testssl, curl-ao-alvo, ZAP (upstream proxy), módulos `lib/` que buscam o alvo | recebe o proxy |
| **Direto (não-alvo)** | subfinder (DNS passivo), `cve_enrich` (NVD/EPSS/KEV), notificações (Telegram/Slack/Teams), ZAP API (localhost) | sem proxy |
| **Pula + avisa (sem proxy)** | nmap | não roda em modo proxy |

## Arquitetura

### Componente 1 — Config & validação (`stiglitz.sh`)

- Default `STIGLITZ_PROXY=""` (sem proxy → comportamento atual idêntico).
- Flag `--proxy <url>` no parser de args (junto de `--repro-raw` etc.) → seta
  `STIGLITZ_PROXY`.
- Validação no início: a URL deve casar `^(https?|socks5h?)://[^/]+`; caso contrário,
  imprime erro PT-BR e aborta (não degrada silencioso).
- `export STIGLITZ_PROXY` para os módulos Python e o `pipeline.py`.
- No início do scan, loga o modo proxy ativo e quais ferramentas serão puladas.

### Componente 2 — Helpers bash (`stiglitz.sh`)

Funções que emitem o flag de proxy correto, aplicadas **apenas** às invocações que
tocam o alvo:

- `proxy_go_arg` → `-proxy <url>` (subfinder NÃO usa; httpx/nuclei/katana/ffuf usam).
- `proxy_curl_args` → `-x <url>` (curl; `socks5h://` é suportado nativamente pelo curl).
- `proxy_testssl_arg` → `--proxy <host:port>` derivado da URL (testssl usa `host:port`).
- nmap: guardado por `if [ -n "$STIGLITZ_PROXY" ]; then warn+skip; else run; fi`.
- ZAP daemon: quando `STIGLITZ_PROXY` setado, adiciona `-config
  network.connection.httpProxy.host/port/enabled` (ou `socksProxy.*` p/ socks) na
  subida do daemon, de modo que spider/active scan saiam pelo proxy. A ZAP API
  (localhost) permanece direta.

curls que NÃO recebem proxy: ZAP API (localhost) e notificações (terceiros).

### Componente 3 — Helper Python `lib/netproxy.py` (puro + testável)

- `proxy_url()` → lê `STIGLITZ_PROXY` (ou `""`).
- `make_opener(ssl_context=None)` → retorna um `urllib.request.OpenerDirector`:
  - sem proxy: opener default (preservando `ssl_context` quando dado);
  - `http(s)://`: `ProxyHandler({"http": url, "https": url})`;
  - `socks5(h)://`: `SocksiPyHandler` do PySocks se disponível; se PySocks ausente,
    levanta `ProxyUnavailable` (o chamador pula+avisa — nunca cai para direto).
- `urlopen(req_or_url, timeout=..., ssl_context=...)` → conveniência sobre `make_opener`.
- Sem `STIGLITZ_PROXY` → tudo transparente; o comportamento atual dos módulos não muda.

### Componente 4 — Aplicação nos módulos `lib/`

Módulos que tocam o alvo passam a obter o opener via `netproxy` (no proxy → idêntico ao
atual). Quando `make_opener` levanta `ProxyUnavailable` (SOCKS sem PySocks), o módulo
emite aviso PT-BR e pula a sua sondagem (degrada como `oob.py`).

- **Roteados por netproxy (tocam o alvo):** `ratelimit_check.py`, `oauth_audit.py`,
  `oauth_refresh.py`, `pan_scanner.py`, `payment_page_monitor.py`, `monitoring_check.py`,
  `version_fingerprint.py`, `secscan.py`, `js_analysis.py`. O `bizlogic.py` (que já tem
  `_OPENER` próprio) incorpora o `ProxyHandler` do `netproxy` nesse opener.
- **Direto (sem mudança):** `cve_enrich.py` (terceiros).
- **A confirmar no plano:** `parsers.py` (verificar se faz fetch em runtime; se só
  parseia, não muda). `bola.py` envia via `bizlogic`/`send_fn` injetável — herda o
  opener proxiado do `bizlogic`.

O plano enumera, por módulo, o ponto exato de troca de `urllib.request.urlopen(...)`
por `netproxy.urlopen(...)` (ou `netproxy.make_opener` quando o módulo reusa um opener).

## Garantia anti-vazamento

A propriedade central a verificar: **nenhuma ferramenta que toca o alvo roda direto
quando `STIGLITZ_PROXY` está setado.** Concretamente:
- ferramentas-alvo recebem o flag de proxy;
- nmap (e qualquer tool-alvo sem proxy) é pulado, não rodado direto;
- módulo-alvo com SOCKS-sem-PySocks pula, não cai para direto;
- `cve_enrich`/subfinder/notificações permanecem diretos (são não-alvo, intencional).

## Testes

- **pytest `tests/test_netproxy.py`:** `make_opener` sem proxy (opener default,
  ssl_context preservado); `http://` e `https://` montam `ProxyHandler` com a URL;
  `socks5://` usa `SocksiPyHandler` quando PySocks presente; `socks5://` sem PySocks
  levanta `ProxyUnavailable`; `proxy_url()` lê o env.
- **bash:** `bash -n` + `shellcheck`; um `--dry-run` com `--proxy` mostra o plumbing;
  asserts via grep de que (a) as invocações-alvo recebem o flag e (b) o bloco do nmap
  pula sob proxy. Reusa o `DRY_RUN` existente.

## Validação (gates do projeto)

```bash
python3 -m py_compile lib/netproxy.py lib/*.py
python3 -m pytest tests/test_netproxy.py
bash -n stiglitz.sh
shellcheck --severity=warning stiglitz.sh
```

## Idioma

Mensagens de console/aviso em PT-BR; sem texto de deliverable neste recurso.

## Fora de escopo (evolução futura)

- `osint.sh` e `stiglitz_red.sh` (e `sqlmap`, que vive no RED) — reaproveitam
  `lib/netproxy.py` e os helpers depois.
- Modo "todo egress pelo proxy" (`--proxy-all`) — só o alvo nesta entrega.
- nmap via proxychains — pulado nesta entrega (evita risco de DNS leak do proxychains).
- DNS do alvo via proxy (resolução remota) — fora; `socks5h://` no curl já resolve
  remoto onde aplicável, mas não é um requisito desta entrega.
