#!/usr/bin/env python3
"""evidence_render.py — Decide inline vs. arquivo lateral para blocos de evidência.

Alguns findings carregam evidência enorme: o "Public Swagger API - Detect" do Nuclei
embute a spec OpenAPI inteira (~400 KB) no campo Evidence. Renderizado inline isso
incha o HTML em vários MB (há mais de um card Swagger) e força o desenvolvedor a rolar
centenas de KB. Aqui decidimos, por tamanho, se a evidência segue inline (na
`.evidence-box`, já rolável) ou se vira um arquivo lateral em `evidence/` linkado a
partir de um trecho — mantendo o HTML leve e preservando a evidência point-in-time
(o conteúdo íntegro vai para o arquivo, não se perde).

Lógica pura, sem I/O — o report grava o arquivo e monta o HTML a partir do plano.
"""

import hashlib


def evidence_filename(content):
    """Nome de arquivo endereçado por conteúdo (estável entre re-runs e dedup natural
    quando dois cards compartilham a mesma spec)."""
    h = hashlib.sha1(content.encode("utf-8", "replace")).hexdigest()[:12]
    return f"ev_{h}.txt"


def plan_evidence(content, max_inline=6000, snippet_chars=3000):
    """Decide como renderizar um bloco de evidência.

    - `len(content) <= max_inline`  → {'mode':'inline', 'content': content}
    - caso contrário                → {'mode':'sidecar', 'snippet', 'filename',
                                        'content', 'kb', 'snippet_kb'}

    `kb`/`snippet_kb` são tamanhos em UTF-8 (bytes), não code points — o que casa com
    o tamanho real do arquivo gravado. Lógica pura.
    """
    if len(content) <= max_inline:
        return {"mode": "inline", "content": content}

    snippet = content[:snippet_chars]
    n_bytes = len(content.encode("utf-8", "replace"))
    snip_bytes = len(snippet.encode("utf-8", "replace"))
    return {
        "mode": "sidecar",
        "snippet": snippet,
        "filename": evidence_filename(content),
        "content": content,
        "kb": round(n_bytes / 1024),
        "snippet_kb": round(snip_bytes / 1024),
    }
