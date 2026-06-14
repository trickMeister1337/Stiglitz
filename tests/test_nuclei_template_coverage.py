"""Regressão Bug #5: a Fase 4 do Nuclei deve rodar os templates OFICIAIS.

Causa raiz: passar `-t <dir_custom>` faz o Nuclei rodar APENAS aquele diretório
(ainda filtrado por -tags), substituindo o repositório oficial. Medido no alvo:
~5913 templates (sem -t) → 3 (com -t custom). Logo as invocações de *scan*
principal (as que usam -tags + -severity critical,high,medium) NÃO podem incluir
NUCLEI_TEMPLATES_FLAGS. O(s) template(s) custom devem rodar numa passada dedicada
(o working example já no código é a fase 'info', que omite -t de propósito).
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SH = os.path.join(ROOT, "stiglitz.sh")


def _nuclei_cmds(text):
    """Comandos nuclei completos (continuações de linha unidas), com saída -jsonl."""
    joined = re.sub(r"\\\n", " ", text)
    return [re.sub(r"\s+", " ", ln).strip()
            for ln in joined.splitlines()
            if re.search(r"\bnuclei\b", ln) and "-jsonl" in ln]


def test_scan_principal_nao_restringe_aos_templates_custom():
    cmds = _nuclei_cmds(open(SH, encoding="utf-8").read())
    scan_cmds = [c for c in cmds if "-tags" in c and "critical,high,medium" in c]
    assert scan_cmds, "esperava encontrar invocações de scan do Nuclei"
    for c in scan_cmds:
        assert "NUCLEI_TEMPLATES_FLAGS" not in c, (
            "invocação de scan restringe aos templates custom — "
            "`-t custom` zera os ~5913 oficiais: " + c[:140])


def test_template_custom_roda_em_passada_dedicada():
    cmds = _nuclei_cmds(open(SH, encoding="utf-8").read())
    custom = [c for c in cmds if "NUCLEI_TEMPLATES_FLAGS" in c]
    assert custom, ("o(s) template(s) custom devem rodar numa passada dedicada com "
                    "NUCLEI_TEMPLATES_FLAGS — senão seriam perdidos")
    for c in custom:
        assert "-tags" not in c, (
            "a passada custom não deve filtrar pelas -tags do scan "
            "(o template custom pode não casar essas tags): " + c[:140])
