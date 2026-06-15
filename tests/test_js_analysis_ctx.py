# tests/test_js_analysis_ctx.py
"""Regressão: a variável `ctx` (um ssl.SSLContext consumido por netproxy.urlopen)
NÃO pode ser reatribuída em escopo de módulo em lib/js_analysis.py.

Bug original: a extração de secrets reusava o nome `ctx` para um trecho de texto
(str), sombreando o SSLContext global. A Fase 8c (verificação de endpoints) então
chamava netproxy.urlopen(context=ctx) com a string e quebrava com
`AttributeError: 'str' object has no attribute 'wrap_socket'`.

js_analysis.py roda como script (sys.argv + rede no top-level), então não é
importável; a verificação é estática via AST.
"""
import ast
import os

JS_ANALYSIS = os.path.join(os.path.dirname(__file__), "..", "lib", "js_analysis.py")


def _module_level_assigns_to(tree, name):
    """Conta atribuições `name = ...` em escopo de módulo (sem descer em def/lambda)."""
    count = 0
    stack = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue  # atribuições dentro de funções são locais, não sombreiam o global
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    count += 1
        for child in ast.iter_child_nodes(node):
            stack.append(child)
    return count


def test_ctx_sslcontext_not_shadowed():
    with open(JS_ANALYSIS, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    n = _module_level_assigns_to(tree, "ctx")
    assert n == 1, (
        f"`ctx` é atribuído {n}x em escopo de módulo; deve ser 1 (apenas o "
        "ssl.SSLContext). Uma 2a atribuição sombreia o SSLContext e quebra "
        "netproxy.urlopen(context=ctx) com 'str' has no attribute 'wrap_socket'."
    )
