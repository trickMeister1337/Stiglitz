#!/usr/bin/env python3
"""
zap_config_fix.py — Ajusta config.xml do ZAP

Extraído de stiglitz.sh (heredoc PYFIX). Recebe argumentos posicionais
via sys.argv, idêntico à invocação original do stiglitz.sh.
"""
import sys

path = sys.argv[1]
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

entry = '''            <addr>
                <name>{}</name>
                <regex>false</regex>
                <enabled>true</enabled>
            </addr>'''

changed = False
for addr in ['127.0.0.1', 'localhost']:
    # Procurar <name>ADDR</name> exato — sem porta
    if '<name>' + addr + '</name>' not in content:
        content = content.replace(
            '        </addrs>',
            entry.format(addr) + '\n        </addrs>'
        )
        print('OK: adicionado ' + addr)
        changed = True
    else:
        print('OK: ' + addr + ' ja existe')

if '<disablekey>false</disablekey>' in content:
    content = content.replace(
        '<disablekey>false</disablekey>',
        '<disablekey>true</disablekey>'
    )
    print('OK: disablekey corrigido')
    changed = True

if changed:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
