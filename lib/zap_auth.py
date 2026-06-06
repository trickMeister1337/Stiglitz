#!/usr/bin/env python3
"""
zap_auth.py — builders dos parâmetros de autenticação do ZAP (#3).

Trava o FORMATO validado ao vivo contra ZAP 2.17 + OWASP Juice Shop:
- authMethodName = jsonBasedAuthentication, com loginUrl + loginRequestData;
- credenciais UsernamePassword com chaves MINÚSCULAS username/password
  (Username/Password capitalizado → "missing_parameter" no ZAP — bug confirmado);
- loginRequestData usa os placeholders {%username%}/{%password%}.

Funções puras (urlencode) — sem rede. O stiglitz.sh consome estas strings
nas chamadas curl da API do ZAP.
"""
import sys
import json
import urllib.parse

# IMPORTANTE (validado ao vivo contra ZAP 2.17): o ZAP url-DECODA os *ConfigParams
# uma SEGUNDA vez internamente. Logo os valores precisam ser url-encodados aqui
# (urllib.urlencode), e o stiglitz.sh aplica MAIS um encode de transporte na query.
# Single-encode → "missing_parameter"; o double-encode (urlencode + transporte) é o
# que o ZAP aceita.


def creds_config(username, password):
    """authCredentialsConfigParams para UsernamePasswordAuthenticationCredentials."""
    return urllib.parse.urlencode({"username": username, "password": password})


def json_auth_config(login_url, login_data):
    """authMethodConfigParams para jsonBasedAuthentication."""
    return urllib.parse.urlencode({"loginUrl": login_url, "loginRequestData": login_data})


def login_data_template(user_field="email", pass_field="password"):
    """Corpo JSON de login com placeholders do ZAP ({%username%}/{%password%})."""
    return json.dumps({user_field: "{%username%}", pass_field: "{%password%}"},
                      separators=(",", ":"))


if __name__ == "__main__":
    # CLI usada pelo stiglitz.sh: emite a string solicitada.
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "creds":
        print(creds_config(sys.argv[2], sys.argv[3]))
    elif cmd == "json-auth":
        print(json_auth_config(sys.argv[2], sys.argv[3]))
    elif cmd == "login-data":
        print(login_data_template(sys.argv[2] if len(sys.argv) > 2 else "email",
                                  sys.argv[3] if len(sys.argv) > 3 else "password"))
