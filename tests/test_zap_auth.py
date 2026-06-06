import os, sys, json, urllib.parse
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import zap_auth as Z


def test_creds_config_uses_lowercase_keys():
    # Bug validado ao vivo: ZAP exige username/password MINÚSCULO
    # (Username/Password capitalizado → missing_parameter).
    cfg = Z.creds_config("admin@x.op", "pw")
    parsed = dict(urllib.parse.parse_qsl(cfg))
    assert parsed == {"username": "admin@x.op", "password": "pw"}


def test_json_auth_config_has_login_url_and_data():
    cfg = Z.json_auth_config("http://t/rest/user/login", '{"email":"{%username%}"}')
    parsed = dict(urllib.parse.parse_qsl(cfg))
    assert parsed["loginUrl"] == "http://t/rest/user/login"
    assert "{%username%}" in parsed["loginRequestData"]


def test_login_data_template_placeholders():
    tpl = Z.login_data_template("email", "password")
    obj = json.loads(tpl)
    assert obj["email"] == "{%username%}"
    assert obj["password"] == "{%password%}"
