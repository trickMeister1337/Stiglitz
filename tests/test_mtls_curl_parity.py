import os, glob
LIBDIR = os.path.join(os.path.dirname(__file__), "..", "lib")


def test_every_curl_proxy_site_also_passes_mtls_args():
    offenders = []
    for f in glob.glob(os.path.join(LIBDIR, "*.py")):
        if os.path.basename(f) in ("netproxy.py", "mtls.py"):
            continue
        src = open(f, encoding="utf-8").read()
        if "curl_proxy_args()" in src and "mtls.curl_cert_args()" not in src:
            offenders.append(os.path.basename(f))
    assert not offenders, f"módulos com curl proxy mas sem mtls: {offenders}"
