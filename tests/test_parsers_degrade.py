import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import parsers as P


def test_extract_urls_degrades_on_malformed_inputs():
    """JSON inválido / arquivos corrompidos não devem levantar — devem degradar."""
    outdir = tempfile.mkdtemp()
    with open(os.path.join(outdir, "input_nuclei.jsonl"), "w") as f:
        f.write("isto não é json\n{\"matched-at\": \"http://t/a\"}\n")
    with open(os.path.join(outdir, "input_zap.json"), "w") as f:
        f.write("{ corrompido")
    with open(os.path.join(outdir, "input_httpx.jsonl"), "w") as f:
        f.write("{quebrado\n")
    result = P.extract_all_urls(outdir, "t.com")
    assert isinstance(result, dict)
