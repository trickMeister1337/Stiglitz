import os, subprocess, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_HARNESS = r'''
set -e
warn() {{ echo "WARN: $*" >&2; }}
eval "$(awk '/^phase_output_ok\(\) \{{/,/^\}}/' "{root}/stiglitz.sh")"
if phase_output_ok "FASE_X" "$1" "$2"; then echo OK; else echo FAIL; fi
'''


def _run(harness_args):
    d = tempfile.mkdtemp()
    present = os.path.join(d, "present.txt"); open(present, "w").write("x\n")
    empty = os.path.join(d, "empty.txt"); open(empty, "w").close()
    missing = os.path.join(d, "missing.txt")
    mapping = {"present": present, "empty": empty, "missing": missing}
    a, b = (mapping[x] for x in harness_args)
    script = _HARNESS.format(root=ROOT)
    r = subprocess.run(["bash", "-c", script, "bash", a, b], capture_output=True, text=True)
    return r.stdout.strip()


def test_all_present_nonempty_ok():
    assert "OK" in _run(("present", "present"))


def test_one_empty_fails():
    assert "FAIL" in _run(("present", "empty"))


def test_one_missing_fails():
    assert "FAIL" in _run(("present", "missing"))
