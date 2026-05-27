#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  Stiglitz RED v7.0 — Test Suite
# ═══════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/stiglitz_red.sh"
PASS=0; FAIL=0; TOTAL=0
TMPDIR_TEST=$(mktemp -d /tmp/stiglitz_red_test_XXXXXX)

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'

cleanup() { rm -rf "$TMPDIR_TEST" stiglitz_red_*_test_* 2>/dev/null; }
trap cleanup EXIT

assert() {
    local desc="$1" result="$2"; ((TOTAL++))
    if [ "$result" = "0" ]; then
        echo -e "  ${GRN}[PASS]${RST} $desc"; ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${RST} $desc"; ((FAIL++))
    fi
}

assert_contains() {
    local desc="$1" text="$2" pattern="$3"; ((TOTAL++))
    if echo "$text" | grep -qiE "$pattern" 2>/dev/null; then
        echo -e "  ${GRN}[PASS]${RST} $desc"; ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${RST} $desc — pattern '$pattern' not found"
        ((FAIL++))
    fi
}

skip() { echo -e "  ${YLW}[SKIP]${RST} $1"; }

# ── Mock Stiglitz scan dir ───────────────────────────────────────────────────────
setup_mock_swarm() {
    local dir="$TMPDIR_TEST/scan_testsite.com_20260514_120000"
    mkdir -p "$dir/raw"

    cat > "$dir/raw/nuclei.json" << 'JSON'
{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical","classification":{"cve-id":["CVE-2021-44228"]}},"matched-at":"https://testsite.com/api?id=1","host":"testsite.com"}
{"template-id":"cve-2023-1234","info":{"name":"Test CVE","severity":"high","classification":{"cve-id":["CVE-2023-1234"]}},"matched-at":"https://testsite.com/search?q=test","host":"testsite.com"}
JSON

    cat > "$dir/raw/nmap.txt" << 'TXT'
22/tcp   open  ssh     OpenSSH 8.9
80/tcp   open  http    Apache httpd 2.4.52
443/tcp  open  ssl     Apache httpd 2.4.52
3306/tcp open  mysql   MySQL 8.0.28
TXT

    cat > "$dir/raw/zap_alerts.json" << 'JSON'
[
  {"alert":"SQL Injection","risk":"High","url":"https://testsite.com/login?user=admin"},
  {"alert":"XSS","risk":"High","url":"https://testsite.com/search?q=test"},
  {"alert":"Missing CSP","risk":"Medium","url":"https://testsite.com"}
]
JSON

    echo "$dir"
}

# ═══════════════════════════════════════════════════════════════
#  TEST SUITE
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
echo -e "${CYN}  Stiglitz RED v7.0 — Test Suite${RST}"
echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
echo ""

# ─── 1. Syntax check ─────────────────────────────────────────────────────────
echo -e "${YLW}▸ 1. Syntax${RST}"
bash -n "$SCRIPT" 2>/dev/null
assert "stiglitz_red.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/lib/sqli.sh" 2>/dev/null
assert "lib/sqli.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/lib/brute.sh" 2>/dev/null
assert "lib/brute.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/lib/recon.sh" 2>/dev/null
assert "lib/recon.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/lib/xss.sh" 2>/dev/null
assert "lib/xss.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/lib/crawl.sh" 2>/dev/null
assert "lib/crawl.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/lib/msf.sh" 2>/dev/null
assert "lib/msf.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/lib/web.sh" 2>/dev/null
assert "lib/web.sh syntax valid" "$?"

bash -n "$(dirname "$SCRIPT")/setup.sh" 2>/dev/null
assert "setup.sh syntax valid" "$?"

# ─── 2. Help flag ────────────────────────────────────────────────────────────
echo -e "${YLW}▸ 2. Help / Usage${RST}"
out=$(bash "$SCRIPT" --help 2>&1)
assert_contains "--help shows Stiglitz RED"         "$out" "Stiglitz RED"
assert_contains "--help shows blackbox mode"     "$out" "blackbox|Blackbox"
assert_contains "--help shows staging profile"   "$out" "staging"
assert_contains "--help shows --auth-cookie"     "$out" "auth-cookie"
assert_contains "--help shows --scope"           "$out" "scope"
assert_contains "--help shows --dry-run"         "$out" "dry-run"
assert_contains "--help shows --skip"            "$out" "skip"
assert_contains "--help shows --resume"          "$out" "resume"

# ─── 3. Argument validation ──────────────────────────────────────────────────
echo -e "${YLW}▸ 3. Argument validation${RST}"

# No args
out=$(bash "$SCRIPT" 2>&1 || true)
assert_contains "No args shows help hint" "$out" "help|blackbox|target"

# Invalid profile
out=$(bash "$SCRIPT" -t https://x.com -p INVALID 2>&1 || true)
assert_contains "Invalid profile rejected" "$out" "inválido|invalid"

# Missing scan dir
out=$(bash "$SCRIPT" -d /nonexistent 2>&1 || true)
assert_contains "Missing scan dir fails" "$out" "não encontrado|not found"

# ─── 4. Blackbox mode + scope derivation ─────────────────────────────────────
echo -e "${YLW}▸ 4. Blackbox mode${RST}"
out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://testsite.com --dry-run 2>&1)
assert_contains "Blackbox derives scope from URL"    "$out" "testsite.com"
assert_contains "Blackbox shows DRY-RUN"             "$out" "DRY-RUN"
assert_contains "Blackbox mode shown in banner"      "$out" "BLACKBOX"

out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://api.company.com:8443/v1 --dry-run 2>&1)
assert_contains "Blackbox handles port in URL"       "$out" "api.company.com"

# ─── 5. Stiglitz mode ───────────────────────────────────────────────────────────
echo -e "${YLW}▸ 5. Stiglitz integration mode${RST}"
MOCK_DIR=$(setup_mock_swarm)
out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -d "$MOCK_DIR" --dry-run 2>&1)
assert_contains "Stiglitz derives target from dir"      "$out" "testsite.com"
assert_contains "Stiglitz mode shown in banner"         "$out" "Stiglitz"

# ─── 6. Profile validation ───────────────────────────────────────────────────
echo -e "${YLW}▸ 6. Profiles${RST}"
for profile in lab staging production; do
    out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://test.com --dry-run -p "$profile" 2>&1)
    assert_contains "Profile '$profile' accepted" "$out" "$profile|$profile"
done

# ─── 7. ROE gate ─────────────────────────────────────────────────────────────
echo -e "${YLW}▸ 7. ROE confirmation gate${RST}"
out=$(echo "NO" | bash "$SCRIPT" -t https://test.com 2>&1 || true)
assert_contains "Wrong confirmation aborts" "$out" "não confirmada|abortando"

out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://test.com --dry-run 2>&1)
assert_contains "Correct confirmation proceeds" "$out" "DRY-RUN"

# ─── 8. --skip / --only ──────────────────────────────────────────────────────
echo -e "${YLW}▸ 8. Phase control (--skip / --only)${RST}"
out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://test.com --dry-run --skip recon,brute 2>&1)
assert_contains "--skip recon shows skip message"  "$out" "recon.*ignor|ignor.*recon"
assert_contains "--skip brute shows skip message"  "$out" "brute.*ignor|ignor.*brute"

out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://test.com --dry-run --only sqli 2>&1)
assert_contains "--only sqli runs sqli"  "$out" "sqli|SQLi"
assert_contains "--only sqli skips xss" "$out" "xss.*ignor|ignor.*xss"

# ─── 9. Production profile restrictions ──────────────────────────────────────
echo -e "${YLW}▸ 9. Production restrictions${RST}"
out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -d "$MOCK_DIR" -p production --dry-run 2>&1)
assert_contains "Production disables brute"  "$out" "brute.*desabilit|desabilit.*brute"
assert_contains "Production disables nikto"  "$out" "nikto.*desabilit|desabilit.*nikto"

# ─── 10. Output directory structure ──────────────────────────────────────────
echo -e "${YLW}▸ 10. Output directory structure${RST}"
out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://testdir.com --dry-run --output-dir "$TMPDIR_TEST/test_outdir" 2>&1)
assert "Output dir created" "$([ -d "$TMPDIR_TEST/test_outdir" ] && echo 0 || echo 1)"
assert "data/ subdir exists" "$([ -d "$TMPDIR_TEST/test_outdir/data" ] && echo 0 || echo 1)"
assert "sqlmap/ subdir exists" "$([ -d "$TMPDIR_TEST/test_outdir/sqlmap" ] && echo 0 || echo 1)"
assert "xss/ subdir exists" "$([ -d "$TMPDIR_TEST/test_outdir/xss" ] && echo 0 || echo 1)"
assert "recon/ subdir exists" "$([ -d "$TMPDIR_TEST/test_outdir/recon" ] && echo 0 || echo 1)"
assert "log file created" "$([ -f "$TMPDIR_TEST/test_outdir/stiglitz_red.log" ] && echo 0 || echo 1)"
assert "exploits_confirmed.csv created" "$([ -f "$TMPDIR_TEST/test_outdir/exploits_confirmed.csv" ] && echo 0 || echo 1)"
assert "state file created" "$([ -f "$TMPDIR_TEST/test_outdir/.stiglitz_red_state" ] && echo 0 || echo 1)"

# ─── 11. CVE extraction (Stiglitz mode) ─────────────────────────────────────────
echo -e "${YLW}▸ 11. CVE extraction${RST}"
out_dir="$TMPDIR_TEST/test_cve_out"
echo "EU AUTORIZO" | bash "$SCRIPT" -d "$MOCK_DIR" --dry-run --output-dir "$out_dir" 2>&1 | head -50 > /dev/null
if [ -f "$out_dir/data/cves_found.txt" ]; then
    assert "CVE-2021-44228 extracted" "$(grep -q 'CVE-2021-44228' "$out_dir/data/cves_found.txt" && echo 0 || echo 1)"
    assert "CVE-2023-1234 extracted"  "$(grep -q 'CVE-2023-1234'  "$out_dir/data/cves_found.txt" && echo 0 || echo 1)"
else
    assert "cves_found.txt created" "1"
fi

# ─── 11.5 Scope enforcement (URLs fora de escopo são filtradas) ──────────────
echo -e "${YLW}▸ 11.5 Scope enforcement${RST}"
SCOPE_DIR="$TMPDIR_TEST/scan_testsite.com_20260514_130000"
mkdir -p "$SCOPE_DIR/raw"
cat > "$SCOPE_DIR/raw/nuclei.json" << 'JSON'
{"template-id":"t1","info":{"name":"In scope","severity":"high"},"matched-at":"https://testsite.com/api?id=1","host":"testsite.com"}
{"template-id":"t2","info":{"name":"Out of scope","severity":"high"},"matched-at":"https://evil-external.com/api?id=1","host":"evil-external.com"}
JSON
scope_out="$TMPDIR_TEST/scope_out"
echo "EU AUTORIZO" | bash "$SCRIPT" -d "$SCOPE_DIR" --dry-run --output-dir "$scope_out" 2>&1 | head -60 > /dev/null
if [ -f "$scope_out/data/targets_scored.txt" ]; then
    assert "In-scope URL mantida"     "$(grep -q 'testsite.com' "$scope_out/data/targets_scored.txt" && echo 0 || echo 1)"
    assert "Out-of-scope URL filtrada" "$(grep -q 'evil-external.com' "$scope_out/data/targets_scored.txt" && echo 1 || echo 0)"
else
    assert "targets_scored.txt criado" "1"
fi

# ─── 12. Python module syntax ────────────────────────────────────────────────
echo -e "${YLW}▸ 12. Python modules${RST}"
LIBDIR="$(dirname "$SCRIPT")/lib"
python3 -c "import ast; ast.parse(open('$LIBDIR/evidence.py').read())" 2>/dev/null
assert "lib/evidence.py syntax valid" "$?"

python3 -c "import ast; ast.parse(open('$LIBDIR/report_generator.py').read())" 2>/dev/null
assert "lib/report_generator.py syntax valid" "$?"

# ─── 13. Scored targets builder ──────────────────────────────────────────────
echo -e "${YLW}▸ 13. URL scoring${RST}"
echo -e "https://target.com/api?id=1\nhttps://target.com/login?user=x&pass=y\nhttps://target.com/img/logo.png\nhttps://target.com/" \
    > "$TMPDIR_TEST/raw.txt"
python3 - "$TMPDIR_TEST/raw.txt" "$TMPDIR_TEST/scored.txt" "target.com" << 'PYEOF'
import sys, re
raw_f, scored_f = sys.argv[1], sys.argv[2]
scope = sys.argv[3:]
crit_params = re.compile(r'[?&](id|user|pass)=', re.I)
sens_paths  = re.compile(r'/(api|login|auth)', re.I)
media_ext   = re.compile(r'\.(jpg|png|gif|css|js|svg|ico|woff)(\?|$)', re.I)
seen, results = set(), []
with open(raw_f) as fi:
    for url in fi:
        url = url.strip()
        if not url or url in seen: continue
        if media_ext.search(url): continue
        seen.add(url)
        s = 0
        if crit_params.search(url): s += 5
        if url.count('=') > 1:     s += 3
        if sens_paths.search(url):  s += 4
        if '?' in url:              s += 2
        results.append((s, url))
results.sort(key=lambda x: x[0], reverse=True)
with open(scored_f, 'w') as fo:
    for s, url in results:
        fo.write(f"{s}|{url}\n")
PYEOF
assert "URL scorer runs" "$?"
assert "PNG filtered out" "$(grep -q 'logo.png' "$TMPDIR_TEST/scored.txt" && echo 1 || echo 0)"
assert "Parametrized URLs scored higher" "$(head -1 "$TMPDIR_TEST/scored.txt" | grep -qE '\?|=' && echo 0 || echo 1)"

# ─── 14. Auth options ────────────────────────────────────────────────────────
echo -e "${YLW}▸ 14. Auth options${RST}"
out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://test.com \
    --auth-cookie "session=abc123" \
    --auth-header "X-API-Key: secret" \
    --dry-run 2>&1)
assert_contains "Auth cookie accepted" "$out" "DRY-RUN|auth|cookie|BLACKBOX"

# ─── 15. Scope file ──────────────────────────────────────────────────────────
echo -e "${YLW}▸ 15. Scope file${RST}"
echo -e "target.com\napi.target.com\nwww.target.com" > "$TMPDIR_TEST/scope.txt"
out=$(echo "EU AUTORIZO" | bash "$SCRIPT" -t https://target.com \
    --scope-file "$TMPDIR_TEST/scope.txt" --dry-run 2>&1)
assert_contains "Scope file loaded" "$out" "target.com"

out=$(bash "$SCRIPT" -t https://test.com --scope-file /nonexistent 2>&1 || true)
assert_contains "Missing scope file fails" "$out" "não encontrado|not found"

# ═══════════════════════════════════════════════════════════════
#  SUMÁRIO
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
echo -e "  ${GRN}PASS: $PASS${RST}  |  ${RED}FAIL: $FAIL${RST}  |  Total: $TOTAL"
echo -e "${CYN}═══════════════════════════════════════════════════════════════${RST}"
echo ""
[ "$FAIL" -eq 0 ] && echo -e "  ${GRN}Todos os testes passaram.${RST}" \
                  || echo -e "  ${RED}$FAIL teste(s) falharam.${RST}"
echo ""
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
