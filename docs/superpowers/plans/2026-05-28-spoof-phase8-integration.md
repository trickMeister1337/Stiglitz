# Spoof Phase-8 Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Plug the existing `email_spoof_poc.py` into the `stiglitz.sh` Phase 8 so every scan emits an analytical spoofing verdict (and, with opt-in flags, sends a forged email), surfaced in the HTML report's Email Security section.

**Architecture:** Add a `--records-json` flag to `email_spoof_poc.py` so it reuses the DNS records Phase 8 already collected (no re-resolution). Phase 8 calls the tool to write `raw/spoof_evidence.json`; new `--spoof-*` flags on `stiglitz.sh` enable opt-in delivery. `stiglitz_report.py` loads that JSON and renders a verdict box (no new finding, to avoid double-counting).

**Tech Stack:** Python 3 stdlib, bash. Tests in `unittest` (runnable via pytest); bash validated with `bash -n` + `shellcheck`.

**Design doc:** `docs/superpowers/specs/2026-05-28-spoof-phase8-integration-design.md`

---

## File Structure

- **Modify** `email_spoof_poc.py` — add `--records-json PATH`; in `main()`, load records from that file instead of `analyze(domain)`.
- **Modify** `stiglitz.sh` — add `--spoof-send`/`--spoof-to`/`--spoof-from`/`--spoof-smtp` flags, a guard, and Phase 8 wiring that runs the tool and captures `SPOOF_VERDICT`.
- **Modify** `stiglitz_report.py` — load `raw/spoof_evidence.json`; render the verdict box (+ SMTP transcript if delivered) inside the Email Security section.
- **Test** `test_email_spoof.py` — unit test for the `--records-json` path.

---

## Task 1: `email_spoof_poc.py` — `--records-json` flag

**Files:**
- Modify: `email_spoof_poc.py`
- Test: `test_email_spoof.py`

- [ ] **Step 1: Write the failing test**

Append this method inside the existing `TestGateAndOutput` class in `test_email_spoof.py`:

```python
    def test_main_records_json_uses_file_not_network(self):
        import json
        import tempfile
        import email_spoof_poc as esp
        with tempfile.TemporaryDirectory() as d:
            recs = {"spf": {"status": "PERMISSIVE", "severity": "high"},
                    "dmarc": {"status": "MONITOR_ONLY", "severity": "medium", "policy": "none"},
                    "dkim": {"status": "NOT_FOUND", "severity": "low"}}
            recpath = os.path.join(d, "email_security.json")
            with open(recpath, "w") as f:
                json.dump(recs, f)
            rc = esp.main(["target.com", "--records-json", recpath, "--outdir", d])
            self.assertEqual(rc, 0)
            with open(os.path.join(d, "spoof_evidence.json")) as f:
                data = json.load(f)
            self.assertEqual(data["verdict"]["status"], "SPOOFABLE_INBOX")
            self.assertNotIn("send", data)
            self.assertEqual(data["dns_records"]["dmarc"]["policy"], "none")
```

(Reusing `target.com` is safe: with `--records-json` set, `analyze()` is never called, so no DNS/network happens.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_email_spoof.py::TestGateAndOutput::test_main_records_json_uses_file_not_network -q`
Expected: FAIL — `--records-json` is an unrecognized argument (argparse `SystemExit`) or the file is ignored and `analyze` runs.

- [ ] **Step 3: Add the `--records-json` argument**

In `email_spoof_poc.py`, in `parse_args`, add this line right after the `p.add_argument("--outdir", default=None)` line:

```python
    p.add_argument("--records-json", default=None,
                   help="Usa registros DNS deste JSON (raw/email_security.json) em vez de resolver")
```

- [ ] **Step 4: Use the records file in `main()`**

In `email_spoof_poc.py`, in `main()`, find this block:

```python
    print(f"  [*] Analisando autenticação de email de {domain} ...")
    records = analyze(domain)
```

Replace it with:

```python
    if args.records_json:
        with open(args.records_json) as f:
            records = json.load(f)
    else:
        print(f"  [*] Analisando autenticação de email de {domain} ...")
        records = analyze(domain)
```

(`json` is already imported at module top; `analyze` is still imported at the top of `main()` and is simply not called in the records-json path.)

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest test_email_spoof.py -q`
Expected: PASS — 32 tests total (31 prior + 1 new).
Then: `python3 -m py_compile email_spoof_poc.py`

- [ ] **Step 6: Commit**

```bash
git add email_spoof_poc.py test_email_spoof.py
git commit -m "feat(spoof): --records-json reusa registros já coletados (sem re-resolver DNS)"
```

---

## Task 2: `stiglitz.sh` — flags `--spoof-*` + wiring na Fase 8

**Files:**
- Modify: `stiglitz.sh` (arg parser ~line 186-197; guard after ~line 203; Phase 8 ~line 1056-1077)

- [ ] **Step 1: Add the new flags to the argument parser**

In `stiglitz.sh`, find the parser block:

```bash
        --outdir)            OUTDIR_OVERRIDE="${_args[$((${_i}+1))]}" ;;
        --only-phase)        ONLY_PHASES="${_args[$((${_i}+1))]}" ;;
        --dry-run)           DRY_RUN=true ;;
    esac
```

Replace it with (adds four cases before `esac`):

```bash
        --outdir)            OUTDIR_OVERRIDE="${_args[$((${_i}+1))]}" ;;
        --only-phase)        ONLY_PHASES="${_args[$((${_i}+1))]}" ;;
        --dry-run)           DRY_RUN=true ;;
        --spoof-send)        SPOOF_SEND=true ;;
        --spoof-to)          SPOOF_TO="${_args[$((${_i}+1))]}" ;;
        --spoof-from)        SPOOF_FROM="${_args[$((${_i}+1))]}" ;;
        --spoof-smtp)        SPOOF_SMTP="${_args[$((${_i}+1))]}" ;;
    esac
```

- [ ] **Step 2: Add the guard (require `--spoof-to` with `--spoof-send`)**

In `stiglitz.sh`, find this line:

```bash
unset _args _i
```

Insert immediately AFTER it:

```bash

# Guard: envio forjado exige destinatário explícito
if [ -n "$SPOOF_SEND" ] && [ -z "$SPOOF_TO" ]; then
    echo -e "${RED}[✗] --spoof-send requer --spoof-to <endereço>${NC}"
    exit 1
fi
```

- [ ] **Step 3: Verify syntax so far**

Run: `bash -n stiglitz.sh && echo BASH_OK`
Expected: `BASH_OK`

- [ ] **Step 4: Wire the spoof verdict into Phase 8**

In `stiglitz.sh`, find this block (inside the `if command -v dig` true-branch of Phase 8):

```bash
    echo -e "  ${GREEN}[✓] Análise de email concluída — $EMAIL_ISSUES problema(s) encontrado(s)${NC}"
else
    echo -e "  ${YELLOW}[○] dig não disponível — pulando análise de email${NC}"
fi
```

Replace it with:

```bash
    echo -e "  ${GREEN}[✓] Análise de email concluída — $EMAIL_ISSUES problema(s) encontrado(s)${NC}"

    # Verdito de spoofing (reusa registros da P8; envio é opt-in via --spoof-send)
    if [ -f "$OUTDIR/raw/email_security.json" ]; then
        SPOOF_ARGS=(--records-json "$OUTDIR/raw/email_security.json" --outdir "$OUTDIR/raw")
        if [ -n "$SPOOF_SEND" ]; then
            SPOOF_ARGS+=(--send --to "$SPOOF_TO" --roe-accept)
            [ -n "$SPOOF_FROM" ] && SPOOF_ARGS+=(--from "$SPOOF_FROM")
            [ -n "$SPOOF_SMTP" ] && SPOOF_ARGS+=(--smtp "$SPOOF_SMTP")
        fi
        python3 "$SCRIPT_DIR/email_spoof_poc.py" "$DOMAIN" "${SPOOF_ARGS[@]}" || true
        SPOOF_VERDICT=$(python3 -c "
import json
try:
    d = json.load(open('$OUTDIR/raw/spoof_evidence.json'))
    print(d.get('verdict',{}).get('status',''))
except Exception: print('')" 2>/dev/null || echo '')
    fi
else
    echo -e "  ${YELLOW}[○] dig não disponível — pulando análise de email${NC}"
fi
```

- [ ] **Step 5: Export `SPOOF_VERDICT`**

In `stiglitz.sh`, find (still in Phase 8, a few lines below):

```bash
export EMAIL_ISSUES
phase_end "P8"
```

Replace with:

```bash
export EMAIL_ISSUES SPOOF_VERDICT
phase_end "P8"
```

- [ ] **Step 6: Update the parser comment + usage hint**

In `stiglitz.sh`, find:

```bash
# Parse args: suporta --token, --header, --osint-dir, --outdir, --only-phase, --dry-run
```

Replace with:

```bash
# Parse args: --token, --header, --osint-dir, --outdir, --only-phase, --dry-run,
#             --spoof-send, --spoof-to, --spoof-from, --spoof-smtp
```

Then find this usage line:

```bash
    echo -e "  ${YELLOW}bash stiglitz.sh target.com --token <jwt>${NC}            — scan autenticado"
```

Insert immediately AFTER it:

```bash
    echo -e "  ${YELLOW}bash stiglitz.sh target.com --spoof-send --spoof-to you@box${NC} — envia spoof forjado (opt-in)"
```

- [ ] **Step 7: Verify syntax, lint, and the guard behavior**

Run:
```bash
bash -n stiglitz.sh && echo BASH_OK
shellcheck --severity=warning stiglitz.sh ; echo "shellcheck rc=$?"
bash stiglitz.sh example.com --spoof-send ; echo "guard rc=$?"
```
Expected: `BASH_OK`; shellcheck shows no NEW warnings vs. baseline (rc 0 is ideal); the guard run prints `[✗] --spoof-send requer --spoof-to <endereço>` and `guard rc=1`.

- [ ] **Step 8: Commit**

```bash
git add stiglitz.sh
git commit -m "feat(spoof): Fase 8 emite verdito de spoofing + flags --spoof-* opt-in"
```

---

## Task 3: `stiglitz_report.py` — render the spoofing verdict box

**Files:**
- Modify: `stiglitz_report.py` (load ~line 722; render ~line 1295, before `if waf_email_html:`)

- [ ] **Step 1: Load `spoof_evidence.json`**

In `stiglitz_report.py`, find:

```python
email_security = {}
_esf = os.path.join(OUTDIR,'raw','email_security.json')
if os.path.exists(_esf):
    try: email_security = json.load(open(_esf))
    except Exception as e: errors.append(f'email_security: {e}')
```

Insert immediately AFTER that block:

```python
# Spoofing verdict (enriquecimento da seção de email; NÃO vira finding)
spoof_evidence = {}
_spoof_f = os.path.join(OUTDIR,'raw','spoof_evidence.json')
if os.path.exists(_spoof_f):
    try: spoof_evidence = json.load(open(_spoof_f))
    except Exception as e: errors.append(f'spoof_evidence: {e}')
```

- [ ] **Step 2: Render the verdict box**

In `stiglitz_report.py`, find this block (the end of the Email Security table build):

```python
    waf_email_html += (f'<h3>Email Security — {html.escape(DOMAIN)}</h3>'
        '<table><tr style="background:#f5f5f5">'
        '<th>Protocol</th><th>Status</th><th>Detail</th><th>Recommendation / Value</th></tr>'
        + email_rows + '</table>')

if waf_email_html:
```

Insert the new block BETWEEN the `email_rows + '</table>')` statement and the `if waf_email_html:` line, so it reads:

```python
    waf_email_html += (f'<h3>Email Security — {html.escape(DOMAIN)}</h3>'
        '<table><tr style="background:#f5f5f5">'
        '<th>Protocol</th><th>Status</th><th>Detail</th><th>Recommendation / Value</th></tr>'
        + email_rows + '</table>')

if spoof_evidence and spoof_evidence.get('verdict'):
    _v = spoof_evidence['verdict']
    _vstatus = _v.get('status', '')
    _vcolor = {'SPOOFABLE_INBOX': '#b34e4e', 'SPOOFABLE_SPAM': '#d4833a',
               'BLOCKED_EXACT': '#27ae60', 'INDETERMINATE': '#999'}.get(_vstatus, '#999')
    _env = _v.get('forged_envelope', {})
    _spoof_html = (f'<div style="margin-top:12px;padding:10px 14px;border-left:4px solid {_vcolor};background:#fafafa">'
        f'<strong>Spoofing verdict:</strong> '
        f'<span style="background:{_vcolor};color:white;padding:2px 8px;border-radius:4px;'
        f'font-size:11px;font-weight:bold">{html.escape(_vstatus)}</span> '
        f'— {html.escape(_v.get("impact_en", ""))}'
        f'<div style="font-size:11px;color:#555;margin-top:6px">Forged envelope: '
        f'<code>MAIL FROM:&lt;{html.escape(_env.get("mail_from", ""))}&gt;</code> '
        f'<code>From: {html.escape(_env.get("header_from", ""))}</code></div>')
    _send = spoof_evidence.get('send')
    if _send and _send.get('accepted'):
        _tr = "\n".join(_send.get('smtp_transcript', []))
        _spoof_html += (f'<div style="margin-top:8px"><strong>Delivery PoC (SMTP transcript):</strong>'
            f'<pre style="background:#1e1e1e;color:#d4d4d4;padding:10px;border-radius:4px;'
            f'font-size:11px;overflow-x:auto">{html.escape(_tr)}</pre></div>')
    _spoof_html += '</div>'
    waf_email_html += _spoof_html

if waf_email_html:
```

- [ ] **Step 3: Verify it compiles**

Run: `python3 -m py_compile stiglitz_report.py && echo COMPILE_OK`
Expected: `COMPILE_OK`

- [ ] **Step 4: Smoke-test the report rendering end-to-end**

Run (creates a throwaway scan dir with the two JSON inputs, generates the report, greps for the box, cleans up):

```bash
TMPD=$(mktemp -d)
mkdir -p "$TMPD/raw"
cat > "$TMPD/raw/email_security.json" <<'JSON'
{"spf":{"status":"PERMISSIVE","severity":"high","detail":"x"},
 "dmarc":{"status":"MONITOR_ONLY","severity":"medium","policy":"none","detail":"y"},
 "dkim":{"status":"NOT_FOUND","severity":"low","detail":"z"}}
JSON
cat > "$TMPD/raw/spoof_evidence.json" <<'JSON'
{"domain":"example.com","verdict":{"status":"SPOOFABLE_INBOX",
 "impact_en":"Forged From: delivered to inbox.",
 "forged_envelope":{"mail_from":"security-test@example.com","header_from":"security-test@example.com"}},
 "send":{"accepted":true,"smtp_transcript":["CONNECTING mx1:25","DATA -> 250 ok"]}}
JSON
OUTDIR="$TMPD" DOMAIN=example.com TARGET=https://example.com python3 stiglitz_report.py >/dev/null 2>&1
grep -l "Spoofing verdict" "$TMPD"/*.html && echo "BOX_RENDERED"
grep -q "SPOOFABLE_INBOX" "$TMPD"/*.html && grep -q "DATA -&gt; 250 ok" "$TMPD"/*.html && echo "VERDICT_AND_TRANSCRIPT_OK"
rm -rf "$TMPD"
```
Expected: prints the html path, `BOX_RENDERED`, and `VERDICT_AND_TRANSCRIPT_OK`.

- [ ] **Step 5: Commit**

```bash
git add stiglitz_report.py
git commit -m "feat(spoof): relatório enriquece seção de email com verdito de spoofing"
```

---

## Task 4: Full regression + validation

**Files:** none (verification only)

- [ ] **Step 1: Run the full relevant test + lint suite**

Run:
```bash
python3 -m pytest test_email_spoof.py test_lib.py test_swarm_modules.py test_pipeline.py -q
bash -n stiglitz.sh && echo BASH_OK
shellcheck --severity=warning stiglitz.sh ; echo "shellcheck rc=$?"
python3 -m py_compile email_spoof_poc.py stiglitz_report.py
```
Expected: all pytest pass (≥178), `BASH_OK`, shellcheck no new warnings, compile clean.

- [ ] **Step 2: No commit** (verification task; prior commits already cover the work).

---

## Self-Review Notes

- **Spec coverage:** §2 `--records-json` → Task 1; §3 flags+guard+wiring+SPOOF_VERDICT → Task 2 (steps 1-6); §4 report load+box+transcript → Task 3; §5 tests/lint → Task 1 step 5, Task 2 step 7, Task 3 step 4, Task 4.
- **Name consistency:** `--records-json` → `args.records_json` (argparse dest); bash vars `SPOOF_SEND/SPOOF_TO/SPOOF_FROM/SPOOF_SMTP/SPOOF_VERDICT`; JSON keys `verdict.status`, `verdict.impact_en`, `verdict.forged_envelope.{mail_from,header_from}`, `send.accepted`, `send.smtp_transcript` — all match `email_spoof_poc.py`'s `compute_verdict`/`write_evidence` output verified in earlier work.
- **No double-count:** Task 3 appends to `waf_email_html` only; it does NOT touch `email_findings`/risk stats — matches spec §4.
- **Placeholders:** none — every step has complete code.
