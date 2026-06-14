# Design — Compliance Mapping só-PCI (PASS/FAIL/N-A)

**Data:** 2026-06-14
**Status:** Aprovado e implementado
**Contexto:** Red team / pentest autorizado (RoE assinado). Console/operador em PT-BR;
campos de relatório/JSON destinados a deliverable em EN (convenção do suite).

> **Nota de escopo:** este design originalmente acompanhava uma reformulação da POC de
> email spoof (`email_spoof_poc.py`). Aquela frente foi revertida do scan e será
> construída em paralelo, fora desta composição. Este spec ficou restrito ao Compliance
> Mapping.

---

## 1. Motivação

A seção "Compliance Mapping" do relatório (`stiglitz_report.py`) mostrava todos os
frameworks (OWASP/ASVS/PCI/ISO/NIST) com contagem de findings por controle. O pedido:
foco em **PCI DSS 4.0.1**, com veredito **PASS/FAIL/N-A** por requisito e **resumo
breve**.

---

## 2. Compliance Mapping só-PCI (PASS/FAIL/N-A)

Repagina **apenas** a seção "Compliance Mapping" (`stiglitz_report.py:~2213-2230`). A
seção "PCI DSS CDE Coverage" (linhas ~2193-2211) permanece intacta.

### 2.1 Regra de veredito por requisito PCI

Universo = requisitos PCI que o scanner consegue exercitar: união dos valores `pci` do
crosswalk `compliance_map._MAP` com os requisitos de `pci_verdicts.py`
(`2.2.1, 2.2.5, 3.2, 4.2.1, 6.2.4, 6.3.3, 7.2.1, 8.3.1, 8.3.4, 8.6.1, 10.2.1`).

Para cada requisito do universo:
1. **FAIL** — ≥1 finding mapeado (via CWE→`pci` **ou** via `pci_req` do CDE).
2. **PASS** — sem finding **e** o sinal de cobertura presente (capacidade rodou).
3. **N/A** — capacidade não exercida. Default conservador: na dúvida, **N/A** (nunca
   PASS falso — mesma filosofia anti-"0 High enganoso").

### 2.2 Mapa requisito → sinal de cobertura

| Req | Capacidade | Sinal de "rodou" (em `raw/`) |
|-----|-----------|------------------------------|
| 2.2.1 | Hardening/misconfig | `security_headers.json` ou findings nuclei |
| 2.2.5 | Serviços de rede expostos | `service_findings.json` (nmap `-sV`) |
| 3.2   | Proteção de dados no CDE | escopo CDE ativo (há findings com `pci_req`) |
| 4.2.1 | TLS forte | `testssl.json` presente |
| 6.2.4 | App seguro (injeção/XSS/CSRF/SSRF) | findings nuclei/ZAP presentes |
| 6.3.3 | Componentes atualizados | nuclei (cve/tech) presente |
| 7.2.1 | Controle de acesso | scan autenticado (`access_control.json`) |
| 8.3.1 / 8.3.4 / 8.6.1 | Autenticação | scan autenticado (`access_control.json`) |
| 10.2.1 | Logging/monitoring | só FAIL se houver finding; senão N/A (DAST não exercita) |

Sem token → access control/autenticação = **N/A**, não PASS.

### 2.3 Implementação

- **`lib/compliance_map.py`** — função pura
  `pci_posture(findings, coverage) -> list[{req, verdict, count, top_findings}]`.
  `coverage` é um dict de flags booleanas. Sem rede/arquivo; recebe tudo pronto.
- **`stiglitz_report.py`** — deriva `coverage` da presença de artefatos em `raw/`, chama
  `pci_posture`, e renderiza:
  - **resumo** (uma linha): `PCI DSS 4.0.1 — N requirements assessed: X FAIL, Y PASS,
    Z N/A. Top gaps: <req (count)> ...`
  - **tabela** PASS/FAIL/N-A por requisito, com contagem e títulos dos findings de topo
    nos requisitos FAIL.

### 2.4 Testes

- `pci_posture` (`tests/test_compliance_map.py`): FAIL com finding; PASS com cobertura
  sem finding; N/A sem cobertura; N/A para access control sem token; precedência FAIL
  sobre cobertura; ordenação numérica; top_findings só em FAIL.

---

## 3. Fora de escopo (YAGNI)

- **Mudar a severidade do `lib/email_security.py`** — o verdito de DNS continua válido
  como risco. Não alterar sem pedido explícito.
- **Listar requisitos PCI fora do universo do scanner** — ruído; a tabela cobre só o
  que o scanner endereça.
