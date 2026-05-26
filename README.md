# GRC & Compliance Automation

[![CI](https://github.com/n0t-intersys/security-audit-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/n0t-intersys/security-audit-framework/actions)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST CSF 2.0](https://img.shields.io/badge/NIST-CSF_2.0-005A9C)](https://www.nist.gov/cyberframework)
[![ISO 27001](https://img.shields.io/badge/ISO-27001:2022-blue)](https://www.iso.org/standard/27001)

Compliance work generates a lot of repetitive documentation. This is my attempt to automate the parts that shouldn't require a consultant — NIST CSF 2.0 maturity scoring, CIS benchmark checks, a proper risk register with likelihood/impact scoring, policy gap analysis against ISO 27001/SOC 2/HIPAA, and IR playbook generation for the five incident types I see most often.

---

## Framework Coverage

| Tool | Framework(s) | Purpose |
|------|-------------|---------|
| `nist_csf_assessor.py` | NIST CSF 2.0 | Interactive maturity scoring |
| `cis_benchmark_checker.py` | CIS Benchmark L1 | Linux hardening verification |
| `risk_register.py` | ISO 27001, SOC 2 | Risk lifecycle management |
| `policy_gap_analyzer.py` | ISO 27001, SOC 2, HIPAA | Policy coverage gap analysis |
| `incident_response_playbook_generator.py` | NIST SP 800-61r2 | IR playbook generation |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Input Layer                                │
│   JSON config  │  Interactive CLI  │  Live system reads      │
└───────────────────────────┬──────────────────────────────────┘
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
┌─────────▼────────┐ ┌──────▼───────┐ ┌───────▼──────────┐
│  nist_csf_        │ │ risk_        │ │ policy_gap_       │
│  assessor.py      │ │ register.py  │ │ analyzer.py       │
│                   │ │              │ │                   │
│  CSF functions    │ │ Likelihood × │ │  ISO / SOC2 /     │
│  Maturity 1-5     │ │ Impact matrix│ │  HIPAA mapping    │
│  JSON + MD export │ │ CSV export   │ │  Gap report MD    │
└─────────┬─────────┘ └──────────────┘ └───────────────────┘
          │
┌─────────▼──────────────────────────────────────────────────┐
│                   Output Layer                               │
│   JSON reports  │  Markdown reports  │  CSV exports         │
└────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/n0t-intersys/security-audit-framework.git
cd security-audit-framework
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# NIST CSF 2.0 assessment (demo mode)
python nist_csf_assessor.py --demo --report nist_report.md --output nist_scores.json

# Interactive NIST assessment
python nist_csf_assessor.py --output my_assessment.json --report my_report.md --org "Acme Corp"

# CIS Benchmark check (mock mode)
python cis_benchmark_checker.py --mock --output cis_report.json

# Risk Register
python risk_register.py add \
    --name "Unpatched critical RCE in production API" \
    --likelihood 4 --impact 5 \
    --owner "security@company.com" \
    --category "Vulnerability" \
    --plan "Apply vendor patch within 24 hours"

python risk_register.py list
python risk_register.py report
python risk_register.py export --output risks.csv

# Policy Gap Analysis
python policy_gap_analyzer.py \
    --org sample_outputs/org_policies.json \
    --framework iso27001 \
    --output gap_report.md

# IR Playbook Generation
python incident_response_playbook_generator.py --type ransomware --output pb_ransomware.md
python incident_response_playbook_generator.py --list
```

---

## Sample Output

### NIST CSF 2.0 Assessor

```
════════════════════════════════════════════════════════════════════════
  NIST CSF 2.0 MATURITY ASSESSMENT RESULTS
════════════════════════════════════════════════════════════════════════
  Overall Maturity Score: 2.68 / 5.00  [Risk Informed]
  Categories Scored: 22 / 22

  [GV] GOVERN             ██████████░░░░░░░░░░░░░░░░░░░░ 2.67
  [ID] IDENTIFY           ████████████░░░░░░░░░░░░░░░░░░ 2.67
  [PR] PROTECT            ████████████░░░░░░░░░░░░░░░░░░ 3.00
  [DE] DETECT             ██████████░░░░░░░░░░░░░░░░░░░░ 2.50  ⚠  GAP
  [RS] RESPOND            ████████░░░░░░░░░░░░░░░░░░░░░░ 2.25  ⚠  GAP
  [RC] RECOVER            ████████░░░░░░░░░░░░░░░░░░░░░░ 2.00  ⚠  GAP
```

### Risk Register

```
══════════════════════════════════════════════════════════════════════════════════════════
  RISK REGISTER  (4 risks)
══════════════════════════════════════════════════════════════════════════════════════════
  ID           Level         Score  Status         Owner                Name
  ──────────── ──────────    ─────  ──────────────  ──────────────────── ──────────────
  RISK-003     🔴 Critical      20  open           security@company.com  Unpatched critical RCE...
  RISK-001     🟠 High          12  mitigating     IT Team              Weak MFA enforcement...
  RISK-002     🟡 Medium         9  open           Vendor Manager       Third-party API...
  RISK-004     🟢 Low            3  accepted       CISO                 Legacy logging format...
══════════════════════════════════════════════════════════════════════════════════════════
```

---

## IR Playbooks Included

| Playbook | ID | Severity | SLA Target |
|----------|----|----------|------------|
| Ransomware | IR-PB-001 | Critical | 4-hour containment |
| Phishing | IR-PB-002 | High | 2-hour triage |
| Data Breach | IR-PB-003 | Critical | 72-hour notification |
| Insider Threat | IR-PB-004 | High | 48-hour investigation |
| DDoS | IR-PB-005 | High | 1-hour restoration |

---

## Disclaimer

This framework is for **educational and authorized internal use only**. Findings should be
treated as sensitive and handled in accordance with your organization's information
classification policy. This tool does not constitute legal or compliance advice.

---

## Running Tests

```bash
pytest tests/ -v --cov=. --cov-report=term-missing
```

---

## License

MIT — see [LICENSE](LICENSE).
