#!/usr/bin/env python3
"""
Policy Gap Analyzer — Compares an organization's policy list against required controls
for ISO 27001, SOC 2, or HIPAA. Outputs a gap report with recommended policy templates.

Usage:
    python policy_gap_analyzer.py --org sample_outputs/org_policies.json --framework iso27001
    python policy_gap_analyzer.py --org sample_outputs/org_policies.json --framework soc2
    python policy_gap_analyzer.py --org sample_outputs/org_policies.json --framework hipaa
    python policy_gap_analyzer.py --org sample_outputs/org_policies.json --framework all --output gap_report.md
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Required policy catalogs per framework
# ---------------------------------------------------------------------------

REQUIRED_POLICIES: dict[str, list[dict]] = {
    "iso27001": [
        {"id": "ISP-001", "name": "Information Security Policy", "clause": "A.5.1", "priority": "Critical"},
        {"id": "ISP-002", "name": "Acceptable Use Policy", "clause": "A.5.10", "priority": "Critical"},
        {"id": "ISP-003", "name": "Access Control Policy", "clause": "A.5.15", "priority": "Critical"},
        {"id": "ISP-004", "name": "Password / Authentication Policy", "clause": "A.5.17", "priority": "Critical"},
        {"id": "ISP-005", "name": "Asset Management Policy", "clause": "A.5.9", "priority": "High"},
        {"id": "ISP-006", "name": "Classification and Labelling Policy", "clause": "A.5.12", "priority": "High"},
        {"id": "ISP-007", "name": "Information Transfer Policy", "clause": "A.5.14", "priority": "High"},
        {"id": "ISP-008", "name": "Supplier Security Policy", "clause": "A.5.19", "priority": "High"},
        {"id": "ISP-009", "name": "Incident Management Policy", "clause": "A.5.24", "priority": "Critical"},
        {"id": "ISP-010", "name": "Business Continuity Policy", "clause": "A.5.29", "priority": "High"},
        {"id": "ISP-011", "name": "Cryptography Policy", "clause": "A.8.24", "priority": "High"},
        {"id": "ISP-012", "name": "Vulnerability Management Policy", "clause": "A.8.8", "priority": "Critical"},
        {"id": "ISP-013", "name": "Logging and Monitoring Policy", "clause": "A.8.15", "priority": "High"},
        {"id": "ISP-014", "name": "Backup and Recovery Policy", "clause": "A.8.13", "priority": "Critical"},
        {"id": "ISP-015", "name": "Change Management Policy", "clause": "A.8.32", "priority": "High"},
        {"id": "ISP-016", "name": "Network Security Policy", "clause": "A.8.20", "priority": "High"},
        {"id": "ISP-017", "name": "Secure Development Policy (SDLC)", "clause": "A.8.25", "priority": "Medium"},
        {"id": "ISP-018", "name": "Clear Desk and Screen Policy", "clause": "A.7.7", "priority": "Medium"},
        {"id": "ISP-019", "name": "Physical Security Policy", "clause": "A.7.1", "priority": "High"},
        {"id": "ISP-020", "name": "Privacy / Data Protection Policy", "clause": "A.5.34", "priority": "Critical"},
        {"id": "ISP-021", "name": "Remote Working Policy", "clause": "A.6.7", "priority": "High"},
        {"id": "ISP-022", "name": "Security Awareness Training Policy", "clause": "A.6.3", "priority": "High"},
        {"id": "ISP-023", "name": "HR Security Policy (Screening, Termination)", "clause": "A.6.1", "priority": "High"},
        {"id": "ISP-024", "name": "Risk Management Policy", "clause": "5.3", "priority": "Critical"},
        {"id": "ISP-025", "name": "Internal Audit Policy", "clause": "9.2", "priority": "High"},
    ],
    "soc2": [
        {"id": "SOC-001", "name": "Security Policy (CC1.1)", "clause": "CC1.1", "priority": "Critical"},
        {"id": "SOC-002", "name": "Access Control Policy (CC6.1)", "clause": "CC6.1", "priority": "Critical"},
        {"id": "SOC-003", "name": "Multi-Factor Authentication Policy (CC6.1)", "clause": "CC6.1", "priority": "Critical"},
        {"id": "SOC-004", "name": "Encryption Policy (CC6.7)", "clause": "CC6.7", "priority": "High"},
        {"id": "SOC-005", "name": "Incident Response Policy (CC7.3)", "clause": "CC7.3", "priority": "Critical"},
        {"id": "SOC-006", "name": "Change Management Policy (CC8.1)", "clause": "CC8.1", "priority": "High"},
        {"id": "SOC-007", "name": "Vendor Management Policy (CC9.2)", "clause": "CC9.2", "priority": "High"},
        {"id": "SOC-008", "name": "Availability / BCP Policy (A1.1)", "clause": "A1.1", "priority": "High"},
        {"id": "SOC-009", "name": "Data Processing Integrity Policy (PI1.1)", "clause": "PI1.1", "priority": "High"},
        {"id": "SOC-010", "name": "Privacy Notice and Policy (P1.1)", "clause": "P1.1", "priority": "Critical"},
        {"id": "SOC-011", "name": "Monitoring and Logging Policy (CC7.1)", "clause": "CC7.1", "priority": "High"},
        {"id": "SOC-012", "name": "Vulnerability Management Policy (CC7.1)", "clause": "CC7.1", "priority": "High"},
        {"id": "SOC-013", "name": "Risk Assessment Policy (CC3.1)", "clause": "CC3.1", "priority": "High"},
        {"id": "SOC-014", "name": "Background Check / HR Policy (CC1.4)", "clause": "CC1.4", "priority": "Medium"},
        {"id": "SOC-015", "name": "Security Awareness Training Policy (CC1.4)", "clause": "CC1.4", "priority": "High"},
    ],
    "hipaa": [
        {"id": "HIP-001", "name": "Privacy Policy (45 CFR 164.520)", "clause": "§164.520", "priority": "Critical"},
        {"id": "HIP-002", "name": "Security Policy (45 CFR 164.306)", "clause": "§164.306", "priority": "Critical"},
        {"id": "HIP-003", "name": "Access Control Policy (45 CFR 164.312(a))", "clause": "§164.312(a)(1)", "priority": "Critical"},
        {"id": "HIP-004", "name": "Audit Controls Policy (45 CFR 164.312(b))", "clause": "§164.312(b)", "priority": "Critical"},
        {"id": "HIP-005", "name": "Integrity Controls Policy (45 CFR 164.312(c))", "clause": "§164.312(c)(1)", "priority": "High"},
        {"id": "HIP-006", "name": "Transmission Security Policy (45 CFR 164.312(e))", "clause": "§164.312(e)(1)", "priority": "Critical"},
        {"id": "HIP-007", "name": "Breach Notification Policy (45 CFR 164.400)", "clause": "§164.400", "priority": "Critical"},
        {"id": "HIP-008", "name": "Workforce Training Policy (45 CFR 164.530(b))", "clause": "§164.530(b)", "priority": "High"},
        {"id": "HIP-009", "name": "Sanction Policy (45 CFR 164.530(e))", "clause": "§164.530(e)", "priority": "High"},
        {"id": "HIP-010", "name": "Business Associate Agreement Policy (45 CFR 164.308(b))", "clause": "§164.308(b)", "priority": "Critical"},
        {"id": "HIP-011", "name": "Risk Analysis and Management Policy (45 CFR 164.308(a)(1))", "clause": "§164.308(a)(1)", "priority": "Critical"},
        {"id": "HIP-012", "name": "Contingency Plan Policy (45 CFR 164.308(a)(7))", "clause": "§164.308(a)(7)", "priority": "High"},
        {"id": "HIP-013", "name": "Device and Media Controls Policy (45 CFR 164.310(d))", "clause": "§164.310(d)", "priority": "High"},
        {"id": "HIP-014", "name": "Minimum Necessary Policy (45 CFR 164.514(d))", "clause": "§164.514(d)", "priority": "High"},
    ],
}

POLICY_TEMPLATES: dict[str, str] = {
    "Information Security Policy": "Define the organization's overall commitment to information security, roles, responsibilities, and consequences for violations.",
    "Acceptable Use Policy": "Define permitted and prohibited uses of company IT resources, including internet, email, and devices.",
    "Access Control Policy": "Define how access to systems and data is granted, reviewed, and revoked based on least privilege and need-to-know.",
    "Incident Management Policy": "Define the process for detecting, reporting, investigating, and resolving security incidents.",
    "Vulnerability Management Policy": "Define how the organization identifies, prioritizes, and remediates security vulnerabilities in systems and software.",
    "Backup and Recovery Policy": "Define backup frequency, retention, testing, and restoration procedures for critical data and systems.",
    "Privacy / Data Protection Policy": "Define how personal data is collected, processed, stored, and protected in compliance with applicable regulations.",
}


@dataclass
class PolicyGap:
    required_id: str
    required_name: str
    clause: str
    priority: str
    status: str          # "covered" | "partial" | "missing"
    matched_policy: str = ""
    template: str = ""

    @property
    def is_gap(self) -> bool:
        return self.status != "covered"


def load_org_policies(path: Path) -> list[dict]:
    with path.open() as fh:
        data = json.load(fh)
    return data.get("policies", data) if isinstance(data, dict) else data


def analyze_gaps(org_policies: list[dict], framework: str) -> list[PolicyGap]:
    required = REQUIRED_POLICIES.get(framework, [])
    org_names_lower = [p.get("name", "").lower() for p in org_policies]

    gaps = []
    for req in required:
        req_words = set(req["name"].lower().replace("(", "").replace(")", "").split())
        req_words -= {"policy", "the", "and", "or", "of", "for", "a", "an"}

        best_match = ""
        best_score = 0
        for org_name in org_names_lower:
            org_words = set(org_name.replace("(", "").replace(")", "").split())
            intersection = req_words & org_words
            score = len(intersection) / max(len(req_words), 1)
            if score > best_score:
                best_score = score
                best_match = org_name

        if best_score >= 0.6:
            status = "covered"
        elif best_score >= 0.3:
            status = "partial"
        else:
            status = "missing"

        template = POLICY_TEMPLATES.get(req["name"], f"Develop a {req['name']} addressing {req['clause']} requirements.")
        gaps.append(PolicyGap(
            required_id=req["id"],
            required_name=req["name"],
            clause=req["clause"],
            priority=req["priority"],
            status=status,
            matched_policy=best_match if status in ("covered", "partial") else "",
            template=template,
        ))

    return gaps


def print_gap_report(gaps: list[PolicyGap], framework: str) -> None:
    covered = [g for g in gaps if g.status == "covered"]
    partial = [g for g in gaps if g.status == "partial"]
    missing = [g for g in gaps if g.status == "missing"]
    critical_missing = [g for g in missing if g.priority == "Critical"]

    print(f"\n{'═'*75}")
    print(f"  POLICY GAP ANALYSIS  |  Framework: {framework.upper()}")
    print(f"{'═'*75}")
    print(f"  Required  : {len(gaps)} policies")
    print(f"  ✅ Covered : {len(covered)}")
    print(f"  🟡 Partial : {len(partial)}")
    print(f"  🔴 Missing : {len(missing)} ({len(critical_missing)} Critical)")
    print(f"  Coverage  : {100 * len(covered) // len(gaps)}%")
    print(f"{'─'*75}")

    if missing:
        print(f"\n  MISSING POLICIES:")
        for g in sorted(missing, key=lambda x: (x.priority != "Critical", x.required_id)):
            icon = "🔴" if g.priority == "Critical" else "🟠" if g.priority == "High" else "🟡"
            print(f"  {icon} [{g.required_id}] {g.required_name} ({g.clause})")

    if partial:
        print(f"\n  PARTIAL COVERAGE (review and expand):")
        for g in partial:
            print(f"  🟡 [{g.required_id}] {g.required_name} → matched: '{g.matched_policy}'")

    print(f"\n{'═'*75}\n")


def generate_gap_report_md(gaps_by_framework: dict[str, list[PolicyGap]], org_name: str) -> str:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"# Policy Gap Analysis Report",
        f"",
        f"| | |",
        f"|---|---|",
        f"| **Organization** | {org_name} |",
        f"| **Date** | {now} |",
        f"| **Frameworks** | {', '.join(gaps_by_framework.keys()).upper()} |",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"| Framework | Required | Covered | Partial | Missing | Coverage |",
        f"|-----------|----------|---------|---------|---------|----------|",
    ]

    for fw, gaps in gaps_by_framework.items():
        covered = sum(1 for g in gaps if g.status == "covered")
        partial = sum(1 for g in gaps if g.status == "partial")
        missing = sum(1 for g in gaps if g.status == "missing")
        pct = 100 * covered // len(gaps) if gaps else 0
        lines.append(f"| **{fw.upper()}** | {len(gaps)} | {covered} | {partial} | {missing} | {pct}% |")

    for fw, gaps in gaps_by_framework.items():
        missing = [g for g in gaps if g.status == "missing"]
        if missing:
            lines += ["", f"---", f"", f"## {fw.upper()} — Missing Policies", ""]
            lines += [
                "| Priority | Policy ID | Policy Name | Clause | Recommended Action |",
                "|----------|-----------|-------------|--------|--------------------|",
            ]
            for g in sorted(missing, key=lambda x: (x.priority != "Critical", x.required_id)):
                lines.append(f"| {g.priority} | `{g.required_id}` | {g.required_name} | {g.clause} | {g.template[:80]} |")

    lines += ["", "---", "", f"*Generated by security-audit-framework · {now}*"]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare org policy list against framework requirements and identify gaps.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--org", type=Path, required=True, help="Org policies JSON file")
    parser.add_argument("--framework", choices=["iso27001", "soc2", "hipaa", "all"], default="iso27001")
    parser.add_argument("--output", type=Path, help="Write Markdown gap report to file")
    parser.add_argument("--org-name", default="Your Organization")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.org.exists():
        logger.error("Organization policies file not found: %s", args.org)
        return 1

    org_policies = load_org_policies(args.org)
    logger.info("Loaded %d organizational policies", len(org_policies))

    frameworks = list(REQUIRED_POLICIES.keys()) if args.framework == "all" else [args.framework]
    gaps_by_framework: dict[str, list[PolicyGap]] = {}

    for fw in frameworks:
        gaps = analyze_gaps(org_policies, fw)
        gaps_by_framework[fw] = gaps
        print_gap_report(gaps, fw)

    if args.output:
        md = generate_gap_report_md(gaps_by_framework, args.org_name)
        args.output.write_text(md)
        logger.info("Gap report written to %s", args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
