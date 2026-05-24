#!/usr/bin/env python3
"""
Incident Response Playbook Generator — Generates step-by-step IR playbooks
in Markdown format for common incident types.

Incident types: ransomware, phishing, data_breach, insider_threat, ddos

Usage:
    python incident_response_playbook_generator.py --type ransomware
    python incident_response_playbook_generator.py --type phishing --output pb_phishing.md
    python incident_response_playbook_generator.py --type data_breach --org "ACME Corp" --severity critical
    python incident_response_playbook_generator.py --list
"""

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Playbook definitions
# ---------------------------------------------------------------------------

PLAYBOOKS: dict[str, dict] = {
    "ransomware": {
        "name": "Ransomware Attack",
        "id": "IR-PB-001",
        "severity": "Critical",
        "sla": "4-hour containment target",
        "overview": (
            "Ransomware encrypts organizational data and/or systems to extort payment. "
            "The primary objectives are to contain the spread, preserve forensic evidence, "
            "restore operations from clean backups, and prevent re-infection."
        ),
        "indicators": [
            "Files renamed with unfamiliar extensions (e.g., .locked, .encrypted, .WNCRY)",
            "Ransom note files (README.txt, DECRYPT_INSTRUCTIONS.html) appearing on desktops",
            "EDR/antivirus alerts for mass file encryption activity",
            "Unusual process executing crypto operations (e.g., vssadmin delete shadows)",
            "Network segmentation alerts or unusual east-west traffic spikes",
            "Users unable to open files or receive 'file is corrupted' errors",
        ],
        "phases": [
            {
                "name": "DETECTION & INITIAL TRIAGE",
                "steps": [
                    "Receive alert from EDR, SIEM, or user report — log timestamp and source",
                    "Identify the affected host(s): hostname, IP, user account, department",
                    "Confirm ransomware indicators: encrypted files, ransom note, EDR telemetry",
                    "Escalate immediately to Security Lead and Incident Commander — open a P1 ticket",
                    "Notify management: CISO, IT Director, Legal (do NOT notify law enforcement yet)",
                    "Stand up the Incident Response bridge/war room call",
                ],
            },
            {
                "name": "CONTAINMENT",
                "steps": [
                    "**IMMEDIATE**: Isolate affected host(s) from the network — disable NIC or apply firewall quarantine rule",
                    "Disable affected AD user account(s) to prevent lateral movement via compromised credentials",
                    "Block C2 IOCs (IPs/domains) at perimeter firewall and DNS sinkhole",
                    "Identify patient zero: review EDR process tree, network logs for initial infection vector",
                    "Assess blast radius: scan for additional encrypted systems using EDR fleet-wide query",
                    "Disable SMB and RDP temporarily if lateral movement via these protocols is suspected",
                    "Preserve forensic state: take memory dump and disk image of affected host before reimaging",
                    "Revoke and rotate service account credentials that may have been exposed",
                ],
            },
            {
                "name": "ERADICATION",
                "steps": [
                    "Identify the specific ransomware variant using: ransom note content, file extension, ID Ransomware tool",
                    "Search all systems for the initial dropper / loader — quarantine or delete",
                    "Purge ransomware binaries, persistence mechanisms (scheduled tasks, registry run keys, services)",
                    "Patch the exploited vulnerability or close the attack vector (VPN creds, RDP exposure, phishing template)",
                    "Reset ALL potentially compromised credentials: local admin, domain admin, service accounts",
                    "Remove any rogue accounts or persistence added by threat actor",
                    "Block all identified IOCs organization-wide (IPs, hashes, domains)",
                ],
            },
            {
                "name": "RECOVERY",
                "steps": [
                    "Identify the last known-good backup — verify integrity before restoring",
                    "Restore from backup to clean, re-imaged systems (NOT back onto the same OS installation)",
                    "Validate restored data integrity: checksums, business functionality testing",
                    "Rebuild affected systems from golden image where restoration is not feasible",
                    "Gradually reconnect restored systems to the network — monitor closely for 72 hours",
                    "Conduct post-recovery scan using EDR and AV before returning to production",
                    "Re-enable disabled accounts only after credential rotation is confirmed",
                ],
            },
            {
                "name": "POST-INCIDENT",
                "steps": [
                    "Conduct post-incident review within 5 business days — all IR team members",
                    "Document full timeline: detection → containment → eradication → recovery",
                    "Identify root cause and contributing factors",
                    "Determine regulatory notification requirements: GDPR (72 hrs), state breach laws, HIPAA (60 days)",
                    "Evaluate cyber insurance policy — notify insurer if applicable",
                    "Update detection rules, SIEM correlation, EDR policies based on IOCs from this incident",
                    "Implement preventive controls identified during review (MFA, backup hardening, EDR tuning)",
                    "Brief executive leadership on incident summary, impact, and remediation roadmap",
                ],
            },
        ],
        "escalation": [
            ("0-15 min",  "Security Analyst detects and triages"),
            ("15-30 min", "Security Lead notified — P1 ticket opened"),
            ("30-60 min", "CISO, IT Director, Legal notified — war room opened"),
            ("1-4 hrs",   "Containment actions completed"),
            ("4-24 hrs",  "Eradication underway — executive briefing"),
            ("24-72 hrs", "Recovery phase — regulatory notification assessment"),
            ("5 days",    "Post-incident review completed"),
        ],
        "tools": ["CrowdStrike Falcon (EDR)", "ID Ransomware (variant ID)", "FTK Imager (forensics)", "Velociraptor (DFIR)"],
        "references": ["NIST SP 800-61r2", "CISA Ransomware Guide", "MS-ISAC Ransomware Playbook"],
    },
    "phishing": {
        "name": "Phishing / Spear Phishing",
        "id": "IR-PB-002",
        "severity": "High",
        "sla": "2-hour triage target",
        "overview": (
            "Phishing attacks attempt to steal credentials, deliver malware, or enable fraud via "
            "deceptive emails. Scope varies from broad campaigns to targeted spear phishing. "
            "Key concern: credential harvesting and downstream account compromise."
        ),
        "indicators": [
            "User reports suspicious email asking for credentials or with unexpected attachment",
            "Email gateway alert for spoofed sender domain or failed SPF/DKIM/DMARC",
            "Unusual login from new geolocation immediately after phishing email received",
            "Identity protection alert for impossible travel or new device registration",
            "Credential posted on dark web threat intel feeds matching company domain",
            "Click-through detected by email security on tracked malicious URL",
        ],
        "phases": [
            {
                "name": "DETECTION & TRIAGE",
                "steps": [
                    "Receive user report, email security alert, or identity protection alert",
                    "Assess: did the user click a link? Enter credentials? Open an attachment?",
                    "Retrieve email headers and analyze: sender IP, return-path, SPF/DKIM/DMARC result",
                    "Extract and detonate URLs in a sandbox (VirusTotal, Any.run, Joe Sandbox)",
                    "Search email gateway logs for same sender/subject across all mailboxes",
                    "Determine campaign scope: is this isolated or organization-wide?",
                ],
            },
            {
                "name": "CONTAINMENT",
                "steps": [
                    "Block sender domain and IP at email gateway",
                    "Remove the phishing email from all mailboxes using eDiscovery/purge",
                    "Block malicious URLs/domains at proxy and DNS layer",
                    "If credentials entered: immediately reset affected account password and revoke sessions",
                    "Enable MFA on affected account if not already enabled",
                    "If malware delivered: escalate to Malware IR track — isolate host",
                    "Notify all recipients who may have received the email",
                ],
            },
            {
                "name": "ERADICATION",
                "steps": [
                    "Audit all actions taken by compromised account: email forwarding rules, OAuth grants, file access",
                    "Revoke unauthorized OAuth applications and mail forwarding rules",
                    "Check for business email compromise (BEC): vendor payment changes, wire transfers requested",
                    "Verify no persistence established (new inbox rules, auto-replies to attacker)",
                    "Update email filtering rules with new sender/subject/URL signatures",
                ],
            },
            {
                "name": "RECOVERY",
                "steps": [
                    "Restore user account access after credential reset and MFA enrollment",
                    "Verify no unauthorized changes to financial systems or vendor records",
                    "Resume normal email delivery after confirming threat is eliminated",
                    "Monitor affected account for 30 days post-incident",
                ],
            },
            {
                "name": "POST-INCIDENT",
                "steps": [
                    "Update phishing simulation campaigns to include TTPs from this incident",
                    "Brief users who were targeted — conduct targeted security awareness training",
                    "Evaluate email security tooling: DMARC enforcement, ATP link detonation",
                    "Document indicators and share with ISAC or threat intel sharing partners",
                    "Assess GDPR/regulatory notification need if credentials or PII were compromised",
                ],
            },
        ],
        "escalation": [
            ("0-30 min",  "Analyst triages — assess if credentials were entered"),
            ("30 min",    "Security Lead notified — purge campaign from mailboxes"),
            ("1-2 hrs",   "Containment complete — affected accounts reset"),
            ("2-4 hrs",   "Scope assessment — identify all affected users"),
            ("24 hrs",    "Post-incident review initiated"),
        ],
        "tools": ["Microsoft Defender for Office 365", "VirusTotal", "MXToolbox (header analysis)", "Sublime Security"],
        "references": ["NIST SP 800-61r2", "CISA Phishing Guidance", "Anti-Phishing Working Group (APWG)"],
    },
    "data_breach": {
        "name": "Data Breach / Unauthorized Disclosure",
        "id": "IR-PB-003",
        "severity": "Critical",
        "sla": "72-hour regulatory notification assessment",
        "overview": (
            "A data breach involves unauthorized access to, or disclosure of, sensitive, protected, "
            "or confidential data. Regulatory notification requirements (GDPR, HIPAA, state breach laws) "
            "impose strict timelines. Legal counsel must be engaged immediately."
        ),
        "indicators": [
            "DLP alert for large data transfer to external destination",
            "Database query anomaly: bulk SELECT on PII tables by non-standard account",
            "Cloud storage bucket misconfiguration alert — public S3/Blob exposure detected",
            "Third-party notification that company data was found for sale on dark web",
            "Unauthorized API access to customer data endpoints",
            "User report of receiving other customers' data",
        ],
        "phases": [
            {
                "name": "DETECTION & INITIAL TRIAGE",
                "steps": [
                    "Identify the data involved: type (PII, PHI, PCI, IP), volume, and affected individuals",
                    "Determine the breach vector: misconfiguration, insider threat, external attack, third party",
                    "Preserve evidence: do NOT delete logs or modify systems before forensic capture",
                    "Immediately engage Legal / General Counsel — this is a legally privileged investigation",
                    "Notify CISO and executive leadership within 1 hour of confirmed breach",
                    "Open a P1 confidential incident ticket — restrict access to need-to-know",
                ],
            },
            {
                "name": "CONTAINMENT",
                "steps": [
                    "Stop the ongoing exposure immediately: close misconfigured storage, revoke API keys, block exfil IP",
                    "Revoke credentials of any account involved in the unauthorized access",
                    "Identify all systems that touched or processed the exposed data",
                    "Preserve forensic evidence before taking remediation actions",
                    "Implement additional monitoring on systems containing sensitive data",
                    "If third-party vendor involved: notify vendor, request their IR process activation",
                ],
            },
            {
                "name": "ERADICATION",
                "steps": [
                    "Patch or remediate the root cause vulnerability",
                    "Verify no additional copies of exfiltrated data remain accessible",
                    "Audit all access to affected data stores for the breach window period",
                    "Identify all individuals whose data was involved — prepare notification list",
                    "Engage forensics firm if scope is large or law enforcement involvement is anticipated",
                ],
            },
            {
                "name": "RECOVERY",
                "steps": [
                    "Restore data integrity if data was modified or deleted",
                    "Implement additional controls: encryption, tokenization, DLP tuning",
                    "Re-enable access to affected systems only after security review",
                    "Provide identity monitoring services to affected individuals if PII was involved",
                ],
            },
            {
                "name": "REGULATORY NOTIFICATION",
                "steps": [
                    "**GDPR**: If EU personal data affected — notify supervisory authority within 72 hours of discovery",
                    "**HIPAA**: If PHI affected — notify affected individuals within 60 days; HHS if 500+ affected",
                    "**State Laws**: Assess applicable state breach notification laws (CA CCPA, NY SHIELD, etc.)",
                    "**PCI DSS**: If cardholder data affected — notify card brands and acquiring bank immediately",
                    "Prepare individual notification letters — reviewed by Legal before sending",
                    "Prepare regulatory notification filings with Legal",
                ],
            },
            {
                "name": "POST-INCIDENT",
                "steps": [
                    "Conduct full post-incident review — root cause, contributing factors, regulatory timeline met",
                    "Implement DLP, CASB, and data classification improvements",
                    "Review third-party access and data sharing agreements",
                    "Assess cyber insurance claim if applicable",
                    "Update privacy impact assessments and data processing records",
                ],
            },
        ],
        "escalation": [
            ("0-1 hr",    "CISO and Legal notified — P1 opened"),
            ("1-4 hrs",   "Containment — breach vector closed"),
            ("4-24 hrs",  "Scope and regulatory assessment"),
            ("24-72 hrs", "Regulatory notification decision point"),
            ("72 hrs",    "GDPR notification deadline if EU data involved"),
            ("5 days",    "Post-incident review"),
        ],
        "tools": ["DLP Platform", "CASB (Cloud Access Security Broker)", "AWS Macie / Azure Purview", "Kroll / Mandiant (forensics)"],
        "references": ["GDPR Article 33", "HIPAA Breach Notification Rule", "NIST SP 800-61r2", "HHS Breach Notification Guidance"],
    },
    "insider_threat": {
        "name": "Insider Threat",
        "id": "IR-PB-004",
        "severity": "High",
        "sla": "48-hour investigation initiation",
        "overview": (
            "Insider threats involve current or former employees, contractors, or partners misusing "
            "authorized access to harm the organization. Motivations include financial gain, espionage, "
            "sabotage, or disgruntlement. Investigations require HR and Legal involvement."
        ),
        "indicators": [
            "DLP alert: bulk download of sensitive files to personal device or cloud storage",
            "UEBA alert: unusual access patterns — after-hours access, atypical data volumes",
            "Manager reports employee attempting to exfiltrate files before departure",
            "Email gateway alert: forwarding sensitive data to personal email account",
            "IT detects installation of unauthorized data transfer tools (Dropbox, USB enabler)",
            "Threat intel feed indicates employee credentials being sold or offered",
        ],
        "phases": [
            {
                "name": "DETECTION & TRIAGE",
                "steps": [
                    "Receive alert from UEBA, DLP, manager tip, or SIEM correlation",
                    "Do NOT alert the suspected insider at this stage — maintain confidentiality",
                    "Engage HR Business Partner and Legal immediately — confidential investigation",
                    "Collect and preserve evidence quietly: email logs, DLP logs, file access logs, badge access",
                    "Determine if immediate threat to systems or data exists — assess urgency",
                    "Assign a dedicated investigator — restrict case knowledge to minimum necessary",
                ],
            },
            {
                "name": "CONTAINMENT (covert)",
                "steps": [
                    "If imminent harm: escalate immediately to HR/Legal for emergency account suspension",
                    "If ongoing investigation: implement covert monitoring per company policy and legal advice",
                    "Quietly restrict access to high-value data without alerting the subject",
                    "Place email/DLP holds on subject's communications",
                    "Monitor for continued exfiltration attempts — do not block until authorized by Legal",
                    "Identify all data accessed or taken: file names, volumes, destinations",
                ],
            },
            {
                "name": "INVESTIGATION",
                "steps": [
                    "Reconstruct timeline of suspicious activity from earliest indicator",
                    "Identify all data accessed, copied, or transmitted",
                    "Determine if external parties were involved (competitor, foreign government)",
                    "Interview witnesses only as directed by Legal — document all interviews",
                    "Preserve chain of custody for all evidence (chain of custody documentation)",
                    "Determine if criminal referral to law enforcement is appropriate",
                ],
            },
            {
                "name": "ERADICATION & RECOVERY",
                "steps": [
                    "Coordinate account termination with HR for confirmed insider threat cases",
                    "Revoke all access immediately upon termination — physical and logical",
                    "Recover or remotely wipe company devices",
                    "Request return of all company data from personal accounts where legally permissible",
                    "Assess and remediate any backdoors or changes made by the insider",
                    "Notify affected parties if data was exfiltrated (per Legal guidance)",
                ],
            },
            {
                "name": "POST-INCIDENT",
                "steps": [
                    "Review and strengthen offboarding / access revocation procedures",
                    "Improve UEBA baselines and DLP policies based on discovered TTPs",
                    "Conduct security awareness training for managers on warning signs",
                    "Assess whether termination and access revocation timing can be improved",
                    "Consider civil/criminal legal action — per Legal guidance",
                ],
            },
        ],
        "escalation": [
            ("0-4 hrs",   "Initial triage — HR and Legal engaged"),
            ("4-24 hrs",  "Evidence preservation — covert monitoring if authorized"),
            ("24-48 hrs", "Full investigation underway"),
            ("48-72 hrs", "Containment decision — HR action if warranted"),
            ("5-10 days", "Post-incident review and process improvements"),
        ],
        "tools": ["UEBA Platform (Securonix, Exabeam)", "DLP", "eDiscovery (M365 Compliance)", "Forensic Toolkit"],
        "references": ["CERT Insider Threat Center", "NIST SP 800-61r2", "CISA Insider Threat Mitigation Guide"],
    },
    "ddos": {
        "name": "Distributed Denial of Service (DDoS)",
        "id": "IR-PB-005",
        "severity": "High",
        "sla": "1-hour service restoration target",
        "overview": (
            "A DDoS attack overwhelms target systems with traffic, causing service degradation or outage. "
            "Types include volumetric (UDP flood), protocol (SYN flood), and application layer (HTTP flood). "
            "Goal is rapid mitigation while preserving forensic data for attribution."
        ),
        "indicators": [
            "NOC alert: interface utilization > 95% without corresponding business event",
            "Application monitoring: error rate spike, latency > baseline × 5",
            "ISP notification of anomalous traffic targeting your IP block",
            "Firewall/IDS alert: massive SYN packets, UDP amplification traffic",
            "Customer reports: website/application unreachable",
            "DNS resolution failures for company domains",
        ],
        "phases": [
            {
                "name": "DETECTION & TRIAGE",
                "steps": [
                    "Confirm DDoS vs. organic traffic spike vs. infrastructure failure",
                    "Identify attack type: volumetric, protocol, or application layer",
                    "Determine target: which IP(s), services, or applications are affected",
                    "Notify Network/Infrastructure team and Security Lead — open P1",
                    "Engage CDN/DDoS protection provider (Cloudflare, Akamai, AWS Shield) immediately",
                    "Notify ISP — request traffic characterization and upstream filtering",
                ],
            },
            {
                "name": "CONTAINMENT",
                "steps": [
                    "Activate DDoS mitigation service (cloud scrubbing, BGP blackhole, anycast)",
                    "Apply ACLs or rate limiting at perimeter to block known attack source ranges",
                    "Enable geo-blocking if attack is concentrated from specific regions (confirm with business)",
                    "Redirect traffic through scrubbing center if CDN/mitigation provider supports it",
                    "Scale up capacity: auto-scaling groups, CDN caching, load balancer capacity",
                    "Implement Captcha challenges for application-layer attacks (HTTP flood)",
                    "Preserve traffic samples for forensic analysis (5-minute PCAP captures)",
                ],
            },
            {
                "name": "ERADICATION",
                "steps": [
                    "Work with ISP to null-route attack traffic upstream",
                    "Identify and block botnet C2 infrastructure (if attackers are using known botnets)",
                    "Tune WAF rules to block application-layer attack patterns",
                    "Implement network-level rate limiting at ISP or carrier level",
                ],
            },
            {
                "name": "RECOVERY",
                "steps": [
                    "Gradually restore services while monitoring for attack continuation",
                    "Verify all services are fully operational: DNS, web, email, API endpoints",
                    "Remove emergency mitigation controls (geo-blocks) only after attack is confirmed stopped",
                    "Monitor for 24-48 hours post-mitigation — attacks often resume",
                    "Communicate status to affected customers/stakeholders",
                ],
            },
            {
                "name": "POST-INCIDENT",
                "steps": [
                    "Document attack timeline, type, volume, and source characteristics",
                    "Evaluate DDoS protection architecture — gaps in coverage",
                    "Review ISP upstream filtering agreements",
                    "Evaluate redundancy: multi-ISP, anycast DNS, CDN coverage",
                    "Assess whether attack was a smokescreen for another attack (common tactic)",
                    "File incident report with ISP and consider law enforcement if attributable",
                ],
            },
        ],
        "escalation": [
            ("0-15 min",  "NOC detects — Network team alerted"),
            ("15 min",    "DDoS mitigation service activated"),
            ("15-30 min", "ISP upstream filtering requested"),
            ("30-60 min", "Service restoration target"),
            ("60+ min",   "Escalate to CISO if mitigation ineffective"),
            ("24 hrs",    "Post-incident review"),
        ],
        "tools": ["Cloudflare / Akamai / AWS Shield", "BGP Blackhole (RTBH)", "NetFlow/IPFIX analysis", "Arbor Networks"],
        "references": ["CISA DDoS Quick Guide", "RFC 7999 (BLACKHOLE)", "MS-ISAC DDoS Playbook"],
    },
}


def generate_playbook_md(
    incident_type: str,
    org_name: str,
    severity_override: str | None = None,
) -> str:
    pb = PLAYBOOKS[incident_type]
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    severity = severity_override or pb["severity"]

    lines = [
        f"# Incident Response Playbook: {pb['name']}",
        f"",
        f"> **Playbook ID**: {pb['id']}  ",
        f"> **Classification**: CONFIDENTIAL — Internal Use Only  ",
        f"> **Organization**: {org_name}  ",
        f"> **Severity**: {severity}  ",
        f"> **SLA Target**: {pb['sla']}  ",
        f"> **Generated**: {now}",
        f"",
        f"---",
        f"",
        f"## Overview",
        f"",
        pb["overview"],
        f"",
        f"---",
        f"",
        f"## Detection Indicators (IOCs / Triggers)",
        f"",
    ]

    for ioc in pb["indicators"]:
        lines.append(f"- {ioc}")

    lines += ["", "---", ""]

    for phase in pb["phases"]:
        lines.append(f"## Phase: {phase['name']}")
        lines.append("")
        for i, step in enumerate(phase["steps"], 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append("---")
        lines.append("")

    lines += [
        "## Escalation Timeline",
        "",
        "| Timeframe | Action |",
        "|-----------|--------|",
    ]
    for timeframe, action in pb["escalation"]:
        lines.append(f"| **{timeframe}** | {action} |")

    lines += [
        "",
        "---",
        "",
        "## Tools & Resources",
        "",
    ]
    for tool in pb["tools"]:
        lines.append(f"- {tool}")

    lines += [
        "",
        "## References",
        "",
    ]
    for ref in pb["references"]:
        lines.append(f"- {ref}")

    lines += [
        "",
        "---",
        "",
        "## Approval & Review",
        "",
        "| Role | Name | Date |",
        "|------|------|------|",
        "| **CISO / Security Lead** | | |",
        "| **IT Director** | | |",
        "| **Legal Counsel** | | |",
        "| **Last Review** | | |",
        "| **Next Review** | Annual or after incident | |",
        "",
        "---",
        "",
        f"*This playbook is for authorized incident response personnel. Distribution restricted.*  ",
        f"*{pb['id']} · security-audit-framework · {now}*",
    ]

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate incident response playbooks in Markdown.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--type",
        choices=list(PLAYBOOKS.keys()),
        help="Incident type",
    )
    parser.add_argument("--list", action="store_true", help="List available playbook types")
    parser.add_argument("--output", type=Path, help="Write playbook to Markdown file")
    parser.add_argument("--org", default="Your Organization", help="Organization name")
    parser.add_argument("--severity", choices=["low", "medium", "high", "critical"], help="Override severity")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.list:
        print("\nAvailable IR playbooks:")
        for key, pb in PLAYBOOKS.items():
            print(f"  {key:<20} [{pb['id']}] {pb['name']} — {pb['severity']}")
        print()
        return 0

    if not args.type:
        print("Provide --type or --list. Use --help for usage.")
        return 1

    playbook_md = generate_playbook_md(
        incident_type=args.type,
        org_name=args.org,
        severity_override=args.severity.capitalize() if args.severity else None,
    )

    if args.output:
        args.output.write_text(playbook_md)
        logger.info("Playbook written to %s", args.output)
    else:
        print(playbook_md)

    return 0


if __name__ == "__main__":
    sys.exit(main())
