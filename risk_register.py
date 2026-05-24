#!/usr/bin/env python3
"""
Risk Register — Full risk register CLI using likelihood × impact matrix.
Add/update/score risks, assign owners, track remediation status, export CSV.

Risk scoring: Likelihood (1-5) × Impact (1-5) = Raw Score (1-25)
Risk levels: Critical (20-25), High (12-19), Medium (6-11), Low (1-5)

Usage:
    python risk_register.py add --name "Unpatched critical vulnerability" --likelihood 4 --impact 5
    python risk_register.py list
    python risk_register.py list --filter high
    python risk_register.py update RISK-001 --status mitigated
    python risk_register.py export --output risk_register.csv
    python risk_register.py report
"""

import argparse
import csv
import json
import logging
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

DB_PATH = Path("risk_register_db.json")


@dataclass
class Risk:
    id: str
    name: str
    description: str
    category: str
    likelihood: int          # 1-5
    impact: int              # 1-5
    owner: str
    status: str              # open | mitigating | mitigated | accepted | transferred
    remediation_plan: str
    created_at: str
    updated_at: str
    due_date: str = ""
    residual_likelihood: int = 0
    residual_impact: int = 0
    tags: list[str] = field(default_factory=list)

    @property
    def raw_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual_score(self) -> int:
        return self.residual_likelihood * self.residual_impact

    @property
    def risk_level(self) -> str:
        return _score_to_level(self.raw_score)

    @property
    def residual_level(self) -> str:
        return _score_to_level(self.residual_score) if self.residual_score > 0 else "N/A"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "raw_score": self.raw_score,
            "risk_level": self.risk_level,
            "owner": self.owner,
            "status": self.status,
            "remediation_plan": self.remediation_plan,
            "due_date": self.due_date,
            "residual_likelihood": self.residual_likelihood,
            "residual_impact": self.residual_impact,
            "residual_score": self.residual_score,
            "residual_level": self.residual_level,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _score_to_level(score: int) -> str:
    if score >= 20:
        return "Critical"
    elif score >= 12:
        return "High"
    elif score >= 6:
        return "Medium"
    elif score > 0:
        return "Low"
    return "N/A"


LEVEL_ICONS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "N/A": "⚪"}


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def load_db() -> list[Risk]:
    if not DB_PATH.exists():
        return []
    with DB_PATH.open() as fh:
        raw = json.load(fh)
    return [Risk(**r) for r in raw]


def save_db(risks: list[Risk]) -> None:
    with DB_PATH.open("w") as fh:
        json.dump([r.to_dict() for r in risks], fh, indent=2)


def next_id(risks: list[Risk]) -> str:
    if not risks:
        return "RISK-001"
    max_num = max(int(r.id.split("-")[1]) for r in risks)
    return f"RISK-{max_num + 1:03d}"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_add(args: argparse.Namespace) -> int:
    risks = load_db()
    now = datetime.now(tz=timezone.utc).isoformat()
    risk = Risk(
        id=next_id(risks),
        name=args.name,
        description=args.description or "",
        category=args.category or "Uncategorized",
        likelihood=args.likelihood,
        impact=args.impact,
        owner=args.owner or "Unassigned",
        status=args.status or "open",
        remediation_plan=args.plan or "",
        due_date=args.due or "",
        created_at=now,
        updated_at=now,
        tags=args.tags.split(",") if args.tags else [],
    )
    risks.append(risk)
    save_db(risks)
    icon = LEVEL_ICONS[risk.risk_level]
    logger.info(
        "Added %s: %s | Score: %d (%s) %s | Owner: %s",
        risk.id, risk.name, risk.raw_score, risk.risk_level, icon, risk.owner,
    )
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    risks = load_db()
    target = next((r for r in risks if r.id == args.risk_id), None)
    if not target:
        logger.error("Risk not found: %s", args.risk_id)
        return 1

    if args.status:
        target.status = args.status
    if args.likelihood:
        target.likelihood = args.likelihood
    if args.impact:
        target.impact = args.impact
    if args.owner:
        target.owner = args.owner
    if args.plan:
        target.remediation_plan = args.plan
    if args.residual_likelihood:
        target.residual_likelihood = args.residual_likelihood
    if args.residual_impact:
        target.residual_impact = args.residual_impact
    if args.due:
        target.due_date = args.due

    target.updated_at = datetime.now(tz=timezone.utc).isoformat()
    save_db(risks)
    logger.info("Updated %s — Status: %s | Score: %d (%s)", target.id, target.status, target.raw_score, target.risk_level)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    risks = load_db()

    if not risks:
        print("  No risks in register. Use 'add' to create your first entry.")
        return 0

    filter_level = args.filter.capitalize() if args.filter else None
    filter_status = args.status_filter

    filtered = risks
    if filter_level:
        filtered = [r for r in filtered if r.risk_level == filter_level]
    if filter_status:
        filtered = [r for r in filtered if r.status == filter_status]

    filtered.sort(key=lambda r: (-r.raw_score, r.id))

    print(f"\n{'═'*90}")
    print(f"  RISK REGISTER  ({len(filtered)} risks")
    if filter_level:
        print(f"  Filter: {filter_level}", end="")
    print(f"{'═'*90}")
    print(f"  {'ID':<12} {'Level':<10} {'Score':>5} {'Status':<14} {'Owner':<20} Name")
    print(f"  {'─'*12} {'─'*10} {'─'*5} {'─'*14} {'─'*20} {'─'*30}")

    for r in filtered:
        icon = LEVEL_ICONS[r.risk_level]
        name = (r.name[:40] + "…") if len(r.name) > 41 else r.name
        print(f"  {r.id:<12} {icon} {r.risk_level:<8} {r.raw_score:>5} {r.status:<14} {r.owner:<20} {name}")

    print(f"{'═'*90}\n")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    risks = load_db()
    if not risks:
        print("No risks to report.")
        return 0

    level_counts: dict[str, int] = {}
    for r in risks:
        level_counts[r.risk_level] = level_counts.get(r.risk_level, 0) + 1

    status_counts: dict[str, int] = {}
    for r in risks:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

    print(f"\n{'═'*60}")
    print(f"  RISK REGISTER EXECUTIVE SUMMARY")
    print(f"  Total Risks: {len(risks)}")
    print(f"{'─'*60}")

    for level in ["Critical", "High", "Medium", "Low"]:
        count = level_counts.get(level, 0)
        bar = "█" * count
        icon = LEVEL_ICONS[level]
        print(f"  {icon} {level:<10} {bar} ({count})")

    print(f"\n  Status Breakdown:")
    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        print(f"    {status:<14} {count}")

    # Top risks
    top = sorted(risks, key=lambda r: -r.raw_score)[:5]
    print(f"\n  Top 5 Risks by Score:")
    for r in top:
        print(f"    {LEVEL_ICONS[r.risk_level]} {r.id} [{r.raw_score}] {r.name[:50]}")

    print(f"{'═'*60}\n")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    risks = load_db()
    if not risks:
        logger.warning("Nothing to export.")
        return 0

    fieldnames = list(risks[0].to_dict().keys())
    with args.output.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(r.to_dict() for r in risks)

    logger.info("Exported %d risks to %s", len(risks), args.output)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Risk register — add, track, score, and export cybersecurity risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # add
    add_p = sub.add_parser("add", help="Add a new risk")
    add_p.add_argument("--name", required=True)
    add_p.add_argument("--description", default="")
    add_p.add_argument("--category", default="Uncategorized")
    add_p.add_argument("--likelihood", type=int, required=True, choices=range(1, 6), metavar="1-5")
    add_p.add_argument("--impact", type=int, required=True, choices=range(1, 6), metavar="1-5")
    add_p.add_argument("--owner", default="Unassigned")
    add_p.add_argument("--status", default="open",
                       choices=["open", "mitigating", "mitigated", "accepted", "transferred"])
    add_p.add_argument("--plan", default="", help="Remediation plan description")
    add_p.add_argument("--due", default="", help="Due date YYYY-MM-DD")
    add_p.add_argument("--tags", default="", help="Comma-separated tags")

    # update
    upd_p = sub.add_parser("update", help="Update an existing risk")
    upd_p.add_argument("risk_id")
    upd_p.add_argument("--status", choices=["open", "mitigating", "mitigated", "accepted", "transferred"])
    upd_p.add_argument("--likelihood", type=int, choices=range(1, 6), metavar="1-5")
    upd_p.add_argument("--impact", type=int, choices=range(1, 6), metavar="1-5")
    upd_p.add_argument("--owner")
    upd_p.add_argument("--plan")
    upd_p.add_argument("--residual-likelihood", type=int, dest="residual_likelihood", choices=range(1, 6))
    upd_p.add_argument("--residual-impact", type=int, dest="residual_impact", choices=range(1, 6))
    upd_p.add_argument("--due")

    # list
    lst_p = sub.add_parser("list", help="List risks")
    lst_p.add_argument("--filter", choices=["critical", "high", "medium", "low"])
    lst_p.add_argument("--status-filter", dest="status_filter",
                       choices=["open", "mitigating", "mitigated", "accepted", "transferred"])

    # report
    sub.add_parser("report", help="Executive summary report")

    # export
    exp_p = sub.add_parser("export", help="Export to CSV")
    exp_p.add_argument("--output", type=Path, required=True)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dispatch = {
        "add": cmd_add,
        "update": cmd_update,
        "list": cmd_list,
        "report": cmd_report,
        "export": cmd_export,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
