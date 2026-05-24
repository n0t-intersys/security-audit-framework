#!/usr/bin/env python3
"""
NIST CSF 2.0 Assessor — Interactive CLI that walks through all six NIST CSF functions,
scores maturity 1-5 per category, and exports a JSON + Markdown report.

Usage:
    python nist_csf_assessor.py                          # interactive assessment
    python nist_csf_assessor.py --output assessment.json # save to file
    python nist_csf_assessor.py --load assessment.json   # view/re-export existing
    python nist_csf_assessor.py --demo                   # run with sample scores
"""

import argparse
import json
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

FRAMEWORK_PATH = Path(__file__).parent / "frameworks" / "nist_csf.json"

MATURITY_LABELS = {
    1: "Partial",
    2: "Risk Informed",
    3: "Repeatable",
    4: "Adaptive",
    5: "Optimizing",
}

MATURITY_DESCRIPTIONS = {
    1: "Ad hoc, reactive — no formal process",
    2: "Management-approved practices, not org-wide policy",
    3: "Formal policy, consistently applied org-wide",
    4: "Adaptive based on lessons learned + metrics",
    5: "Continuously improved, industry-leading practices",
}

DEMO_SCORES: dict[str, int] = {
    "GV.OC": 3, "GV.RM": 2, "GV.RR": 3, "GV.PO": 4, "GV.OV": 2, "GV.SC": 2,
    "ID.AM": 3, "ID.RA": 3, "ID.IM": 2,
    "PR.AA": 4, "PR.AT": 3, "PR.DS": 3, "PR.PS": 3, "PR.IR": 2,
    "DE.CM": 3, "DE.AE": 2,
    "RS.MA": 2, "RS.AN": 2, "RS.CO": 2, "RS.MI": 3,
    "RC.RP": 2, "RC.CO": 2,
}


def load_framework() -> dict:
    if not FRAMEWORK_PATH.exists():
        logger.error("Framework file not found: %s", FRAMEWORK_PATH)
        sys.exit(1)
    with FRAMEWORK_PATH.open() as fh:
        return json.load(fh)


def prompt_score(category_id: str, category_name: str, description: str) -> int:
    """Prompt the user for a maturity score 1-5."""
    print(f"\n  ┌─ {category_id}: {category_name}")
    print(f"  │  {description[:100]}{'…' if len(description) > 100 else ''}")
    print(f"  │")
    for level, label in MATURITY_LABELS.items():
        print(f"  │  [{level}] {label} — {MATURITY_DESCRIPTIONS[level]}")

    while True:
        try:
            raw = input(f"  └─ Score for {category_id} [1-5, or 's' to skip]: ").strip()
            if raw.lower() == "s":
                return 0
            score = int(raw)
            if 1 <= score <= 5:
                return score
            print("  ⚠  Please enter a number between 1 and 5.")
        except (ValueError, EOFError):
            return 0
        except KeyboardInterrupt:
            print("\n\n  Assessment interrupted.")
            sys.exit(0)


def run_assessment(framework: dict, demo: bool = False) -> dict:
    """Walk through all CSF functions and categories, collecting scores."""
    scores: dict[str, int] = {}

    if not demo:
        print(f"\n{'═'*70}")
        print(f"  NIST CYBERSECURITY FRAMEWORK 2.0 — MATURITY ASSESSMENT")
        print(f"  {framework['framework']} | Published: {framework['published']}")
        print(f"{'═'*70}")
        print(f"  Score each category 1-5 (or 's' to skip).")
        print(f"  The assessment can be resumed by saving the output JSON.")
        print(f"{'═'*70}")

    for function in framework["functions"]:
        if not demo:
            print(f"\n{'─'*70}")
            print(f"  FUNCTION: [{function['id']}] {function['name']}")
            print(f"  {function['description'][:120]}")
            print(f"{'─'*70}")

        for category in function["categories"]:
            if demo:
                scores[category["id"]] = DEMO_SCORES.get(category["id"], 2)
            else:
                score = prompt_score(category["id"], category["name"], category["description"])
                scores[category["id"]] = score

    return scores


def compute_results(framework: dict, scores: dict[str, int]) -> dict:
    """Aggregate scores into per-function and overall summaries."""
    results = {"functions": {}, "overall": {}}

    all_scores = []
    for function in framework["functions"]:
        func_scores = []
        func_results = {"name": function["name"], "categories": {}}

        for cat in function["categories"]:
            score = scores.get(cat["id"], 0)
            func_results["categories"][cat["id"]] = {
                "name": cat["name"],
                "score": score,
                "label": MATURITY_LABELS.get(score, "Not Assessed"),
            }
            if score > 0:
                func_scores.append(score)
                all_scores.append(score)

        func_results["average"] = round(sum(func_scores) / len(func_scores), 2) if func_scores else 0.0
        func_results["min"] = min(func_scores) if func_scores else 0
        func_results["max"] = max(func_scores) if func_scores else 0
        results["functions"][function["id"]] = func_results

    results["overall"]["average"] = round(sum(all_scores) / len(all_scores), 2) if all_scores else 0.0
    results["overall"]["categories_scored"] = len([s for s in all_scores if s > 0])
    results["overall"]["total_categories"] = len(all_scores)
    return results


def print_console_report(results: dict) -> None:
    overall = results["overall"]["average"]
    label = MATURITY_LABELS.get(round(overall), "Partial")

    print(f"\n{'═'*70}")
    print(f"  NIST CSF 2.0 MATURITY ASSESSMENT RESULTS")
    print(f"{'═'*70}")
    print(f"  Overall Maturity Score: {overall:.2f} / 5.00  [{label}]")
    print(f"  Categories Scored: {results['overall']['categories_scored']} / {results['overall']['total_categories']}")
    print(f"{'─'*70}")

    for func_id, func_data in results["functions"].items():
        avg = func_data["average"]
        bar_len = int(avg * 6)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        gap_flag = " ⚠  GAP" if avg < 2.5 else ""
        print(f"\n  [{func_id}] {func_data['name']:<20} {bar} {avg:.2f}{gap_flag}")

        for cat_id, cat_data in func_data["categories"].items():
            score = cat_data["score"]
            if score == 0:
                indicator = "  ─"
            elif score <= 2:
                indicator = "  🔴"
            elif score <= 3:
                indicator = "  🟡"
            else:
                indicator = "  🟢"
            print(f"    {indicator} {cat_id:<8} {cat_data['name']:<40} {score}/5")

    print(f"\n{'═'*70}\n")


def generate_markdown_report(framework: dict, results: dict, org_name: str = "Your Organization") -> str:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    overall = results["overall"]["average"]
    label = MATURITY_LABELS.get(round(overall), "Partial")

    lines = [
        f"# NIST CSF 2.0 Maturity Assessment Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Organization** | {org_name} |",
        f"| **Framework** | {framework['framework']} |",
        f"| **Assessment Date** | {now} |",
        f"| **Overall Score** | **{overall:.2f} / 5.00** ({label}) |",
        f"| **Assessor** | Security Team |",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        f"This assessment evaluated cybersecurity program maturity across all six NIST CSF 2.0 functions. "
        f"The organization achieved an overall maturity score of **{overall:.2f}** (Tier: **{label}**), "
        f"indicating {"strong foundational controls with room for optimization." if overall >= 3.5 else "significant gaps requiring prioritized remediation."}",
        f"",
        f"## Function Scores",
        f"",
        f"| Function | Name | Score | Tier |",
        f"|----------|------|-------|------|",
    ]

    for func_id, func_data in results["functions"].items():
        avg = func_data["average"]
        tier = MATURITY_LABELS.get(round(avg), "N/A")
        flag = " ⚠" if avg < 2.5 else ""
        lines.append(f"| **{func_id}** | {func_data['name']} | {avg:.2f} | {tier}{flag} |")

    lines += ["", "---", "", "## Detailed Category Scores", ""]

    for func_id, func_data in results["functions"].items():
        lines.append(f"### [{func_id}] {func_data['name']} — Average: {func_data['average']:.2f}")
        lines.append("")
        lines.append("| Category | Name | Score | Maturity Tier |")
        lines.append("|----------|------|-------|---------------|")

        for cat_id, cat_data in func_data["categories"].items():
            score = cat_data["score"]
            tier = MATURITY_LABELS.get(score, "Not Assessed")
            lines.append(f"| `{cat_id}` | {cat_data['name']} | {score}/5 | {tier} |")

        lines.append("")

    lines += [
        "---",
        "",
        "## Remediation Priorities",
        "",
        "Categories scoring below 3 (not yet at 'Repeatable' tier):",
        "",
    ]

    for func_id, func_data in results["functions"].items():
        for cat_id, cat_data in func_data["categories"].items():
            if 0 < cat_data["score"] < 3:
                lines.append(f"- **{cat_id}** ({cat_data['name']}) — Current: {cat_data['score']}/5 → Target: 3")

    lines += [
        "",
        "---",
        "",
        f"*Report generated by security-audit-framework · NIST CSF 2.0 · {now}*",
        "*This assessment is for internal use. Findings should be treated as sensitive.*",
    ]

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive NIST CSF 2.0 maturity assessment tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--output", type=Path, help="Save assessment results to JSON file")
    parser.add_argument("--load", type=Path, help="Load and re-render existing assessment JSON")
    parser.add_argument("--report", type=Path, help="Write Markdown report to file")
    parser.add_argument("--org", type=str, default="Your Organization", help="Organization name for report")
    parser.add_argument("--demo", action="store_true", help="Run with pre-populated demo scores")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    framework = load_framework()

    if args.load:
        if not args.load.exists():
            logger.error("Assessment file not found: %s", args.load)
            return 1
        with args.load.open() as fh:
            saved = json.load(fh)
        scores = saved.get("scores", {})
    else:
        scores = run_assessment(framework, demo=args.demo)

    results = compute_results(framework, scores)
    print_console_report(results)

    if args.output:
        payload = {
            "framework": framework["framework"],
            "version": framework["version"],
            "assessed_at": datetime.now(tz=timezone.utc).isoformat(),
            "organization": args.org,
            "scores": scores,
            "results": results,
        }
        with args.output.open("w") as fh:
            json.dump(payload, fh, indent=2)
        logger.info("Assessment saved to %s", args.output)

    if args.report:
        md = generate_markdown_report(framework, results, org_name=args.org)
        args.report.write_text(md)
        logger.info("Markdown report written to %s", args.report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
