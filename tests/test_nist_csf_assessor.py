"""Unit tests for nist_csf_assessor.py"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from nist_csf_assessor import compute_results, generate_markdown_report, MATURITY_LABELS, DEMO_SCORES, load_framework


def _mock_framework():
    return {
        "framework": "NIST CSF 2.0",
        "version": "2.0",
        "published": "2024-02-26",
        "functions": [
            {
                "id": "GV",
                "name": "GOVERN",
                "description": "Test function",
                "categories": [
                    {"id": "GV.OC", "name": "Org Context", "description": "desc"},
                    {"id": "GV.RM", "name": "Risk Mgmt", "description": "desc"},
                ],
            },
            {
                "id": "ID",
                "name": "IDENTIFY",
                "description": "Test function",
                "categories": [
                    {"id": "ID.AM", "name": "Asset Mgmt", "description": "desc"},
                ],
            },
        ],
        "maturity_levels": {},
    }


class TestMaturityLabels:
    def test_all_five_levels_defined(self):
        assert len(MATURITY_LABELS) == 5

    def test_level_1_is_partial(self):
        assert MATURITY_LABELS[1] == "Partial"

    def test_level_5_is_optimizing(self):
        assert MATURITY_LABELS[5] == "Optimizing"


class TestComputeResults:
    def test_function_average_computed(self):
        fw = _mock_framework()
        scores = {"GV.OC": 3, "GV.RM": 5, "ID.AM": 4}
        results = compute_results(fw, scores)
        assert results["functions"]["GV"]["average"] == 4.0

    def test_overall_average(self):
        fw = _mock_framework()
        scores = {"GV.OC": 4, "GV.RM": 4, "ID.AM": 4}
        results = compute_results(fw, scores)
        assert results["overall"]["average"] == 4.0

    def test_skipped_scores_excluded(self):
        fw = _mock_framework()
        scores = {"GV.OC": 3, "GV.RM": 0, "ID.AM": 3}  # 0 = not scored
        results = compute_results(fw, scores)
        # GV average should only use GV.OC (score=3), not GV.RM (score=0)
        assert results["functions"]["GV"]["average"] == 3.0

    def test_categories_scored_count(self):
        fw = _mock_framework()
        scores = {"GV.OC": 3, "GV.RM": 0, "ID.AM": 4}
        results = compute_results(fw, scores)
        assert results["overall"]["categories_scored"] == 2

    def test_category_label_assigned(self):
        fw = _mock_framework()
        scores = {"GV.OC": 3, "GV.RM": 3, "ID.AM": 3}
        results = compute_results(fw, scores)
        assert results["functions"]["GV"]["categories"]["GV.OC"]["label"] == "Repeatable"

    def test_zero_scores_produce_zero_average(self):
        fw = _mock_framework()
        scores = {"GV.OC": 0, "GV.RM": 0, "ID.AM": 0}
        results = compute_results(fw, scores)
        assert results["functions"]["GV"]["average"] == 0.0


class TestMarkdownReport:
    def test_report_contains_framework_name(self):
        fw = _mock_framework()
        scores = {"GV.OC": 3, "GV.RM": 3, "ID.AM": 3}
        results = compute_results(fw, scores)
        md = generate_markdown_report(fw, results, "Test Corp")
        assert "NIST" in md or "CSF" in md

    def test_report_contains_org_name(self):
        fw = _mock_framework()
        scores = {"GV.OC": 4, "GV.RM": 4, "ID.AM": 4}
        results = compute_results(fw, scores)
        md = generate_markdown_report(fw, results, "Acme Corp")
        assert "Acme Corp" in md

    def test_report_contains_score(self):
        fw = _mock_framework()
        scores = {"GV.OC": 3, "GV.RM": 3, "ID.AM": 3}
        results = compute_results(fw, scores)
        md = generate_markdown_report(fw, results)
        assert "3.00" in md


class TestDemoScores:
    def test_all_demo_scores_valid(self):
        for cat_id, score in DEMO_SCORES.items():
            assert 1 <= score <= 5, f"Invalid score {score} for {cat_id}"

    def test_demo_scores_have_expected_categories(self):
        expected = {"GV.OC", "GV.RM", "ID.AM", "PR.AA", "DE.CM", "RS.MA", "RC.RP"}
        for cat in expected:
            assert cat in DEMO_SCORES
