"""Unit tests for risk_register.py"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from risk_register import Risk, _score_to_level
from datetime import datetime, timezone


def _make_risk(**kwargs) -> Risk:
    defaults = {
        "id": "RISK-001",
        "name": "Test Risk",
        "description": "Test",
        "category": "Technical",
        "likelihood": 3,
        "impact": 3,
        "owner": "Test Owner",
        "status": "open",
        "remediation_plan": "",
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "updated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    defaults.update(kwargs)
    return Risk(**defaults)


class TestScoreToLevel:
    def test_critical(self):
        assert _score_to_level(20) == "Critical"
        assert _score_to_level(25) == "Critical"

    def test_high(self):
        assert _score_to_level(12) == "High"
        assert _score_to_level(19) == "High"

    def test_medium(self):
        assert _score_to_level(6) == "Medium"
        assert _score_to_level(11) == "Medium"

    def test_low(self):
        assert _score_to_level(1) == "Low"
        assert _score_to_level(5) == "Low"

    def test_zero(self):
        assert _score_to_level(0) == "N/A"


class TestRisk:
    def test_raw_score_computed(self):
        r = _make_risk(likelihood=4, impact=5)
        assert r.raw_score == 20

    def test_raw_score_critical(self):
        r = _make_risk(likelihood=5, impact=5)
        assert r.risk_level == "Critical"

    def test_raw_score_medium(self):
        r = _make_risk(likelihood=2, impact=3)
        assert r.risk_level == "Medium"  # 6

    def test_raw_score_low(self):
        r = _make_risk(likelihood=1, impact=2)
        assert r.risk_level == "Low"  # 2

    def test_residual_score_zero_when_not_set(self):
        r = _make_risk()
        assert r.residual_score == 0

    def test_residual_level_na_when_not_set(self):
        r = _make_risk()
        assert r.residual_level == "N/A"

    def test_residual_score_computed(self):
        r = _make_risk()
        r.residual_likelihood = 2
        r.residual_impact = 2
        assert r.residual_score == 4
        assert r.residual_level == "Low"

    def test_to_dict_has_required_keys(self):
        r = _make_risk()
        d = r.to_dict()
        for key in ["id", "name", "likelihood", "impact", "raw_score", "risk_level", "status"]:
            assert key in d

    def test_to_dict_raw_score_consistent(self):
        r = _make_risk(likelihood=3, impact=4)
        d = r.to_dict()
        assert d["raw_score"] == 12
        assert d["risk_level"] == "High"
