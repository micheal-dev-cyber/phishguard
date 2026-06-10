"""Tests for PlanService feature gating and quota enforcement."""

import pytest

from src.plan_service import PlanService
from src.billing.config import get_plan, PlanConfig


class TestPlanService:
    def test_has_feature_true(self):
        assert PlanService.has_feature("business", "api_access") is True

    def test_has_feature_false(self):
        assert PlanService.has_feature("free", "api_access") is False

    def test_has_feature_free_has_basic_scan(self):
        assert PlanService.has_feature("free", "basic_scan") is True

    def test_get_quota_free(self):
        assert PlanService.get_quota("free") > 0

    def test_get_quota_starter(self):
        assert PlanService.get_quota("starter") >= 100

    def test_get_quota_business(self):
        assert PlanService.get_quota("business") >= 500

    def test_get_quota_enterprise_unlimited(self):
        assert PlanService.get_quota("enterprise") >= 99999

    def test_get_quota_unknown_plan_falls_back(self):
        assert PlanService.get_quota("nonexistent") == PlanService.get_quota("free")

    def test_get_allowed_features_returns_list(self):
        features = PlanService.get_allowed_features("starter")
        assert isinstance(features, list)

    def test_get_concurrent_sessions_starter(self):
        assert PlanService.get_concurrent_sessions("starter") >= 2

    def test_get_concurrent_sessions_enterprise(self):
        assert PlanService.get_concurrent_sessions("enterprise") >= 50

    def test_get_rate_limit_business(self):
        assert PlanService.get_rate_limit("business") >= 30

    def test_get_plan_label(self):
        assert PlanService.get_plan_label("starter") == "Starter"
        assert PlanService.get_plan_label("enterprise") == "Enterprise"

    def test_get_plan_price_display(self):
        price = PlanService.get_plan_price_display("starter")
        assert isinstance(price, str)
        assert "$" in price or price == "Free"

    def test_is_upgrade_true(self):
        assert PlanService.is_upgrade("free", "starter") is True
        assert PlanService.is_upgrade("starter", "business") is True

    def test_is_upgrade_false(self):
        assert PlanService.is_upgrade("business", "starter") is False
        assert PlanService.is_upgrade("starter", "free") is False

    def test_is_upgrade_same(self):
        assert PlanService.is_upgrade("starter", "starter") is False

    def test_get_plan_config_returns_plan_config(self):
        config = PlanService.get_plan_config("starter")
        assert isinstance(config, PlanConfig)
        assert config.key == "starter"

    def test_get_all_plan_configs_returns_list(self):
        configs = PlanService.get_all_plan_configs()
        assert len(configs) >= 4
        assert all(isinstance(c, PlanConfig) for c in configs)

    def test_check_scan_allowed_true(self):
        allowed, reason = PlanService.check_scan_allowed("starter", 0)
        assert allowed is True
        assert reason == ""

    def test_check_scan_allowed_at_quota(self):
        quota = PlanService.get_quota("starter")
        allowed, reason = PlanService.check_scan_allowed("starter", quota)
        assert allowed is False
        assert "limit" in reason.lower()

    def test_check_scan_allowed_under_quota(self):
        quota = PlanService.get_quota("starter")
        allowed, reason = PlanService.check_scan_allowed("starter", quota - 1)
        assert allowed is True

    def test_check_scan_allowed_enterprise_unlimited(self):
        allowed, reason = PlanService.check_scan_allowed("enterprise", 99999)
        assert allowed is True
        assert reason == ""

    def test_check_scan_allowed_unknown_plan(self):
        allowed, reason = PlanService.check_scan_allowed("nonexistent", 0)
        assert allowed is True
