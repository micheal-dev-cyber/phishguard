"""
PhishGuard AI — Plan Service (Feature Gating)

Centralized plan enforcement.  All feature checks, quota lookups, and permission
gates must go through this service.  No scattered `if plan == "starter"` checks.
"""
from typing import List, Optional

from src.tenants import PLANS
from src.billing.config import get_plan, PlanConfig


class PlanService:
    """Feature gating and quota enforcement."""

    @staticmethod
    def has_feature(plan_name: str, feature: str) -> bool:
        """Check if a plan has access to a specific feature."""
        features = PLANS.get(plan_name, PLANS["free"]).get("features", [])
        return feature in features

    @staticmethod
    def get_quota(plan_name: str) -> int:
        """Get monthly analysis quota for a plan."""
        return PLANS.get(plan_name, PLANS["free"]).get("analyses_per_month", 0)

    @staticmethod
    def get_allowed_features(plan_name: str) -> List[str]:
        """Get list of features enabled for a plan."""
        return PLANS.get(plan_name, PLANS["free"]).get("features", [])

    @staticmethod
    def get_concurrent_sessions(plan_name: str) -> int:
        return PLANS.get(plan_name, PLANS["free"]).get("concurrent_sessions", 1)

    @staticmethod
    def get_rate_limit(plan_name: str) -> int:
        return PLANS.get(plan_name, PLANS["free"]).get("rate_per_minute", 5)

    @staticmethod
    def get_plan_label(plan_name: str) -> str:
        return PLANS.get(plan_name, PLANS["free"]).get("label", "Free")

    @staticmethod
    def get_plan_price_display(plan_name: str) -> str:
        return PLANS.get(plan_name, PLANS["free"]).get("price", "Free")

    @staticmethod
    def is_upgrade(current_plan: str, target_plan: str) -> bool:
        """Check if target_plan is an upgrade from current_plan."""
        tiers = ["free", "trial", "starter", "business", "consultant", "enterprise"]
        try:
            return tiers.index(target_plan) > tiers.index(current_plan)
        except ValueError:
            return False

    @staticmethod
    def get_plan_config(plan_name: str) -> PlanConfig:
        return get_plan(plan_name)

    @staticmethod
    def get_all_plan_configs() -> List[PlanConfig]:
        from src.billing.config import get_all_plans
        return get_all_plans()

    @staticmethod
    def check_scan_allowed(plan_name: str, current_usage: int) -> tuple:
        """Check if a scan is allowed. Returns (allowed: bool, reason: str)."""
        quota = PlanService.get_quota(plan_name)
        if quota >= 99999:
            return True, ""
        if current_usage >= quota:
            return False, f"Monthly scan limit reached ({quota}). Upgrade to continue."
        return True, ""
