# src/billing/config.py
"""
Pricing configuration for all plans.
Single source of truth — all business logic reads from here, not hardcoded strings.
"""
from dataclasses import dataclass, field
from typing import List

from src.tenants import PLANS as _TENANT_PLANS


@dataclass
class PlanConfig:
    key: str
    label: str
    price_monthly: float
    price_yearly: float
    analyses_per_month: int
    features: List[str]
    concurrent_sessions: int = 1
    rate_per_minute: int = 5
    gumroad_monthly_permalink: str = ""
    gumroad_yearly_permalink: str = ""
    paddle_price_id: str = ""
    stripe_price_id: str = ""


# Sync from tenants.PLANS so all pricing stays consistent
_PLAN_MAP = {
    "free": PlanConfig(
        key="free", label="Free",
        price_monthly=0, price_yearly=0,
        analyses_per_month=_TENANT_PLANS.get("free", {}).get("analyses_per_month", 5),
        features=_TENANT_PLANS.get("free", {}).get("features", ["basic_scan", "pdf_export"]),
    ),
    "starter": PlanConfig(
        key="starter", label="Starter",
        price_monthly=29, price_yearly=290,
        analyses_per_month=_TENANT_PLANS.get("starter", {}).get("analyses_per_month", 100),
        features=_TENANT_PLANS.get("starter", {}).get("features", []),
        concurrent_sessions=2, rate_per_minute=15,
    ),
    "business": PlanConfig(
        key="business", label="Business",
        price_monthly=99, price_yearly=990,
        analyses_per_month=_TENANT_PLANS.get("business", {}).get("analyses_per_month", 500),
        features=_TENANT_PLANS.get("business", {}).get("features", []),
        concurrent_sessions=5, rate_per_minute=30,
    ),
    "enterprise": PlanConfig(
        key="enterprise", label="Enterprise",
        price_monthly=0, price_yearly=0,
        analyses_per_month=_TENANT_PLANS.get("enterprise", {}).get("analyses_per_month", 99999),
        features=_TENANT_PLANS.get("enterprise", {}).get("features", []),
        concurrent_sessions=50, rate_per_minute=120,
    ),
}


def get_plan(plan_key: str) -> PlanConfig:
    return _PLAN_MAP.get(plan_key, _PLAN_MAP["free"])


def get_all_plans() -> list:
    return list(_PLAN_MAP.values())


def get_monthly_plans() -> list:
    return [p for p in _PLAN_MAP.values() if p.price_monthly > 0]


def get_yearly_plans() -> list:
    return [p for p in _PLAN_MAP.values() if p.price_yearly > 0]


def get_yearly_savings_pct(plan_key: str) -> int:
    plan = get_plan(plan_key)
    if plan.price_monthly <= 0:
        return 0
    monthly_total = plan.price_monthly * 12
    if monthly_total <= 0:
        return 0
    return int((1 - plan.price_yearly / monthly_total) * 100)
