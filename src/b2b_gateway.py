import functools
import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)
from src.tenants import PLANS  # noqa: E402

# Tier definitions — features sourced from PLANS in tenants.py
TIERS = {
    "trial": {
        "label": "Trial",
        "scans_per_month": 10,
        "concurrent_sessions": 1,
        "rate_per_minute": 5,
        "features": PLANS["trial"]["features"],
    },
    "starter": {
        "label": "Starter",
        "scans_per_month": 100,
        "concurrent_sessions": 2,
        "rate_per_minute": 15,
        "features": PLANS["starter"]["features"],
    },
    "business": {
        "label": "Business",
        "scans_per_month": 500,
        "concurrent_sessions": 5,
        "rate_per_minute": 30,
        "features": PLANS["business"]["features"],
    },
    "consultant": {
        "label": "Consultant",
        "scans_per_month": 2000,
        "concurrent_sessions": 10,
        "rate_per_minute": 60,
        "features": PLANS["consultant"]["features"],
    },
    "enterprise": {
        "label": "Enterprise",
        "scans_per_month": 999999,
        "concurrent_sessions": 50,
        "rate_per_minute": 120,
        "features": PLANS["enterprise"]["features"],
    },
}

# In-memory rate tracking
_rate_buckets: Dict[str, list] = defaultdict(list)
_lock = Lock()


class QuotaExceededError(Exception):
    """Raised when the user has exceeded their plan quota."""
    pass


class RateLimitError(Exception):
    """Raised when the user has exceeded their per-minute rate limit."""
    pass


class FeatureAccessError(Exception):
    """Raised when the user's plan does not include a requested feature."""
    pass


def get_tier_config(plan: str) -> Dict:
    """Return the tier configuration for a given plan name."""
    return TIERS.get(plan, TIERS["trial"])


def check_feature_access(plan: str, feature: str) -> bool:
    """Check if the given plan includes a specific feature."""
    config = get_tier_config(plan)
    return feature in config["features"]


def require_feature(feature: str):
    """
    Decorator that checks if the user's plan includes a required feature.
    Usage:
        @require_feature("api_access")
        def my_api_endpoint(username, plan, ...):
            ...
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            plan = kwargs.get("plan") or (args[1] if len(args) > 1 else None)
            if plan is None:
                raise ValueError("Plan must be provided for feature check")
            if not check_feature_access(plan, feature):
                raise FeatureAccessError(
                    f"'{feature}' is not available on your current plan. "
                    f"Upgrade to access this feature."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _check_rate_bucket(key: str, max_per_minute: int) -> bool:
    """
    Sliding window rate check per key.
    Returns True if request is allowed, False if rate limited.
    """
    now = time.time()
    cutoff = now - 60

    with _lock:
        timestamps = _rate_buckets[key]
        timestamps[:] = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= max_per_minute:
            return False
        timestamps.append(now)
        return True


def rate_limit_by_tier():
    """
    Decorator that enforces rate limits based on the user's plan tier.
    Expects `username` and `plan` as keyword arguments or positional args[0], args[1].

    Usage:
        @rate_limit_by_tier()
        def analyze_email(username, plan, ...):
            ...
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            username = kwargs.get("username") or (args[0] if args else None)
            plan = kwargs.get("plan") or (args[1] if len(args) > 1 else None)

            if not username or not plan:
                logger.warning("rate_limit_by_tier missing username/plan")
                return func(*args, **kwargs)

            tier = get_tier_config(plan)
            bucket_key = f"rate:{username}"

            if not _check_rate_bucket(bucket_key, tier["rate_per_minute"]):
                raise RateLimitError(
                    f"Rate limit exceeded for {tier['label']} plan "
                    f"({tier['rate_per_minute']} requests/minute). "
                    "Please wait before submitting another request."
                )

            return func(*args, **kwargs)
        return wrapper
    return decorator


class MockAPIGateway:
    """
    Simulates an enterprise API gateway with authentication, rate limiting,
    and tier-based access control. Designed for demonstration and integration testing.
    """

    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        self.api_keys = api_keys or {}
        self._key_usage: Dict[str, list] = defaultdict(list)

    def register_key(self, key: str, username: str, plan: str):
        """Register a mock API key for a user."""
        self.api_keys[key] = {"username": username, "plan": plan}

    def authenticate(self, api_key: str) -> Optional[Dict[str, str]]:
        """Validate an API key and return user info."""
        return self.api_keys.get(api_key)

    def call_endpoint(self, api_key: str, endpoint: str, payload: Any = None) -> Dict:
        """
        Simulate an authenticated API call through the gateway.
        Enforces auth, rate limits, and feature access.
        """
        user_info = self.authenticate(api_key)
        if not user_info:
            return {"status": "error", "code": 401, "message": "Invalid or missing API key."}

        username = user_info["username"]
        plan = user_info["plan"]
        tier = get_tier_config(plan)

        # Feature access
        endpoint_feature_map = {
            "/v1/analyze": "basic_scan",
            "/v1/threat-intel": "threat_intel",
            "/v1/osint": "osint",
            "/v1/export": "api_access",
        }
        required_feature = endpoint_feature_map.get(endpoint, "basic_scan")
        if required_feature not in tier["features"]:
            return {
                "status": "error",
                "code": 403,
                "message": f"Endpoint '{endpoint}' requires '{required_feature}', "
                           f"not available on {tier['label']} plan.",
            }

        # Rate limit
        bucket_key = f"gateway:{api_key}:{endpoint}"
        if not _check_rate_bucket(bucket_key, tier["rate_per_minute"]):
            return {
                "status": "error",
                "code": 429,
                "message": f"Rate limited. {tier['rate_per_minute']} requests/minute allowed.",
            }

        return {
            "status": "ok",
            "code": 200,
            "user": username,
            "plan": plan,
            "tier": tier["label"],
            "remaining": tier["scans_per_month"],
        }

    def get_usage_summary(self, api_key: str) -> Dict:
        """Return usage statistics for the given API key."""
        user_info = self.authenticate(api_key)
        if not user_info:
            return {"status": "error", "message": "Invalid API key."}

        plan = user_info["plan"]
        tier = get_tier_config(plan)
        now = time.time()
        cutoff = now - 60

        with _lock:
            recent = sum(
                1 for ts in _rate_buckets.get(f"gateway:{api_key}:", [])
                if ts > cutoff
            )

        return {
            "username": user_info["username"],
            "plan": tier["label"],
            "monthly_limit": tier["scans_per_month"],
            "rate_per_minute": tier["rate_per_minute"],
            "current_rpm": recent,
            "features": tier["features"],
        }
