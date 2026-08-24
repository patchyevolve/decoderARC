"""Application configuration via environment variables."""

import os


class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:postgres@localhost:5432/coreids",
    )
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_expire_minutes: int = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))  # 24h

    # Stripe
    stripe_secret_key: str = os.getenv("STRIPE_SECRET_KEY", "")
    stripe_webhook_secret: str = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if stripe_secret_key or stripe_webhook_secret:
        if not stripe_secret_key or not stripe_webhook_secret:
            import warnings
            warnings.warn("Only one of STRIPE_SECRET_KEY / STRIPE_WEBHOOK_SECRET is set — Stripe will fail")
    else:
        import warnings
        warnings.warn("Stripe keys not set — subscription payments will not work")

    # Plans (hardcoded for MVP)
    plans: dict = {
        "free": {
            "name": "Free",
            "sensors": 1,
            "retention_days": 7,
            "events_per_month": 1_000_000,
            "price_monthly": 0,
            "price_yearly": 0,
        },
        "pro": {
            "name": "Pro",
            "sensors": 5,
            "retention_days": 30,
            "events_per_month": 10_000_000,
            "price_monthly": 4900,  # $49 in cents
            "price_yearly": 49900,  # $499 in cents
        },
        "enterprise": {
            "name": "Enterprise",
            "sensors": 999,
            "retention_days": 365,
            "events_per_month": 999_999_999,
            "price_monthly": 19900,  # $199 in cents
            "price_yearly": 199900,  # $1999 in cents
        },
    }

    # Default plan on registration
    default_plan: str = "free"


_secret = os.getenv("JWT_SECRET")
if _secret:
    _validate = _secret.strip()
    if _validate in ("", "change-me-in-production"):
        import warnings
        warnings.warn("JWT_SECRET is set to an insecure default or empty value")
elif not os.getenv("DISABLE_JWT_SECRET_CHECK"):
    import warnings
    warnings.warn(
        "JWT_SECRET environment variable is not set. "
        "Authentication will fail until you set a strong random secret (64+ chars). "
        "Set DISABLE_JWT_SECRET_CHECK=1 to silence this warning."
    )

settings = Settings()
