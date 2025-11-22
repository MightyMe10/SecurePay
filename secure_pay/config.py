"""Application configuration module."""
from __future__ import annotations

import os
from datetime import timedelta
from typing import Dict, Type


class BaseConfig:
    """Base security-conscious configuration shared across environments."""

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///secure_pay.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    WTF_CSRF_TIME_LIMIT = 3600
    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT", "set-a-random-salt")
    TOTP_ENCRYPTION_KEY = os.getenv("TOTP_ENCRYPTION_KEY")
    CONTENT_SECURITY_POLICY = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCK_WINDOW = timedelta(minutes=15)


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(BaseConfig):
    DEBUG = False


CONFIG_MAP: Dict[str, Type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}


def get_config(name: str | None = None) -> Type[BaseConfig]:
    """Return a configuration class by name, defaulting to production."""

    if not name:
        return ProductionConfig
    return CONFIG_MAP.get(name.lower(), ProductionConfig)
