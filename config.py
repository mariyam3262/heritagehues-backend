import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "").strip() or os.getenv("FLASK_SECRET_KEY", "").strip() or "change-me-in-env"

    SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "heritage_hues_admin_session")
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes"}

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = SESSION_COOKIE_SAMESITE
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE

    ADMIN_REGISTRATION_ENABLED = os.getenv("ADMIN_REGISTRATION_ENABLED", "true").strip().lower() in {"1", "true", "yes"}
    ADMIN_LOGIN_RATE_LIMIT = int(os.getenv("ADMIN_LOGIN_RATE_LIMIT", "5"))
    ADMIN_LOGIN_RATE_WINDOW_SECONDS = int(os.getenv("ADMIN_LOGIN_RATE_WINDOW_SECONDS", "900"))
