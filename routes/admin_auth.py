import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request, session
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from models import Admin


admin_auth_bp = Blueprint("admin_auth", __name__)

_login_attempts = {}


def admins_collection():
    return current_app.extensions["admins_collection"]


def _json_success(message, admin=None, extra=None, status=200):
    payload = {"success": True, "message": message}
    if admin is not None:
        payload["admin"] = admin
    if extra:
        payload.update(extra)
    return jsonify(payload), status


def _json_error(message, status=400):
    return jsonify({"success": False, "message": message}), status


def _get_client_key(email=""):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    return f"{(email or '').strip().lower()}|{ip}"


def _prune_attempts(key):
    window = current_app.config["ADMIN_LOGIN_RATE_WINDOW_SECONDS"]
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
    attempts = _login_attempts.get(key, [])
    _login_attempts[key] = [item for item in attempts if item > cutoff]
    return _login_attempts[key]


def is_rate_limited(email=""):
    key = _get_client_key(email)
    attempts = _prune_attempts(key)
    return len(attempts) >= current_app.config["ADMIN_LOGIN_RATE_LIMIT"]


def record_failed_attempt(email=""):
    key = _get_client_key(email)
    attempts = _prune_attempts(key)
    attempts.append(datetime.now(timezone.utc))
    _login_attempts[key] = attempts


def clear_failed_attempts(email=""):
    _login_attempts.pop(_get_client_key(email), None)


def generate_admin_csrf_token():
    token = secrets.token_urlsafe(32)
    session["admin_csrf_token"] = token
    return token


def get_admin_csrf_token():
    return session.get("admin_csrf_token") or generate_admin_csrf_token()


def validate_email(value):
    email = str(value or "").strip().lower()
    if not email:
        raise ValueError("Email is required")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Please enter a valid email address")
    return email


def validate_password(value):
    password = str(value or "")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    return password


@admin_auth_bp.post("/admin/register")
def register_admin():
    payload = request.get_json(silent=True) or {}
    collection = admins_collection()

    if collection.count_documents({}) > 0 and not current_app.config["ADMIN_REGISTRATION_ENABLED"]:
        return _json_error("Admin registration is disabled", 403)

    try:
        name = str(payload.get("name", "")).strip()
        email = validate_email(payload.get("email"))
        password = validate_password(payload.get("password"))
        role = str(payload.get("role", "admin")).strip().lower() or "admin"
        if role not in {"admin", "superadmin"}:
            raise ValueError("Role must be admin or superadmin")
        if not name:
            raise ValueError("Name is required")
    except ValueError as exc:
        return _json_error(str(exc), 400)

    if collection.find_one({"email": email}):
        return _json_error("An admin with this email already exists", 409)

    if collection.count_documents({}) == 0:
        role = "superadmin"

    admin_doc = {
        "name": name,
        "email": email,
        "password": generate_password_hash(password),
        "role": role,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    inserted = collection.insert_one(admin_doc)
    admin = Admin.from_document(collection.find_one({"_id": inserted.inserted_id}))

    csrf_token = generate_admin_csrf_token()
    return _json_success(
        "Admin registered successfully",
        admin=admin.to_dict(),
        extra={"csrf_token": csrf_token},
        status=201,
    )


@admin_auth_bp.post("/admin/login")
def login_admin():
    payload = request.get_json(silent=True) or {}
    collection = admins_collection()
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    remember = bool(payload.get("remember_me", False))

    if is_rate_limited(email):
        return _json_error("Too many failed login attempts. Please try again later.", 429)

    try:
        email = validate_email(email)
        if not password:
            raise ValueError("Password is required")
    except ValueError as exc:
        return _json_error(str(exc), 400)

    admin = Admin.from_document(collection.find_one({"email": email}))
    if not admin or not check_password_hash(admin.password, password):
        record_failed_attempt(email)
        return _json_error("Invalid email or password", 401)

    clear_failed_attempts(email)
    session.clear()
    login_user(admin, remember=remember)
    csrf_token = generate_admin_csrf_token()
    return _json_success(
        "Login successful",
        admin=admin.to_dict(),
        extra={"csrf_token": csrf_token},
    )


@admin_auth_bp.post("/admin/logout")
@login_required
def logout_admin():
    logout_user()
    session.clear()
    return _json_success("Logout successful")


@admin_auth_bp.get("/admin/profile")
def admin_profile():
    if not current_user.is_authenticated:
        return _json_error("Unauthorized access", 401)
    return _json_success(
        "Profile fetched successfully",
        admin=current_user.to_dict(),
        extra={"csrf_token": get_admin_csrf_token()},
    )


@admin_auth_bp.get("/admin/dashboard")
@login_required
def admin_dashboard():
    return _json_success(
        "Dashboard loaded successfully",
        admin=current_user.to_dict(),
        extra={
            "dashboard": {
                "welcome": f"Welcome back, {current_user.name}",
                "role": current_user.role,
            }
        },
    )
