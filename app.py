from datetime import datetime, timedelta, timezone
import base64
import gzip
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
from functools import wraps
from pathlib import Path
from urllib import request as urlrequest
from urllib.parse import urlencode
import smtplib
from email.message import EmailMessage
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from bson import ObjectId
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, Response, abort, jsonify, make_response, request, send_file
from flask_cors import CORS
from flask_login import current_user
from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.errors import DuplicateKeyError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from config import Config
from extensions import login_manager
from models import Admin
from routes.admin_auth import admin_auth_bp, get_admin_csrf_token
from seo_utils import (
    SITEMAP_URL,
    SITEMAP_CACHE_SECONDS,
    SITEMAP_MAX_URLS,
    STATIC_SITEMAP_PAGES,
    build_product_seo,
    build_sitemap_index_xml,
    build_sitemap_xml,
    generate_unique_slug,
    ping_google_sitemap_async,
    slugify,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_UPLOAD_FILES = 10
MAX_CART_QUANTITY = 10
MAX_REVIEW_ATTACHMENTS = 5


# ---------------------------------------------------------------------------
# Helpers used before app context
# ---------------------------------------------------------------------------

def _safe_str(value, default="") -> str:
    """Cast to str safely, stripping whitespace."""
    return str(value or default).strip()


def _safe_float(value, default=0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default=0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    if os.getenv("TRUST_PROXY_HEADERS", "true").strip().lower() in {"1", "true", "yes"}:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    login_manager.init_app(app)
    login_manager.login_view = None
    app.register_blueprint(admin_auth_bp)

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("UPLOAD DIR: %s", UPLOAD_DIR)

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    mongo_db_name = os.getenv("MONGODB_DB", "heritage_hues")

    client = MongoClient(
        mongo_uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=10000,
    )
    db = client[mongo_db_name]

    products           = db.products
    carts              = db.carts
    orders             = db.orders
    order_status_history = db.order_status_history
    contact_messages   = db.contact_messages
    pricing_settings   = db.pricing_settings
    payment_settings   = db.payment_settings
    reviews            = db.reviews
    users              = db.users
    admins             = db.admins
    blogs              = db.blogs
    sitemap_cache: dict = {}

    # ------------------------------------------------------------------
    # Indexes
    # ------------------------------------------------------------------
    try:
        products.create_index([("slug", ASCENDING)], unique=True)
        products.create_index([("updated_at", DESCENDING)])
        carts.create_index([("session_id", ASCENDING)], unique=True)
        carts.create_index([("updated_at", DESCENDING)])
        orders.create_index([("order_ref", ASCENDING)], unique=True)
        orders.create_index([("created_at", DESCENDING)])
        order_status_history.create_index(
            [("order_id", ASCENDING), ("timestamp", DESCENDING)]
        )
        contact_messages.create_index([("created_at", DESCENDING)])
        reviews.create_index([("product_slug", ASCENDING), ("created_at", DESCENDING)])
        reviews.create_index([("created_at", DESCENDING)])
        users.create_index([("email", ASCENDING)], unique=True)
        users.create_index([("updated_at", DESCENDING)])
        users.create_index([("joined_at", DESCENDING)])
        admins.create_index([("email", ASCENDING)], unique=True)
        admins.create_index([("created_at", DESCENDING)])
        blogs.create_index(
            [("slug", ASCENDING)],
            unique=True,
            partialFilterExpression={"slug": {"$exists": True, "$type": "string"}},
        )
        blogs.create_index([("updated_at", DESCENDING)])
    except Exception as exc:
        logger.warning("Could not create indexes: %s", exc)

    # Recreate payment_id index safely
    try:
        orders.drop_index("payment_id_1")
    except Exception:
        pass
    orders.create_index(
        [("payment_id", ASCENDING)],
        unique=True,
        partialFilterExpression={"payment_id": {"$exists": True, "$type": "string"}},
        name="payment_id_1",
    )

    app.extensions["admins_collection"] = admins

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    cors_origins = os.getenv(
        "CORS_ORIGINS",
        "https://heritagehues.net,http://localhost:5173,http://localhost:5174,http://localhost:4173",
    )
    allowed_origins = [o.strip() for o in cors_origins.split(",") if o.strip()]
    CORS(
        app,
        supports_credentials=True,
        resources={
            r"/api/*": {"origins": allowed_origins},
            r"/admin/*": {"origins": allowed_origins},
        },
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Admin-Token", "X-Session-Id", "X-Use-Encryption"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        expose_headers=["Content-Length", "X-Content-Type-Options"],
    )

    # ------------------------------------------------------------------
    # Login manager hooks
    # ------------------------------------------------------------------
    @login_manager.user_loader
    def load_admin_user(admin_id):
        oid = Admin.normalize_id(admin_id)
        if not oid:
            return None
        return Admin.from_document(admins.find_one({"_id": oid}))

    @login_manager.unauthorized_handler
    def unauthorized_handler():
        return jsonify({"success": False, "message": "Unauthorized access"}), 401

    # ------------------------------------------------------------------
    # Request guards
    # ------------------------------------------------------------------
    SITEMAP_PATHS = {"/sitemap.xml", "/sitemap-static.xml", "/robots.txt"}
    SITEMAP_PREFIXES = ("/sitemap-products-", "/sitemap-blogs-")
    CSRF_EXEMPT_PATHS = {"/admin/login", "/admin/register"}
    UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    @app.before_request
    def protect_admin_endpoints():
        path = request.path

        # Always allow sitemaps/robots
        if path in SITEMAP_PATHS or path.startswith(SITEMAP_PREFIXES):
            return None

        # Return proper 204 for OPTIONS so flask-cors can add its headers
        if request.method == "OPTIONS":
            return make_response("", 204)

        # Admin API guard
        if path.startswith("/api/admin") and not is_admin_request():
            return jsonify({"error": "Admin access required"}), 403

        # CSRF guard
        needs_csrf = request.method in UNSAFE_METHODS and (
            path.startswith("/api/admin") or path == "/admin/logout"
        )
        if needs_csrf and path not in CSRF_EXEMPT_PATHS and current_user.is_authenticated:
            request_token = _safe_str(request.headers.get("X-CSRF-Token"))
            session_token = _safe_str(get_admin_csrf_token())
            if not request_token or not secrets.compare_digest(request_token, session_token):
                return jsonify({"success": False, "message": "CSRF token missing or invalid"}), 400

        return None

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------
    @app.after_request
    def set_security_headers(response):
        if response is None:
            # Defensive: should not happen after fixing OPTIONS handler
            response = make_response("", 500)

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )

        ct = response.content_type or ""
        if ct.startswith("image/"):
            response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"

        # Optional payload encryption
        if ct.startswith("application/json") and should_encrypt_response():
            payload = response.get_json(silent=True)
            if payload is not None:
                encrypted = encrypt_json_payload(payload)
                if encrypted is not None:
                    body = json.dumps(encrypted).encode()
                    response.set_data(body)
                    response.headers["Content-Type"] = "application/json"
                    response.headers["Content-Length"] = str(len(body))

        return response

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------
    def get_api_encryption_key():
        key_source = os.getenv("API_ENCRYPTION_KEY", "").strip()
        if not key_source:
            return None
        return hashlib.sha256(key_source.encode()).digest()

    def encrypt_json_payload(payload):
        key = get_api_encryption_key()
        if not key:
            return None
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return {"encrypted": base64.urlsafe_b64encode(nonce + ciphertext).decode()}

    def should_encrypt_response() -> bool:
        if not get_api_encryption_key():
            return False
        return _safe_str(request.headers.get("X-Use-Encryption")).lower() in {"1", "true", "yes"}

    def get_encryption_key() -> bytes:
        key_source = os.getenv("ENCRYPTION_KEY", os.getenv("SECRET_KEY", "")).strip()
        if not key_source:
            raise RuntimeError("ENCRYPTION_KEY or SECRET_KEY is required for UPI encryption")
        digest = hashlib.sha256(key_source.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    def get_cipher() -> Fernet:
        return Fernet(get_encryption_key())

    def encrypt_text(plaintext: str) -> str:
        value = _safe_str(plaintext)
        if not value:
            return ""
        return get_cipher().encrypt(value.encode()).decode()

    def decrypt_text(ciphertext: str) -> str:
        value = _safe_str(ciphertext)
        if not value:
            return ""
        try:
            return get_cipher().decrypt(value.encode()).decode()
        except (InvalidToken, ValueError):
            logger.warning("Failed to decrypt text — returning empty string")
            return ""

    # ------------------------------------------------------------------
    # Admin check
    # ------------------------------------------------------------------
    def is_admin_request() -> bool:
        if current_user.is_authenticated and getattr(current_user, "role", "") in {"admin", "superadmin"}:
            return True
        configured_token = os.getenv("ADMIN_API_TOKEN", "").strip()
        if not configured_token:
            return False
        provided = _safe_str(request.headers.get("X-Admin-Token"))
        return bool(provided) and secrets.compare_digest(provided, configured_token)

    def require_admin_access():
        if not is_admin_request():
            raise PermissionError("Admin access required")

    # Decorator version for cleaner route definitions
    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not is_admin_request():
                return jsonify({"error": "Admin access required"}), 403
            return f(*args, **kwargs)
        return decorated

    # ------------------------------------------------------------------
    # Pricing helpers
    # ------------------------------------------------------------------
    def get_or_create_pricing_settings() -> dict:
        defaults = {
            "_id": "global",
            "target_margin": 0.40,
            "brand_multiplier": 1.10,
            "gst_rate": 0.05,
            "minimum_margin": 0.25,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        doc = pricing_settings.find_one({"_id": "global"})
        if doc:
            missing = {k: v for k, v in defaults.items() if k not in doc}
            if missing:
                pricing_settings.update_one({"_id": "global"}, {"$set": missing})
                doc.update(missing)
            return doc
        pricing_settings.insert_one(defaults)
        return defaults

    def normalize_pricing_settings(raw: dict) -> dict:
        settings = {
            "target_margin":   _safe_float(raw.get("target_margin", 0.40)),
            "brand_multiplier": _safe_float(raw.get("brand_multiplier", 1.10)),
            "gst_rate":        _safe_float(raw.get("gst_rate", 0.05)),
            "minimum_margin":  _safe_float(raw.get("minimum_margin", 0.25)),
        }
        if not (0 <= settings["target_margin"] < 1):
            raise ValueError("target_margin must be between 0 and less than 1")
        if settings["brand_multiplier"] <= 0:
            raise ValueError("brand_multiplier must be greater than 0")
        if settings["gst_rate"] < 0:
            raise ValueError("gst_rate cannot be negative")
        if not (0 <= settings["minimum_margin"] < 1):
            raise ValueError("minimum_margin must be between 0 and less than 1")
        return settings

    def calculate_prices(
        cost_price, packaging_cost, delivery_cost, discount_percentage, settings
    ) -> dict:
        cp  = _safe_float(cost_price)
        pc  = _safe_float(packaging_cost)
        dc  = _safe_float(delivery_cost)
        dp  = _safe_float(discount_percentage)

        zero = {
            "cost_price": 0.0, "packaging_cost": 0.0, "delivery_cost": 0.0,
            "total_cost": 0.0, "base_price": 0.0, "mrp": 0.0,
            "discount_percentage": 0.0, "discount_amount": 0.0,
            "discounted_price": 0.0, "gst_amount": 0.0, "final_price": 0.0,
            "profit": 0.0, "margin": 0.0, "margin_percentage": 0.0,
        }
        if cp <= 0:
            return zero
        if pc < 0 or dc < 0:
            raise ValueError("packaging_cost and delivery_cost cannot be negative")
        if not (0 <= dp <= 100):
            raise ValueError("discount_percentage must be between 0 and 100")

        total_cost      = cp + pc + dc
        base_price      = total_cost / (1 - settings["target_margin"])
        mrp             = round(base_price * settings["brand_multiplier"], 2)
        discount_amount = mrp * (dp / 100)
        discounted      = mrp - discount_amount
        gst             = discounted * settings["gst_rate"]
        final_price     = round(discounted + gst, 2)
        profit          = final_price - total_cost
        margin          = (profit / final_price) if final_price > 0 else 0.0

        if margin < settings["minimum_margin"]:
            raise ValueError(
                f"Calculated margin {margin:.1%} is below minimum {settings['minimum_margin']:.1%}"
            )

        return {
            "cost_price": cp, "packaging_cost": pc, "delivery_cost": dc,
            "total_cost": total_cost, "base_price": base_price, "mrp": mrp,
            "discount_percentage": dp, "discount_amount": discount_amount,
            "discounted_price": discounted, "gst_amount": gst,
            "final_price": final_price, "profit": profit,
            "margin": margin, "margin_percentage": margin * 100,
        }

    # ------------------------------------------------------------------
    # Payment helpers
    # ------------------------------------------------------------------
    def get_or_create_payment_settings() -> dict:
        defaults = {
            "_id": "global",
            "upi_id_encrypted": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        doc = payment_settings.find_one({"_id": "global"})
        if doc:
            patch = {}
            if "created_at" not in doc:
                patch["created_at"] = datetime.now(timezone.utc).isoformat()
            if "updated_at" not in doc:
                patch["updated_at"] = datetime.now(timezone.utc).isoformat()
            if patch:
                payment_settings.update_one({"_id": "global"}, {"$set": patch})
                doc.update(patch)
            return doc

        env_upi = os.getenv("UPI_ID", "").strip()
        if env_upi:
            defaults["upi_id_encrypted"] = encrypt_text(env_upi)
        payment_settings.insert_one(defaults)
        return defaults

    def get_upi_id() -> str:
        doc = get_or_create_payment_settings()
        return decrypt_text(doc.get("upi_id_encrypted", ""))

    # ------------------------------------------------------------------
    # Stock helper
    # ------------------------------------------------------------------
    def get_stock_count(doc) -> int:
        raw = doc.get("stock_count")
        if raw is None:
            return 0 if bool(doc.get("is_out_of_stock", False)) else 1
        return max(0, _safe_int(raw))

    # ------------------------------------------------------------------
    # Product formatting
    # ------------------------------------------------------------------
    def format_product(doc) -> dict:
        stock_count = get_stock_count(doc)
        settings = get_or_create_pricing_settings()
        legacy_price = doc.get("price", 0)
        legacy_disc  = doc.get("discount", 0)

        result = {
            "id":                str(doc["_id"]),
            "slug":              doc.get("slug", ""),
            "title":             doc.get("title", ""),
            "category":          doc.get("category", ""),
            "description":       doc.get("description", ""),
            "cost_price":        doc.get("cost_price", 0),
            "packaging_cost":    doc.get("packaging_cost", doc.get("packaging_charge", 0)),
            "delivery_cost":     doc.get("delivery_cost", doc.get("delivery_charge", 0)),
            "discount_percentage": doc.get("discount_percentage", legacy_disc),
            "mrp":               doc.get("mrp", legacy_price),
            "discount_amount":   doc.get("discount_amount", 0),
            "discounted_price":  doc.get("discounted_price", legacy_price),
            "final_price":       doc.get("final_price", legacy_price),
            "gst_amount":        doc.get("gst_amount", 0),
            "total_cost":        doc.get("total_cost", 0),
            "profit":            doc.get("profit", doc.get("net_profit", 0)),
            "margin":            doc.get("margin", 0),
            "margin_percentage": doc.get("margin_percentage", 0),
            "stock_count":       stock_count,
            "is_out_of_stock":   bool(doc.get("is_out_of_stock", False)) or stock_count <= 0,
            "currency":          doc.get("currency", "INR"),
            "gradient":          doc.get("gradient", "linear-gradient(135deg, #772920, #cf9f64)"),
            "photos":            doc.get("photos", []),
            "description_points": doc.get("description_points", []),
            "created_at":        doc.get("created_at"),
            "updated_at":        doc.get("updated_at"),
        }

        cp = result["cost_price"]
        if cp and _safe_float(cp) > 0:
            try:
                prices = calculate_prices(
                    cp,
                    result["packaging_cost"],
                    result["delivery_cost"],
                    result["discount_percentage"],
                    settings,
                )
                result.update({k: prices[k] for k in (
                    "mrp", "discount_amount", "discounted_price", "final_price",
                    "gst_amount", "total_cost", "profit", "margin", "margin_percentage",
                )})
            except ValueError:
                pass  # Keep stored values as fallback

        return result

    def format_product_with_seo(doc) -> dict:
        product = format_product(doc)
        seo = build_product_seo(product)
        product["seo"] = seo["meta"]
        product["structured_data"] = seo["structured_data"]
        product["json_ld"] = seo["json_ld"]
        return product

    # ------------------------------------------------------------------
    # Slug helpers
    # ------------------------------------------------------------------
    def sanitize_slug(value: str) -> str:
        return slugify(value)

    def make_unique_product_slug(value, current_product_id=None) -> str:
        current_id = _safe_str(current_product_id)

        def slug_exists(candidate):
            doc = products.find_one({"slug": candidate}, {"_id": 1})
            if not doc:
                return False
            return str(doc.get("_id")) != current_id

        return generate_unique_slug(value, slug_exists)

    # ------------------------------------------------------------------
    # File upload helpers
    # ------------------------------------------------------------------
    def is_allowed_file(filename: str) -> bool:
        return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

    def build_photo_url(filename: str) -> str:
        return f"/api/uploads/{filename}"

    def save_upload(file) -> str:
        """Validate, store a single upload, return its public URL."""
        filename = secure_filename(file.filename or "")
        if not filename:
            raise ValueError("Invalid file name")
        if not is_allowed_file(filename):
            raise ValueError("Only jpg, jpeg, png, and webp files are allowed")
        ext = filename.rsplit(".", 1)[1].lower()
        stored_name = f"{secrets.token_hex(12)}.{ext}"
        file_path = UPLOAD_DIR / stored_name
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        file.save(file_path)
        logger.info("Saved upload: %s", file_path)
        return build_photo_url(stored_name)

    # ------------------------------------------------------------------
    # Money helpers
    # ------------------------------------------------------------------
    def format_money(value) -> float:
        return round(_safe_float(value), 2)

    def calculate_discounted_price(price, discount) -> float:
        """Legacy helper kept for checkout compatibility."""
        base = format_money(price)
        pct  = format_money(discount)
        return format_money(base * (1 - pct / 100))

    # ------------------------------------------------------------------
    # UPI helpers
    # ------------------------------------------------------------------
    def _upi_params(vpa: str, name: str, amount, ref: str) -> str:
        params = {
            "pa": vpa, "pn": name,
            "am": f"{format_money(amount):.2f}",
            "cu": "INR", "tn": f"Heritage Hues order {ref}", "tr": ref,
        }
        return f"upi://pay?{urlencode(params)}"

    def build_upi_url(vpa: str, name: str, amount, order_ref: str) -> str:
        return _upi_params(vpa, name, amount, order_ref)

    def build_secure_upi_link(vpa: str, amount, order_id) -> str:
        params = {
            "pa": vpa, "pn": "HeritageHue",
            "am": f"{format_money(amount):.2f}",
            "cu": "INR", "tn": f"Order#{_safe_str(order_id)}",
        }
        return f"upi://pay?{urlencode(params)}"

    # ------------------------------------------------------------------
    # Email helpers
    # ------------------------------------------------------------------
    def get_email_settings() -> dict:
        return {
            "host":       os.getenv("EMAIL_HOST", "smtp.gmail.com").strip(),
            "port":       int(os.getenv("EMAIL_PORT", "587")),
            "username":   os.getenv("EMAIL_USERNAME", "care.heritagehues@gmail.com").strip(),
            "password":   os.getenv("EMAIL_PASSWORD", "").strip(),
            "use_tls":    os.getenv("EMAIL_USE_TLS", "true").strip().lower() in ("1", "true", "yes"),
            "recipients": [
                a.strip()
                for a in os.getenv(
                    "EMAIL_RECIPIENTS",
                    os.getenv("EMAIL_USERNAME", "care.heritagehues@gmail.com"),
                ).split(",")
                if a.strip()
            ],
        }

    def send_email(subject: str, body: str, recipients=None, from_address=None):
        cfg = get_email_settings()
        if not cfg["password"]:
            raise ValueError("Email password is not configured")
        if recipients is None:
            recipients = cfg["recipients"]
        if isinstance(recipients, str):
            recipients = [recipients]
        if not recipients:
            raise ValueError("No email recipients configured")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"]    = from_address or cfg["username"]
        msg["To"]      = ", ".join(recipients)
        msg.set_content(body)

        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=20) as smtp:
            if cfg["use_tls"]:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
            smtp.login(cfg["username"], cfg["password"])
            smtp.send_message(msg)

    def format_contact_email(data: dict) -> str:
        return (
            "New contact request from Heritage Hues:\n\n"
            f"Name: {data['name']}\n"
            f"Email: {data['email']}\n\n"
            f"Message:\n{data['message']}\n"
        )

    # ------------------------------------------------------------------
    # Contact helpers
    # ------------------------------------------------------------------
    def sanitize_contact_payload(payload: dict):
        name    = _safe_str(payload.get("name"))
        email   = _safe_str(payload.get("email"))
        message = _safe_str(payload.get("message"))

        if not name:
            return None, "Name is required"
        if not email or "@" not in email or "." not in email:
            return None, "Valid email is required"
        if not message:
            return None, "Message is required"

        return {"name": name, "email": email, "message": message}, None

    def format_contact_message(doc: dict) -> dict:
        return {
            "id":         str(doc.get("_id")),
            "name":       doc.get("name", ""),
            "email":      doc.get("email", ""),
            "message":    doc.get("message", ""),
            "created_at": doc.get("created_at"),
        }

    # ------------------------------------------------------------------
    # Order helpers
    # ------------------------------------------------------------------
    FULFILLMENT_STATUSES = {
        "pending", "confirmed", "packed", "shipped",
        "out_for_delivery", "delivered", "cancelled",
    }

    def create_status_history_entry(order_id, status: str, note: str = ""):
        order_status_history.insert_one({
            "order_id":  order_id,
            "status":    status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note":      _safe_str(note),
        })

    def get_status_history(order_id) -> list:
        try:
            oid = ObjectId(order_id) if not isinstance(order_id, ObjectId) else order_id
        except Exception:
            return []
        docs = list(
            order_status_history
            .find({"order_id": oid})
            .sort("timestamp", ASCENDING)
        )
        return [
            {"status": d.get("status", ""), "timestamp": d.get("timestamp"), "note": d.get("note", "")}
            for d in docs
        ]

    def update_order_fulfillment_status(order_doc, status, note="", tracking_id=None, tracking_url=None):
        if status not in FULFILLMENT_STATUSES:
            raise ValueError("Invalid order status")
        if status == "cancelled" and order_doc.get("status") != "cancelled":
            order_doc = restore_order_stock_if_needed(order_doc)
        updates = {
            "status":            status,
            "status_updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_at":        datetime.now(timezone.utc).isoformat(),
        }
        if tracking_id is not None:
            updates["tracking_id"] = _safe_str(tracking_id)
        if tracking_url is not None:
            updates["tracking_url"] = _safe_str(tracking_url)
        updated = orders.find_one_and_update(
            {"_id": order_doc["_id"]}, {"$set": updates}, return_document=ReturnDocument.AFTER
        )
        create_status_history_entry(order_doc["_id"], status, note)
        return updated

    def format_order(doc: dict) -> dict:
        return {
            "id":               str(doc["_id"]),
            "order_id":         str(doc["_id"]),
            "order_ref":        doc.get("order_ref", ""),
            "status":           doc.get("status", ""),
            "status_updated_at": doc.get("status_updated_at"),
            "payment_status":   doc.get("payment_status", ""),
            "payment_provider": doc.get("payment_provider", ""),
            "payment_id":       doc.get("payment_id"),
            "transaction_id":   doc.get("payment_id"),
            "total_amount":     doc.get("total_amount", doc.get("total", 0)),
            "currency":         doc.get("currency", "INR"),
            "items":            doc.get("items", []),
            "address":          doc.get("address", {}),
            "tracking_id":      doc.get("tracking_id", ""),
            "tracking_url":     doc.get("tracking_url", ""),
            "is_deleted":       bool(doc.get("is_deleted", False)),
            "deleted_at":       doc.get("deleted_at"),
            "created_at":       doc.get("created_at"),
            "updated_at":       doc.get("updated_at"),
        }

    # ------------------------------------------------------------------
    # Razorpay helpers
    # ------------------------------------------------------------------
    def create_razorpay_order(amount, receipt: str):
        key_id     = os.getenv("RAZORPAY_KEY_ID", "").strip()
        key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
        if not key_id or not key_secret:
            raise ValueError("Razorpay is not configured on the server")

        payload = json.dumps({
            "amount":          int(round(_safe_float(amount) * 100)),
            "currency":        "INR",
            "receipt":         receipt,
            "payment_capture": 1,
        }).encode()
        auth = base64.b64encode(f"{key_id}:{key_secret}".encode()).decode()
        req = urlrequest.Request(
            "https://api.razorpay.com/v1/orders",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
            method="POST",
        )
        try:
            with urlrequest.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode()), key_id
        except Exception as exc:
            logger.error("Razorpay order creation failed: %s", exc)
            raise ValueError(f"Payment gateway error: {exc}") from exc

    def verify_razorpay_signature(rz_order_id: str, rz_payment_id: str, rz_signature: str) -> bool:
        key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
        if not key_secret:
            raise ValueError("Razorpay is not configured on the server")
        message  = f"{rz_order_id}|{rz_payment_id}".encode()
        expected = hmac.new(key_secret.encode(), message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, rz_signature or "")

    # ------------------------------------------------------------------
    # Cart helpers
    # ------------------------------------------------------------------
    def get_request_session_id(payload=None, required=False) -> str:
        payload = payload or {}
        sid = (
            payload.get("session_id")
            or request.args.get("session_id")
            or request.headers.get("X-Session-Id")
            or ""
        ).strip()
        if not sid and required:
            raise ValueError("session_id is required")
        return sid

    def create_session_id() -> str:
        return secrets.token_urlsafe(18)

    def get_or_create_cart(session_id=None, temporary=False) -> dict:
        sid = (_safe_str(session_id)) or create_session_id()
        now = datetime.now(timezone.utc).isoformat()
        cart = carts.find_one({"session_id": sid})
        if cart:
            return cart
        doc = {
            "user": None, "session_id": sid, "temporary": bool(temporary),
            "items": [], "created_at": now, "updated_at": now,
        }
        carts.insert_one(doc)
        return carts.find_one({"session_id": sid})

    def resolve_product_reference(ref):
        try:
            return products.find_one({"_id": ObjectId(ref)})
        except Exception:
            return products.find_one({"slug": sanitize_slug(ref)})

    def sanitize_cart_item_payload(payload: dict):
        ref = _safe_str(payload.get("product_id") or payload.get("slug"))
        if not ref:
            raise ValueError("product_id or slug is required")
        qty = _safe_int(payload.get("quantity", 1))
        if qty < 1 or qty > MAX_CART_QUANTITY:
            raise ValueError(f"quantity must be between 1 and {MAX_CART_QUANTITY}")
        return ref, qty

    def build_cart_summary_from_docs(cart_items: list) -> dict:
        summary_items = []
        subtotal = 0.0
        for item in cart_items:
            doc      = item["product"]
            stock    = get_stock_count(doc)
            quantity = item["quantity"]
            if doc.get("is_out_of_stock") or stock <= 0:
                raise ValueError(f"{doc.get('title', 'A product')} is out of stock")
            if quantity > stock:
                raise ValueError(f"Only {stock} unit(s) available for {doc.get('title', 'this product')}")
            fmt        = format_product(doc)
            unit_price = _safe_float(fmt.get("final_price"))
            line_total = unit_price * quantity
            subtotal  += line_total
            summary_items.append({
                "product_id":     fmt["id"],
                "slug":           fmt["slug"],
                "title":          fmt["title"],
                "category":       fmt["category"],
                "photos":         fmt.get("photos", []),
                "quantity":       quantity,
                "available_stock": stock,
                "unit_price":     round(unit_price, 2),
                "line_total":     round(line_total, 2),
                "currency":       fmt.get("currency", "INR"),
            })
        return {
            "items":        summary_items,
            "total_amount": round(subtotal, 2),
            "currency":     "INR",
            "notes": ["Inclusive of all taxes", "Free Delivery", "Premium Packaging Included"],
        }

    def build_cart_summary(cart_doc: dict) -> dict:
        resolved = []
        for item in cart_doc.get("items", []):
            doc = None
            if item.get("product_id"):
                try:
                    doc = products.find_one({"_id": ObjectId(item["product_id"])})
                except Exception:
                    pass
            if not doc and item.get("slug"):
                doc = products.find_one({"slug": item["slug"]})
            if doc:
                resolved.append({"product": doc, "quantity": _safe_int(item.get("quantity", 1), 1)})
        return build_cart_summary_from_docs(resolved)

    # ------------------------------------------------------------------
    # Address / user helpers
    # ------------------------------------------------------------------
    def validate_address(address) -> dict:
        if not isinstance(address, dict):
            raise ValueError("address must be an object")
        required = ["name", "phone", "address", "city", "state", "pincode"]
        normalized = {}
        for field in required:
            val = _safe_str(address.get(field))
            if not val:
                raise ValueError(f"{field} is required")
            normalized[field] = val
        email = _safe_str(address.get("email")).lower()
        if email:
            normalized["email"] = email
        return normalized

    def normalize_user_identity(payload) -> dict | None:
        if not isinstance(payload, dict):
            return None
        email = _safe_str(payload.get("email")).lower()
        if not email or "@" not in email:
            return None
        return {"name": _safe_str(payload.get("name")), "email": email}

    def build_user_email_query(email: str):
        cleaned = _safe_str(email).lower()
        if not cleaned:
            return None
        return {"$regex": f"^{re.escape(cleaned)}$", "$options": "i"}

    # ------------------------------------------------------------------
    # Review helpers
    # ------------------------------------------------------------------
    def validate_review_payload(payload: dict):
        if not isinstance(payload, dict):
            return None, "Review payload must be an object"
        name    = _safe_str(payload.get("name"))
        email   = _safe_str(payload.get("email"))
        message = _safe_str(payload.get("message"))
        try:
            rating = int(payload.get("rating"))
        except (TypeError, ValueError):
            rating = None

        if not name:
            return None, "Name is required"
        if not email or "@" not in email:
            return None, "Valid email is required"
        if not message:
            return None, "Review message is required"
        if rating is None or not (1 <= rating <= 5):
            return None, "Rating must be between 1 and 5"

        attachments = payload.get("attachments") or []
        if not isinstance(attachments, list):
            return None, "Attachments must be an array"
        clean_att = []
        for a in attachments:
            if not isinstance(a, str) or not a.strip():
                return None, "Attachments must be valid URLs"
            clean_att.append(a.strip())
        if len(clean_att) > MAX_REVIEW_ATTACHMENTS:
            return None, f"Maximum {MAX_REVIEW_ATTACHMENTS} attachments are allowed"

        return {"name": name, "email": email, "message": message, "rating": rating, "attachments": clean_att}, None

    def format_review(doc: dict) -> dict:
        return {
            "id":            str(doc.get("_id")),
            "product_slug":  doc.get("product_slug", ""),
            "product_title": doc.get("product_title", ""),
            "name":          doc.get("name", ""),
            "email":         doc.get("email", ""),
            "message":       doc.get("message", ""),
            "rating":        _safe_int(doc.get("rating")),
            "attachments":   doc.get("attachments", []),
            "created_at":    doc.get("created_at"),
            "updated_at":    doc.get("updated_at"),
        }

    def get_user_reviews(email: str) -> list:
        q = build_user_email_query(email)
        if not q:
            return []
        return [format_review(d) for d in reviews.find({"email": q}).sort("created_at", DESCENDING)]

    def count_user_reviews(email: str) -> int:
        q = build_user_email_query(email)
        return int(reviews.count_documents({"email": q})) if q else 0

    def _order_email_query(email: str) -> dict:
        q = build_user_email_query(email)
        return {
            "$or": [
                {"customer_email": q},
                {"user.email": q},
                {"address.email": q},
            ],
            "is_deleted": {"$ne": True},
        }

    def get_user_orders(email: str) -> list:
        q = build_user_email_query(email)
        if not q:
            return []
        return [format_order(d) for d in orders.find(_order_email_query(email)).sort("created_at", DESCENDING)]

    def count_user_orders(email: str) -> int:
        q = build_user_email_query(email)
        if not q:
            return 0
        return int(orders.count_documents(_order_email_query(email)))

    # ------------------------------------------------------------------
    # User formatting
    # ------------------------------------------------------------------
    def format_user(doc: dict, include_activity=True) -> dict:
        if not doc:
            return {}
        result = {
            "id":           str(doc.get("_id", "")),
            "name":         doc.get("name", ""),
            "email":        doc.get("email", ""),
            "address":      doc.get("address", ""),
            "joined_at":    doc.get("joined_at", ""),
            "last_seen_at": doc.get("last_seen_at", ""),
            "updated_at":   doc.get("updated_at", ""),
        }
        if include_activity:
            email = result["email"]
            review_list = get_user_reviews(email)
            order_list  = get_user_orders(email)
            result["review_count"] = len(review_list)
            result["order_count"]  = len(order_list)
            result["reviews"]      = review_list
            result["orders"]       = order_list
        return result

    # ------------------------------------------------------------------
    # Checkout helpers
    # ------------------------------------------------------------------
    def validate_checkout_payload(payload: dict):
        items = payload.get("items", [])
        if not isinstance(items, list) or not items:
            return None, "items must be a non-empty array"
        normalized, seen = [], set()
        for item in items:
            if not isinstance(item, dict):
                return None, "each item must be an object"
            slug = sanitize_slug(item.get("slug"))
            if not slug:
                return None, "each item must include a valid slug"
            qty = _safe_int(item.get("quantity", 1))
            if qty < 1 or qty > MAX_CART_QUANTITY:
                return None, f"quantity must be between 1 and {MAX_CART_QUANTITY}"
            if slug in seen:
                return None, "duplicate cart items are not allowed"
            seen.add(slug)
            normalized.append({"slug": slug, "quantity": qty})
        return normalized, None

    def build_checkout_summary(items: list):
        slug_map = {i["slug"]: i["quantity"] for i in items}
        docs = list(products.find({"slug": {"$in": list(slug_map)}}))
        if len(docs) != len(items):
            found   = {d.get("slug") for d in docs}
            missing = sorted(i["slug"] for i in items if i["slug"] not in found)
            return None, f"Products not found: {', '.join(missing)}"

        summary_items, subtotal = [], 0.0
        for doc in docs:
            slug      = doc.get("slug")
            quantity  = slug_map[slug]
            stock     = get_stock_count(doc)
            if doc.get("is_out_of_stock") or stock <= 0:
                return None, f"{doc.get('title', 'A product')} is out of stock"
            if quantity > stock:
                return None, f"Only {stock} unit(s) available for {doc.get('title', 'this product')}"
            unit_price = doc.get("final_price", calculate_discounted_price(doc.get("price", 0), doc.get("discount", 0)))
            line_total = format_money(unit_price * quantity)
            subtotal  += line_total
            summary_items.append({
                "slug": slug, "title": doc.get("title", ""),
                "quantity": quantity, "available_stock": stock,
                "unit_price": unit_price, "line_total": line_total,
            })

        subtotal = format_money(subtotal)
        gst      = format_money(subtotal * 0.18)
        total    = format_money(subtotal + gst)
        summary_items.sort(key=lambda x: x["slug"])
        return {"items": summary_items, "subtotal": subtotal, "gst": gst, "total": total, "currency": "INR"}, None

    # ------------------------------------------------------------------
    # Product payload validation
    # ------------------------------------------------------------------
    _ALLOWED_PRODUCT_FIELDS = {
        "slug", "title", "category", "description", "price", "discount",
        "cost_price", "packaging_cost", "delivery_cost", "discount_percentage",
        "stock_count", "is_out_of_stock", "currency", "gradient", "photos",
        "description_points",
    }

    def validate_payload(payload: dict, partial=False):
        unknown = set(payload.keys()) - _ALLOWED_PRODUCT_FIELDS
        if unknown:
            return None, f"Unsupported fields: {', '.join(sorted(unknown))}"

        data = {}

        # Title
        if not partial or "title" in payload:
            title = _safe_str(payload.get("title"))
            if not title:
                return None, "title is required"
            data["title"] = title

        # Slug
        if "slug" in payload:
            slug = sanitize_slug(payload.get("slug"))
        elif not partial:
            slug = sanitize_slug(payload.get("title"))
        else:
            slug = None
        if slug is not None:
            if not slug:
                return None, "slug is required"
            data["slug"] = slug

        if not partial or "category" in payload:
            data["category"] = _safe_str(payload.get("category")) or "General"

        if not partial or "description" in payload:
            data["description"] = _safe_str(payload.get("description"))

        if not partial or "description_points" in payload:
            pts = payload.get("description_points", [])
            if not isinstance(pts, list):
                return None, "description_points must be an array"
            data["description_points"] = [
                {"order": p.get("order", i), "point": p["point"].strip()}
                for i, p in enumerate(pts)
                if isinstance(p, dict) and isinstance(p.get("point"), str)
            ]

        for field in ("cost_price", "packaging_cost", "delivery_cost"):
            if not partial or field in payload:
                val = _safe_float(payload.get(field, 0))
                if val < 0:
                    return None, f"{field} cannot be negative"
                data[field] = val

        if not partial or "discount_percentage" in payload:
            dp = _safe_float(payload.get("discount_percentage", 0))
            if not (0 <= dp <= 100):
                return None, "discount_percentage must be between 0 and 100"
            data["discount_percentage"] = dp

        # Legacy
        if "price" in payload and "cost_price" not in payload:
            price = _safe_float(payload.get("price", 0))
            if price < 0:
                return None, "price cannot be negative"
            data["final_price"] = round(price, 2)
        if "discount" in payload and "discount_percentage" not in payload:
            disc = _safe_float(payload.get("discount", 0))
            if not (0 <= disc <= 100):
                return None, "discount must be between 0 and 100"
            data["discount_percentage"] = round(disc, 2)

        if not partial or "stock_count" in payload:
            sc = _safe_int(payload.get("stock_count", 0))
            if sc < 0:
                return None, "stock_count cannot be negative"
            data["stock_count"] = sc

        if not partial or "is_out_of_stock" in payload:
            data["is_out_of_stock"] = bool(payload.get("is_out_of_stock", False))

        if not partial or "currency" in payload:
            data["currency"] = (_safe_str(payload.get("currency")) or "INR").upper()

        if not partial or "gradient" in payload:
            data["gradient"] = _safe_str(payload.get("gradient")) or "linear-gradient(135deg, #772920, #cf9f64)"

        if not partial or "photos" in payload:
            photos = payload.get("photos", [])
            if not isinstance(photos, list):
                return None, "photos must be an array"
            if len(photos) > MAX_UPLOAD_FILES:
                return None, f"maximum {MAX_UPLOAD_FILES} photos are allowed"
            data["photos"] = [_safe_str(p) for p in photos if _safe_str(p)]

        return data, None

    # ------------------------------------------------------------------
    # Sitemap helpers
    # ------------------------------------------------------------------
    def build_static_sitemap_entries():
        now = datetime.now(timezone.utc)
        return [{"loc": p["path"], "lastmod": now, "priority": p["priority"]} for p in STATIC_SITEMAP_PAGES]

    def _build_cursor_entries(cursor, loc_fn, priority):
        return [{"loc": loc_fn(d), "lastmod": d.get("updated_at"), "priority": priority} for d in cursor.batch_size(1000)]

    def build_blog_sitemap_entries(page=None):
        cursor = blogs.find({"slug": {"$exists": True, "$ne": ""}}, {"slug": 1, "updated_at": 1}).sort("updated_at", DESCENDING)
        if page:
            cursor = cursor.skip((page - 1) * SITEMAP_MAX_URLS).limit(SITEMAP_MAX_URLS)
        return _build_cursor_entries(cursor, lambda d: f"/blog/{sanitize_slug(d.get('slug'))}", "0.7")

    def build_product_sitemap_entries(page=None):
        cursor = products.find({"slug": {"$exists": True, "$ne": ""}}, {"slug": 1, "updated_at": 1}).sort("updated_at", DESCENDING)
        if page:
            cursor = cursor.skip((page - 1) * SITEMAP_MAX_URLS).limit(SITEMAP_MAX_URLS)
        return _build_cursor_entries(cursor, lambda d: f"/product/{sanitize_slug(d.get('slug'))}", "0.9")

    def build_sitemap_entries():
        return build_static_sitemap_entries() + build_blog_sitemap_entries() + build_product_sitemap_entries()

    def build_sitemap_index_entries():
        now          = datetime.now(timezone.utc)
        entries      = [{"loc": "/sitemap-static.xml", "lastmod": now}]
        blog_count   = blogs.count_documents({"slug": {"$exists": True, "$ne": ""}})
        prod_count   = products.count_documents({"slug": {"$exists": True, "$ne": ""}})
        for page in range(1, (blog_count + SITEMAP_MAX_URLS - 1) // SITEMAP_MAX_URLS + 1):
            entries.append({"loc": f"/sitemap-blogs-{page}.xml", "lastmod": now})
        for page in range(1, (prod_count + SITEMAP_MAX_URLS - 1) // SITEMAP_MAX_URLS + 1):
            entries.append({"loc": f"/sitemap-products-{page}.xml", "lastmod": now})
        return entries

    def invalidate_sitemap_cache():
        sitemap_cache.clear()

    def get_cached_sitemap(key):
        cached = sitemap_cache.get(key)
        if not cached or cached["expires_at"] <= datetime.now(timezone.utc):
            sitemap_cache.pop(key, None)
            return None
        return cached["xml"], cached["generated_at"]

    def set_cached_sitemap(key, xml):
        at = datetime.now(timezone.utc)
        sitemap_cache[key] = {"xml": xml, "generated_at": at, "expires_at": at + timedelta(seconds=SITEMAP_CACHE_SECONDS)}
        return xml, at

    def make_sitemap_response(xml, generated_at=None):
        generated_at  = generated_at or datetime.now(timezone.utc)
        body          = xml.encode()
        use_gzip      = "gzip" in request.headers.get("Accept-Encoding", "").lower()
        response_body = gzip.compress(body) if use_gzip else body
        resp = Response(response_body, mimetype="application/xml")
        resp.headers.update({
            "Cache-Control":       f"public, max-age={SITEMAP_CACHE_SECONDS}, s-maxage={SITEMAP_CACHE_SECONDS}",
            "Content-Type":        "application/xml; charset=utf-8",
            "Last-Modified":       generated_at.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "X-Robots-Tag":        "all",
            "Vary":                "Accept-Encoding",
            "X-Content-Type-Options": "nosniff",
            "Content-Length":      str(len(response_body)),
        })
        resp.set_etag(hashlib.sha256(body).hexdigest())
        if use_gzip:
            resp.headers["Content-Encoding"] = "gzip"
        return resp

    def cached_sitemap_response(cache_key, builder):
        cached = get_cached_sitemap(cache_key)
        if cached:
            return make_sitemap_response(*cached)
        try:
            xml = builder()
        except Exception:
            logger.exception("Failed to generate sitemap: %s", cache_key)
            return jsonify({"error": "Failed to generate sitemap"}), 500
        return make_sitemap_response(*set_cached_sitemap(cache_key, xml))

    # ------------------------------------------------------------------
    # Stock deduction helper
    # ------------------------------------------------------------------
    def deduct_stock(order_items: list):
        """Validate stock then atomically deduct. Raises ValueError on insufficient stock."""
        for item in order_items:
            doc = products.find_one({"_id": ObjectId(item["product_id"])})
            if not doc:
                raise ValueError("Ordered product not found")
            if _safe_int(item.get("quantity")) > get_stock_count(doc):
                raise ValueError(f"Insufficient stock for {doc.get('title', 'product')}")
        for item in order_items:
            updated = products.find_one_and_update(
                {"_id": ObjectId(item["product_id"])},
                {"$inc": {"stock_count": -_safe_int(item["quantity"])},
                 "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}},
                return_document=ReturnDocument.AFTER,
            )
            if updated:
                remaining_stock = get_stock_count(updated)
                products.update_one(
                    {"_id": updated["_id"]},
                    {"$set": {"is_out_of_stock": remaining_stock <= 0}},
                )

    def restore_stock(order_items: list):
        """Restore previously deducted stock back to inventory."""
        for item in order_items:
            doc = products.find_one({"_id": ObjectId(item["product_id"])})
            if not doc:
                continue
            updated = products.find_one_and_update(
                {"_id": doc["_id"]},
                {"$inc": {"stock_count": _safe_int(item["quantity"])},
                 "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}},
                return_document=ReturnDocument.AFTER,
            )
            if updated:
                remaining_stock = get_stock_count(updated)
                products.update_one(
                    {"_id": updated["_id"]},
                    {"$set": {"is_out_of_stock": remaining_stock <= 0}},
                )

    def ensure_order_stock_deducted(order_doc: dict) -> dict:
        if bool(order_doc.get("stock_deducted")):
            return order_doc
        deduct_stock(order_doc.get("items", []))
        return orders.find_one_and_update(
            {"_id": order_doc["_id"]},
            {
                "$set": {
                    "stock_deducted": True,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            return_document=ReturnDocument.AFTER,
        )

    def restore_order_stock_if_needed(order_doc: dict) -> dict:
        if not bool(order_doc.get("stock_deducted")):
            return order_doc
        restore_stock(order_doc.get("items", []))
        return orders.find_one_and_update(
            {"_id": order_doc["_id"]},
            {
                "$set": {
                    "stock_deducted": False,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            return_document=ReturnDocument.AFTER,
        )

    def clear_cart_after_payment(session_id: str):
        carts.update_one(
            {"session_id": session_id},
            {"$set": {"items": [], "updated_at": datetime.now(timezone.utc).isoformat()}},
        )

    # ==================================================================
    # ROUTES
    # ==================================================================

    # ---- Health -------------------------------------------------------
    @app.get("/api/health")
    def health():
        try:
            client.admin.command("ping")
            db_status = "ok"
        except Exception:
            db_status = "unreachable"
        return jsonify({"status": "ok", "db": db_status})

    # ---- Sitemaps -----------------------------------------------------
    @app.get("/sitemap.xml")
    def sitemap_xml():
        def build():
            total = (
                len(STATIC_SITEMAP_PAGES)
                + blogs.count_documents({"slug": {"$exists": True, "$ne": ""}})
                + products.count_documents({"slug": {"$exists": True, "$ne": ""}})
            )
            return build_sitemap_index_xml(build_sitemap_index_entries()) if total > SITEMAP_MAX_URLS else build_sitemap_xml(build_sitemap_entries())
        return cached_sitemap_response("root", build)

    @app.get("/sitemap-static.xml")
    def sitemap_static_xml():
        return cached_sitemap_response("static", lambda: build_sitemap_xml(build_static_sitemap_entries()))

    @app.get("/sitemap-blogs-<int:page>.xml")
    def sitemap_blogs_xml(page):
        if page < 1:
            abort(404)
        return cached_sitemap_response(f"blogs:{page}", lambda: build_sitemap_xml(build_blog_sitemap_entries(page=page)))

    @app.get("/sitemap-products-<int:page>.xml")
    def sitemap_products_xml(page):
        if page < 1:
            abort(404)
        return cached_sitemap_response(f"products:{page}", lambda: build_sitemap_xml(build_product_sitemap_entries(page=page)))

    @app.get("/robots.txt")
    def robots_txt():
        content = "\n".join([
            "User-agent: *", "Allow: /",
            "Disallow: /admin/", "Disallow: /dashboard/",
            f"Sitemap: {SITEMAP_URL}", "",
        ])
        resp = Response(content, mimetype="text/plain")
        resp.headers["Cache-Control"] = f"public, max-age={SITEMAP_CACHE_SECONDS}, s-maxage={SITEMAP_CACHE_SECONDS}"
        resp.headers["X-Robots-Tag"]  = "all"
        return resp

    # ---- Contact ------------------------------------------------------
    @app.post("/api/contact")
    def submit_contact():
        payload = request.get_json(silent=True) or {}
        data, err = sanitize_contact_payload(payload)
        if err:
            return jsonify({"error": err}), 400

        now = datetime.now(timezone.utc).isoformat()
        doc = {**data, "created_at": now, "updated_at": now}
        contact_messages.insert_one(doc)

        email_error = None
        if os.getenv("EMAIL_PASSWORD", "").strip():
            try:
                send_email(
                    subject=f"New contact from {data['name']}",
                    body=format_contact_email(data),
                    recipients=os.getenv("EMAIL_RECIPIENTS", os.getenv("EMAIL_USERNAME", "")),
                    from_address=os.getenv("EMAIL_USERNAME", ""),
                )
            except Exception as exc:
                logger.error("Email send error: %s", exc)
                email_error = str(exc)

        result = format_contact_message(doc)
        if email_error:
            result["email_error"] = email_error
        return jsonify(result), 201

    @app.get("/api/admin/contacts")
    @admin_required
    def admin_list_contacts():
        docs = list(contact_messages.find().sort("created_at", DESCENDING))
        return jsonify([format_contact_message(d) for d in docs])

    @app.delete("/api/admin/contacts/<string:message_id>")
    @admin_required
    def admin_delete_contact(message_id):
        try:
            oid = ObjectId(message_id)
        except Exception:
            return jsonify({"error": "Invalid message id"}), 400
        result = contact_messages.delete_one({"_id": oid})
        if result.deleted_count == 0:
            return jsonify({"error": "Message not found"}), 404
        return jsonify({"message": "Contact message deleted"})

    # ---- Uploads ------------------------------------------------------
    @app.get("/api/uploads/<filename>")
    def serve_upload(filename):
        # Prevent path traversal
        safe = secure_filename(filename)
        if not safe or safe != filename:
            return jsonify({"error": "Invalid filename"}), 400
        file_path = UPLOAD_DIR / safe
        if not file_path.exists() or not file_path.is_file():
            return jsonify({"error": "File not found"}), 404
        mime, _ = mimetypes.guess_type(str(file_path))
        return send_file(file_path, mimetype=mime or "application/octet-stream")

    @app.get("/api/debug/uploads")
    def debug_uploads():
        return jsonify({"upload_dir": str(UPLOAD_DIR), "files": [f.name for f in UPLOAD_DIR.glob("*")]})

    @app.post("/api/admin/uploads")
    @admin_required
    def upload_product_photos():
        files = request.files.getlist("photos")
        if not files or not any(f.filename for f in files):
            return jsonify({"error": "No files uploaded"}), 400
        if len(files) > MAX_UPLOAD_FILES:
            return jsonify({"error": f"maximum {MAX_UPLOAD_FILES} photos are allowed"}), 400
        try:
            uploaded = [save_upload(f) for f in files]
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"photos": uploaded}), 201

    @app.post("/api/uploads/review-images")
    def upload_review_attachment():
        attachment = request.files.get("attachment")
        if not attachment:
            return jsonify({"error": "No attachment file uploaded"}), 400
        try:
            url = save_upload(attachment)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"url": url}), 201

    # ---- Products (public) --------------------------------------------
    @app.get("/api/products")
    def list_products():
        docs = products.find().sort("updated_at", DESCENDING)
        return jsonify([format_product(d) for d in docs])

    @app.get("/api/products/<string:slug>")
    def get_product(slug):
        doc = products.find_one({"slug": sanitize_slug(slug)})
        if not doc:
            return jsonify({"error": "Product not found"}), 404
        return jsonify(format_product_with_seo(doc))

    @app.get("/product/<string:slug>")
    def get_product_page_data(slug):
        doc = products.find_one({"slug": sanitize_slug(slug)})
        if not doc:
            return jsonify({"error": "Product not found"}), 404
        return jsonify(format_product_with_seo(doc))

    # ---- Products (admin) ---------------------------------------------
    @app.post("/api/admin/products")
    @admin_required
    def create_product():
        payload = request.get_json(silent=True) or {}
        data, err = validate_payload(payload, partial=False)
        if err:
            return jsonify({"error": err}), 400
        data["slug"] = make_unique_product_slug(data.get("slug") or data.get("title"))
        try:
            settings = normalize_pricing_settings(get_or_create_pricing_settings())
            prices   = calculate_prices(data["cost_price"], data.get("packaging_cost", 0), data.get("delivery_cost", 0), data["discount_percentage"], settings)
            data.update({k: prices[k] for k in ("mrp","discount_amount","discounted_price","final_price","gst_amount","total_cost","profit","margin","margin_percentage")})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        data["is_out_of_stock"] = _safe_int(data.get("stock_count", 0)) <= 0
        now = datetime.now(timezone.utc).isoformat()
        data["created_at"] = data["updated_at"] = now
        try:
            result = products.insert_one(data)
        except DuplicateKeyError:
            return jsonify({"error": "A product with this slug already exists"}), 409
        created = products.find_one({"_id": result.inserted_id})
        invalidate_sitemap_cache()
        ping_google_sitemap_async()
        return jsonify(format_product(created)), 201

    @app.put("/api/admin/products/<string:product_id>")
    @admin_required
    def update_product(product_id):
        payload = request.get_json(silent=True) or {}
        data, err = validate_payload(payload, partial=True)
        if err:
            return jsonify({"error": err}), 400
        if not data:
            return jsonify({"error": "No valid fields to update"}), 400
        try:
            oid = ObjectId(product_id)
        except Exception:
            return jsonify({"error": "Invalid product id"}), 400
        existing = products.find_one({"_id": oid})
        if not existing:
            return jsonify({"error": "Product not found"}), 404
        if "slug" in data:
            data["slug"] = make_unique_product_slug(data["slug"], current_product_id=oid)
        if {"cost_price","packaging_cost","delivery_cost","discount_percentage"} & set(data.keys()):
            try:
                settings = normalize_pricing_settings(get_or_create_pricing_settings())
                prices = calculate_prices(
                    _safe_float(data.get("cost_price", existing.get("cost_price", 0))),
                    _safe_float(data.get("packaging_cost", existing.get("packaging_cost", existing.get("packaging_charge", 0)))),
                    _safe_float(data.get("delivery_cost", existing.get("delivery_cost", existing.get("delivery_charge", 0)))),
                    _safe_float(data.get("discount_percentage", existing.get("discount_percentage", existing.get("discount", 0)))),
                    settings,
                )
                data.update({k: prices[k] for k in ("mrp","discount_amount","discounted_price","final_price","gst_amount","total_cost","profit","margin","margin_percentage")})
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
        data["is_out_of_stock"] = _safe_int(data.get("stock_count", existing.get("stock_count", 0))) <= 0
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        try:
            updated = products.find_one_and_update({"_id": oid}, {"$set": data}, return_document=ReturnDocument.AFTER)
        except DuplicateKeyError:
            return jsonify({"error": "A product with this slug already exists"}), 409
        if not updated:
            return jsonify({"error": "Product not found"}), 404
        invalidate_sitemap_cache()
        return jsonify(format_product(updated))

    @app.delete("/api/admin/products/<string:product_id>")
    @admin_required
    def delete_product(product_id):
        try:
            oid = ObjectId(product_id)
        except Exception:
            return jsonify({"error": "Invalid product id"}), 400
        result = products.delete_one({"_id": oid})
        if result.deleted_count == 0:
            return jsonify({"error": "Product not found"}), 404
        invalidate_sitemap_cache()
        return jsonify({"message": "Product deleted"})

    # ---- Reviews ------------------------------------------------------
    @app.get("/api/products/<string:slug>/reviews")
    def get_product_reviews(slug):
        docs = reviews.find({"product_slug": sanitize_slug(slug)}).sort("created_at", DESCENDING)
        return jsonify([format_review(d) for d in docs])

    @app.post("/api/products/<string:slug>/reviews")
    def create_product_review(slug):
        payload = request.get_json(silent=True) or {}
        data, err = validate_review_payload(payload)
        if err:
            return jsonify({"error": err}), 400
        data["email"] = data["email"].strip().lower()
        doc = products.find_one({"slug": sanitize_slug(slug)})
        if not doc:
            return jsonify({"error": "Product not found"}), 404
        now = datetime.now(timezone.utc).isoformat()
        review_doc = {
            "product_id": doc["_id"], "product_slug": doc.get("slug", ""),
            "product_title": doc.get("title", ""), **data,
            "created_at": now, "updated_at": now,
        }
        result = reviews.insert_one(review_doc)
        return jsonify(format_review(reviews.find_one({"_id": result.inserted_id}))), 201

    @app.get("/api/admin/reviews")
    @admin_required
    def get_admin_reviews():
        return jsonify([format_review(d) for d in reviews.find().sort("created_at", DESCENDING)])

    @app.delete("/api/admin/reviews/<string:review_id>")
    @admin_required
    def delete_admin_review(review_id):
        try:
            oid = ObjectId(review_id)
        except Exception:
            return jsonify({"error": "Invalid review id"}), 400
        if reviews.delete_one({"_id": oid}).deleted_count == 0:
            return jsonify({"error": "Review not found"}), 404
        return jsonify({"message": "Review deleted"})

    # ---- Users --------------------------------------------------------
    @app.post("/api/users")
    def create_or_update_user():
        payload = request.get_json(silent=True) or {}
        name    = _safe_str(payload.get("name"))
        email   = _safe_str(payload.get("email")).lower()
        address = _safe_str(payload.get("address"))
        if not name:
            return jsonify({"error": "Name is required."}), 400
        if not email or "@" not in email:
            return jsonify({"error": "A valid email address is required."}), 400
        now = datetime.now(timezone.utc).isoformat()
        try:
            users.update_one(
                {"email": email},
                {"$set": {"name": name, "address": address, "last_seen_at": now, "updated_at": now},
                 "$setOnInsert": {"email": email, "joined_at": now}},
                upsert=True,
            )
            return jsonify(format_user(users.find_one({"email": email}))), 200
        except Exception as exc:
            logger.error("User upsert error: %s", exc)
            return jsonify({"error": "Failed to save user record."}), 500

    @app.get("/api/admin/users")
    @admin_required
    def get_admin_users():
        docs      = users.find().sort([("last_seen_at", DESCENDING), ("updated_at", DESCENDING), ("joined_at", DESCENDING)])
        user_list = []
        for doc in docs:
            email = _safe_str(doc.get("email"))
            if not email:
                continue
            ud = format_user(doc, include_activity=False)
            ud["review_count"] = count_user_reviews(email)
            ud["order_count"]  = count_user_orders(email)
            user_list.append(ud)
        return jsonify(user_list)

    @app.delete("/api/admin/users/<string:email>")
    @admin_required
    def delete_admin_user(email):
        cleaned = _safe_str(email).lower()
        if not cleaned:
            return jsonify({"error": "Invalid email address"}), 400
        users.delete_one({"email": cleaned})
        result = reviews.delete_many({"email": cleaned})
        return jsonify({"message": f"Deleted user record and {result.deleted_count} review(s) for {cleaned}"})

    # ---- Cart ---------------------------------------------------------
    @app.get("/api/cart")
    def get_cart():
        try:
            sid     = get_request_session_id(required=False)
            cart    = get_or_create_cart(session_id=sid)
            summary = build_cart_summary(cart)
            return jsonify({"session_id": cart["session_id"], **summary})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/cart/items")
    def add_cart_item():
        payload = request.get_json(silent=True) or {}
        try:
            sid       = get_request_session_id(payload)
            ref, qty  = sanitize_cart_item_payload(payload)
            doc       = resolve_product_reference(ref)
            if not doc:
                return jsonify({"error": "Product not found"}), 404
            stock = get_stock_count(doc)
            if doc.get("is_out_of_stock") or stock <= 0:
                return jsonify({"error": "Product is out of stock"}), 400
            cart     = get_or_create_cart(session_id=sid)
            items    = list(cart.get("items", []))
            pid      = str(doc["_id"])
            existing = next((i for i in items if i.get("product_id") == pid), None)
            new_qty  = qty + _safe_int(existing.get("quantity")) if existing else qty
            if new_qty > stock:
                return jsonify({"error": f"Only {stock} unit(s) available"}), 400
            if existing:
                existing["quantity"] = new_qty
            else:
                items.append({"product_id": pid, "slug": doc.get("slug"), "quantity": qty})
            carts.find_one_and_update(
                {"session_id": cart["session_id"]},
                {"$set": {"items": items, "updated_at": datetime.now(timezone.utc).isoformat()}},
                return_document=ReturnDocument.AFTER,
            )
            updated = carts.find_one({"session_id": cart["session_id"]})
            summary = build_cart_summary(updated)
            return jsonify({"session_id": updated["session_id"], **summary}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.put("/api/cart/items/<string:item_ref>")
    def update_cart_item(item_ref):
        payload = request.get_json(silent=True) or {}
        try:
            sid = get_request_session_id(payload, required=True)
            _, qty = sanitize_cart_item_payload({"product_id": item_ref, "quantity": payload.get("quantity", 1)})
            cart = carts.find_one({"session_id": sid})
            if not cart:
                return jsonify({"error": "Cart not found"}), 404
            resolved = resolve_product_reference(item_ref)
            pid   = str(resolved["_id"]) if resolved else item_ref
            items = list(cart.get("items", []))
            target = next((i for i in items if i.get("product_id") == pid or i.get("slug") == sanitize_slug(item_ref)), None)
            if not target:
                return jsonify({"error": "Cart item not found"}), 404
            doc = resolve_product_reference(target.get("product_id") or target.get("slug"))
            if not doc:
                return jsonify({"error": "Product not found"}), 404
            if qty > get_stock_count(doc):
                return jsonify({"error": f"Only {get_stock_count(doc)} unit(s) available"}), 400
            target["quantity"] = qty
            carts.update_one({"session_id": sid}, {"$set": {"items": items, "updated_at": datetime.now(timezone.utc).isoformat()}})
            summary = build_cart_summary(carts.find_one({"session_id": sid}))
            return jsonify({"session_id": sid, **summary})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.delete("/api/cart/items/<string:item_ref>")
    def remove_cart_item(item_ref):
        payload = request.get_json(silent=True) or {}
        try:
            sid  = get_request_session_id(payload, required=True)
            cart = carts.find_one({"session_id": sid})
            if not cart:
                return jsonify({"error": "Cart not found"}), 404
            slug       = sanitize_slug(item_ref)
            next_items = [i for i in cart.get("items", []) if i.get("product_id") != item_ref and i.get("slug") != slug]
            carts.update_one({"session_id": sid}, {"$set": {"items": next_items, "updated_at": datetime.now(timezone.utc).isoformat()}})
            summary = build_cart_summary(carts.find_one({"session_id": sid}))
            return jsonify({"session_id": sid, **summary})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/buy-now")
    def buy_now():
        payload = request.get_json(silent=True) or {}
        try:
            ref, qty = sanitize_cart_item_payload(payload)
            doc      = resolve_product_reference(ref)
            if not doc:
                return jsonify({"error": "Product not found"}), 404
            stock = get_stock_count(doc)
            if doc.get("is_out_of_stock") or stock <= 0:
                return jsonify({"error": "Product is out of stock"}), 400
            if qty > stock:
                return jsonify({"error": f"Only {stock} unit(s) available"}), 400
            cart = get_or_create_cart(session_id=create_session_id(), temporary=True)
            carts.update_one(
                {"session_id": cart["session_id"]},
                {"$set": {"items": [{"product_id": str(doc["_id"]), "slug": doc.get("slug"), "quantity": qty}],
                          "updated_at": datetime.now(timezone.utc).isoformat()}},
            )
            return jsonify({"session_id": cart["session_id"], "checkout_url": f"/checkout?session_id={cart['session_id']}"}), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    # ---- Checkout / Orders --------------------------------------------
    @app.post("/api/checkout/summary")
    def checkout_summary():
        payload = request.get_json(silent=True) or {}
        try:
            sid  = get_request_session_id(payload, required=True)
            cart = carts.find_one({"session_id": sid})
            if not cart:
                return jsonify({"error": "Cart not found"}), 404
            address = validate_address(payload["address"]) if payload.get("address") else None
            summary = build_cart_summary(cart)
            return jsonify({"session_id": sid, "address": address, **summary})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    def _build_order_doc(summary, session_id, address, user_identity, payment_provider, extra=None):
        now       = datetime.now(timezone.utc).isoformat()
        order_ref = f"HH{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{secrets.token_hex(3).upper()}"
        doc = {
            "user":            user_identity,
            "customer_email":  _safe_str((user_identity or {}).get("email") or address.get("email", "")).lower(),
            "session_id":      session_id,
            "order_ref":       order_ref,
            "address":         address,
            "items": [
                {"product_id": i["product_id"], "slug": i["slug"], "title": i["title"],
                 "quantity": i["quantity"], "price_at_purchase": i["unit_price"]}
                for i in summary["items"]
            ],
            "total_amount":    summary["total_amount"],
            "currency":        summary["currency"],
            "status":          "pending",
            "status_updated_at": now,
            "tracking_id":     "",
            "tracking_url":    "",
            "payment_provider": payment_provider,
            "payment_status":  "pending",
            "stock_deducted":  False,
            "created_at":      now,
            "updated_at":      now,
        }
        if extra:
            doc.update(extra)
        return doc, order_ref

    @app.post("/api/orders")
    def create_order():
        payload = request.get_json(silent=True) or {}
        try:
            sid           = get_request_session_id(payload, required=True)
            address       = validate_address(payload.get("address", {}))
            user_identity = normalize_user_identity(payload.get("user"))
            cart          = carts.find_one({"session_id": sid})
            if not cart or not cart.get("items"):
                return jsonify({"error": "Cart is empty"}), 400
            summary              = build_cart_summary(cart)
            rz_order, key_id = create_razorpay_order(summary["total_amount"], f"tmp_{secrets.token_hex(4)}")
            order_doc, order_ref = _build_order_doc(
                summary, sid, address, user_identity, "razorpay",
                extra={"payment_status": "pending", "payment_order_id": rz_order.get("id")},
            )
            deduct_stock(order_doc["items"])
            order_doc["stock_deducted"] = True
            orders.insert_one(order_doc)
            created = orders.find_one({"order_ref": order_ref})
            create_status_history_entry(created["_id"], "pending", "Order created and stock deducted")
            return jsonify({
                "order_id": str(created["_id"]), "order_ref": order_ref,
                "total_amount": summary["total_amount"], "currency": summary["currency"],
                "items": summary["items"], "notes": summary["notes"],
                "razorpay": {
                    "key": key_id, "order_id": rz_order.get("id"),
                    "amount": rz_order.get("amount"), "currency": rz_order.get("currency", "INR"),
                    "name": "Heritage Hues", "description": f"Order {order_ref}",
                    "prefill": {"name": address["name"], "contact": address["phone"]},
                },
            }), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            logger.exception("create_order error")
            return jsonify({"error": str(exc)}), 500

    @app.post("/api/orders/upi")
    def create_upi_order():
        vpa  = get_upi_id()
        name = os.getenv("UPI_PAYEE_NAME", "Heritage Hues").strip() or "Heritage Hues"
        if not vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500
        payload = request.get_json(silent=True) or {}
        try:
            sid           = get_request_session_id(payload, required=True)
            address       = validate_address(payload.get("address", {}))
            user_identity = normalize_user_identity(payload.get("user"))
            cart          = carts.find_one({"session_id": sid})
            if not cart or not cart.get("items"):
                return jsonify({"error": "Cart is empty"}), 400
            summary              = build_cart_summary(cart)
            order_doc, order_ref = _build_order_doc(
                summary, sid, address, user_identity, "upi",
                extra={"payment_status": "payment_pending"},
            )
            deduct_stock(order_doc["items"])
            order_doc["stock_deducted"] = True
            orders.insert_one(order_doc)
            created = orders.find_one({"order_ref": order_ref})
            create_status_history_entry(created["_id"], "pending", "Order created and stock deducted")
            return jsonify({
                "order_id": str(created["_id"]), "order_ref": order_ref,
                "total_amount": summary["total_amount"], "currency": summary["currency"],
                "items": summary["items"], "notes": summary["notes"],
            }), 201
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            logger.exception("create_upi_order error")
            return jsonify({"error": str(exc)}), 500

    @app.get("/api/payment/upi-link/<string:order_id>")
    def get_payment_upi_link(order_id):
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400
        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        if order.get("payment_provider") != "upi":
            return jsonify({"error": "UPI link is only available for UPI orders"}), 400
        amount = order.get("total_amount")
        if amount is None:
            return jsonify({"error": "Order amount missing"}), 400
        vpa = get_upi_id()
        if not vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500
        return jsonify({"upi_link": build_secure_upi_link(vpa, amount, order_id)})

    @app.post("/api/orders/confirm-upi")
    def confirm_upi_order():
        payload        = request.get_json(silent=True) or {}
        order_id       = _safe_str(payload.get("order_id"))
        transaction_id = _safe_str(payload.get("transaction_id"))
        if not order_id or not transaction_id:
            return jsonify({"error": "order_id and transaction_id are required"}), 400
        if len(transaction_id) < 6:
            return jsonify({"error": "transaction_id looks too short"}), 400
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400
        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        if order.get("payment_provider") != "upi":
            return jsonify({"error": "Order is not a UPI order"}), 400
        updated = orders.find_one_and_update(
            {"_id": oid},
            {"$set": {"payment_status": "verification_pending", "payment_id": transaction_id,
                      "updated_at": datetime.now(timezone.utc).isoformat()}},
            return_document=ReturnDocument.AFTER,
        )
        return jsonify({
            "order_id":  str(updated["_id"]), "order_ref": updated["order_ref"],
            "status":    updated["status"],   "payment_id": updated["payment_id"],
            "message":   "Payment submitted for verification",
        })

    @app.post("/api/orders/verify-payment")
    def verify_order_payment():
        payload           = request.get_json(silent=True) or {}
        order_id          = _safe_str(payload.get("order_id"))
        rz_order_id       = _safe_str(payload.get("razorpay_order_id"))
        rz_payment_id     = _safe_str(payload.get("razorpay_payment_id"))
        rz_signature      = _safe_str(payload.get("razorpay_signature"))
        if not all([order_id, rz_order_id, rz_payment_id, rz_signature]):
            return jsonify({"error": "order_id, razorpay_order_id, razorpay_payment_id, and razorpay_signature are required"}), 400
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400
        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        if order.get("payment_order_id") != rz_order_id:
            return jsonify({"error": "Payment order mismatch"}), 400
        try:
            if not verify_razorpay_signature(rz_order_id, rz_payment_id, rz_signature):
                return jsonify({"error": "Invalid payment signature"}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            order = ensure_order_stock_deducted(order)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        updated = orders.find_one_and_update(
            {"_id": oid},
            {"$set": {"payment_status": "paid", "payment_id": rz_payment_id,
                      "updated_at": datetime.now(timezone.utc).isoformat()}},
            return_document=ReturnDocument.AFTER,
        )
        clear_cart_after_payment(order.get("session_id", ""))
        return jsonify({"order_id": str(updated["_id"]), "order_ref": updated["order_ref"],
                        "status": updated["status"], "payment_id": updated["payment_id"]})

    # ---- Orders (public) ----------------------------------------------
    @app.get("/api/order/<string:order_id>")
    def get_order_details(order_id):
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400
        order = orders.find_one({"_id": oid})
        if not order or bool(order.get("is_deleted")):
            return jsonify({"error": "Order not found"}), 404
        sid = get_request_session_id(required=False)
        if not is_admin_request() and sid != _safe_str(order.get("session_id")):
            return jsonify({"error": "You can only view your own orders"}), 403
        result = format_order(order)
        result["status_history"] = get_status_history(oid)
        return jsonify(result)

    # ---- Orders (admin) -----------------------------------------------
    @app.get("/api/admin/orders")
    @admin_required
    def admin_list_orders():
        status          = _safe_str(request.args.get("status"))
        payment_status  = _safe_str(request.args.get("payment_status"))
        include_deleted = _safe_str(request.args.get("include_deleted")).lower() in {"1","true","yes"}
        query = {} if include_deleted else {"is_deleted": {"$ne": True}}
        if status:
            query["status"] = status
        if payment_status:
            query["payment_status"] = payment_status
        docs = list(orders.find(query).sort("created_at", DESCENDING))
        return jsonify([format_order(d) for d in docs])

    @app.patch("/api/admin/orders/<string:order_id>/status")
    @admin_required
    def admin_update_order_status(order_id):
        payload      = request.get_json(silent=True) or {}
        status       = _safe_str(payload.get("status"))
        note         = _safe_str(payload.get("note"))
        tracking_id  = payload.get("tracking_id")
        tracking_url = payload.get("tracking_url")
        if not status:
            return jsonify({"error": "status is required"}), 400
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400
        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        try:
            updated = update_order_fulfillment_status(order, status, note, tracking_id, tracking_url)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        result = format_order(updated)
        result["status_history"] = get_status_history(oid)
        return jsonify(result)

    @app.post("/api/admin/orders/<string:order_id>/soft-delete")
    @admin_required
    def admin_soft_delete_order(order_id):
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400
        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        if bool(order.get("is_deleted")):
            return jsonify({"error": "Order is already deleted"}), 400
        if order.get("payment_status") != "paid":
            order = restore_order_stock_if_needed(order)
        now = datetime.now(timezone.utc).isoformat()
        updated = orders.find_one_and_update(
            {"_id": oid},
            {"$set": {"is_deleted": True, "deleted_at": now, "updated_at": now}},
            return_document=ReturnDocument.AFTER,
        )
        return jsonify(format_order(updated))

    @app.post("/api/admin/orders/<string:order_id>/approve-payment")
    @admin_required
    def admin_approve_order_payment(order_id):
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400
        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        if order.get("payment_provider") != "upi":
            return jsonify({"error": "Only UPI orders can be approved here"}), 400
        if order.get("payment_status") == "paid":
            return jsonify({"error": "Order is already marked paid"}), 400
        if order.get("payment_status") != "verification_pending":
            return jsonify({"error": "Order is not awaiting verification"}), 400
        try:
            order = ensure_order_stock_deducted(order)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        updated = orders.find_one_and_update(
            {"_id": oid},
            {"$set": {"payment_status": "paid", "updated_at": datetime.now(timezone.utc).isoformat()}},
            return_document=ReturnDocument.AFTER,
        )
        clear_cart_after_payment(order.get("session_id", ""))
        return jsonify(format_order(updated))

    # ---- Pricing ------------------------------------------------------
    @app.post("/api/pricing/calculate")
    def pricing_calculate():
        payload = request.get_json(silent=True) or {}
        try:
            base     = get_or_create_pricing_settings()
            settings = normalize_pricing_settings({**base, **(payload.get("settings") or {})})
            prices   = calculate_prices(
                _safe_float(payload.get("cost_price")),
                _safe_float(payload.get("packaging_cost")),
                _safe_float(payload.get("delivery_cost")),
                _safe_float(payload.get("discount_percentage")),
                settings,
            )
            return jsonify(prices)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/api/admin/pricing-settings")
    @admin_required
    def get_pricing_settings():
        try:
            settings = normalize_pricing_settings(get_or_create_pricing_settings())
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        settings["upi_id"] = decrypt_text(get_or_create_payment_settings().get("upi_id_encrypted", ""))
        return jsonify(settings)

    @app.put("/api/admin/pricing-settings")
    @admin_required
    def update_pricing_settings():
        payload = request.get_json(silent=True) or {}
        upi_id  = payload.get("upi_id")
        try:
            current    = get_or_create_pricing_settings()
            normalized = normalize_pricing_settings({**current, **payload})
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        normalized["updated_at"] = datetime.now(timezone.utc).isoformat()
        pricing_settings.find_one_and_update({"_id": "global"}, {"$set": normalized}, upsert=True, return_document=ReturnDocument.AFTER)
        if upi_id is not None:
            now = datetime.now(timezone.utc).isoformat()
            payment_settings.find_one_and_update(
                {"_id": "global"},
                {"$set": {"upi_id_encrypted": encrypt_text(upi_id), "updated_at": now},
                 "$setOnInsert": {"created_at": now}},
                upsert=True,
            )
            normalized["upi_id"] = _safe_str(upi_id)
        else:
            normalized["upi_id"] = decrypt_text(get_or_create_payment_settings().get("upi_id_encrypted", ""))
        return jsonify(normalized)

    # ---- Legacy UPI intent/link (kept for compat) ---------------------
    @app.post("/api/checkout/upi-intent")
    def create_upi_intent():
        vpa  = get_upi_id()
        name = os.getenv("UPI_PAYEE_NAME", "Heritage Hues").strip() or "Heritage Hues"
        if not vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500
        payload = request.get_json(silent=True) or {}
        items, err = validate_checkout_payload(payload)
        if err:
            return jsonify({"error": err}), 400
        summary, err = build_checkout_summary(items)
        if err:
            return jsonify({"error": err}), 400
        now       = datetime.now(timezone.utc).isoformat()
        order_ref = f"HH{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{secrets.token_hex(3).upper()}"
        orders.insert_one({
            "order_ref": order_ref, "items": summary["items"],
            "subtotal": summary["subtotal"], "gst": summary["gst"],
            "total": summary["total"], "currency": summary["currency"],
            "payment_method": "upi_intent", "payment_status": "pending",
            "created_at": now, "updated_at": now,
        })
        return jsonify({
            "order_ref": order_ref, "upi_url": build_upi_url(vpa, name, summary["total"], order_ref),
            "summary": summary, "message": "Redirecting to your default UPI app.",
        })

    @app.post("/api/checkout/upi-link")
    def create_upi_link():
        payload  = request.get_json(silent=True) or {}
        order_id = _safe_str(payload.get("order_id"))
        if not order_id:
            return jsonify({"error": "order_id is required"}), 400
        try:
            amount = float(payload.get("amount", 0))
        except (TypeError, ValueError):
            return jsonify({"error": "amount must be a number"}), 400
        if amount <= 0:
            return jsonify({"error": "amount must be greater than zero"}), 400
        vpa = get_upi_id()
        if not vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500
        return jsonify({"upi_link": build_secure_upi_link(vpa, amount, order_id)})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
