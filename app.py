from datetime import datetime, timedelta, timezone
import base64
import gzip
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
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

from flask import Flask, Response, abort, jsonify, make_response, request, send_file, url_for
from flask_cors import CORS, cross_origin
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

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    if os.getenv("TRUST_PROXY_HEADERS", "true").strip().lower() in {"1", "true", "yes"}:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
    login_manager.init_app(app)
    login_manager.login_view = None
    app.register_blueprint(admin_auth_bp)

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    print("UPLOAD DIR:", UPLOAD_DIR)
    print("FILES:", [file.name for file in UPLOAD_DIR.glob("*")])
    allowed_extensions = {"jpg", "jpeg", "png", "webp"}

    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    mongo_db_name = os.getenv("MONGODB_DB", "heritage_hues")

    client = MongoClient(mongo_uri)
    db = client[mongo_db_name]
    products = db.products
    carts = db.carts
    orders = db.orders
    order_status_history = db.order_status_history
    contact_messages = db.contact_messages
    pricing_settings = db.pricing_settings
    payment_settings = db.payment_settings
    reviews = db.reviews
    users = db.users
    admins = db.admins
    blogs = db.blogs
    sitemap_cache = {}

    try:
        products.create_index([("slug", ASCENDING)], unique=True)
        products.create_index([("updated_at", DESCENDING)])
        carts.create_index([("session_id", ASCENDING)], unique=True)
        carts.create_index([("updated_at", DESCENDING)])
        orders.create_index([("order_ref", ASCENDING)], unique=True)
        orders.create_index([("created_at", DESCENDING)])
        order_status_history.create_index([("order_id", ASCENDING), ("timestamp", DESCENDING)])
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

    except Exception as e:
        print(f"Warning: Could not create indexes: {e}")

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

    cors_origins = os.getenv("CORS_ORIGINS", "https://heritagehues.net","http://localhost:5173,http://localhost:5174,http://localhost:4173")
    allowed_origins = [origin.strip() for origin in cors_origins.split(",") if origin.strip()]
    CORS(
        app,
        supports_credentials=True,
        resources={
            r"/api/*": {"origins": allowed_origins},
            r"/admin/*": {"origins": allowed_origins},
        },
    )

    @login_manager.user_loader
    def load_admin_user(admin_id):
        oid = Admin.normalize_id(admin_id)
        if not oid:
            return None
        return Admin.from_document(admins.find_one({"_id": oid}))

    @login_manager.unauthorized_handler
    def unauthorized_handler():
        return jsonify({"success": False, "message": "Unauthorized access"}), 401

    @app.before_request
    def protect_admin_endpoints():
        if request.path in {
            "/sitemap.xml",
            "/sitemap-static.xml",
            "/robots.txt",
        } or request.path.startswith(("/sitemap-products-", "/sitemap-blogs-")):
            return None

        if request.method == "OPTIONS":
            return None

        protected_paths = request.path.startswith("/api/admin")
        if protected_paths and not is_admin_request():
            return jsonify({"error": "Admin access required"}), 403

        unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}
        csrf_exempt_paths = {"/admin/login", "/admin/register"}
        needs_csrf = request.method in unsafe_methods and (
            request.path.startswith("/api/admin") or request.path == "/admin/logout"
        )
        if needs_csrf and request.path not in csrf_exempt_paths and current_user.is_authenticated:
            request_token = str(request.headers.get("X-CSRF-Token", "")).strip()
            session_token = str(get_admin_csrf_token()).strip()
            if not request_token or not secrets.compare_digest(request_token, session_token):
                return jsonify({"success": False, "message": "CSRF token missing or invalid"}), 400

    def get_api_encryption_key():
        key_source = os.getenv("API_ENCRYPTION_KEY", "").strip()
        if not key_source:
            return None
        return hashlib.sha256(key_source.encode("utf-8")).digest()

    def encrypt_json_payload(payload):
        key = get_api_encryption_key()
        if not key:
            return None
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        encoded = base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")
        return {"encrypted": encoded}

    def should_encrypt_response():
        if not get_api_encryption_key():
            return False
        return str(request.headers.get("X-Use-Encryption", "")).strip().lower() in {"1", "true", "yes"}

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

        if response.content_type and response.content_type.startswith("application/json") and should_encrypt_response():
            payload = response.get_json(silent=True)
            if payload is not None:
                encrypted_payload = encrypt_json_payload(payload)
                if encrypted_payload is not None:
                    response.set_data(json.dumps(encrypted_payload))
                    response.headers["Content-Type"] = "application/json"
                    response.headers["Content-Length"] = str(len(response.get_data()))
        return response

    def get_stock_count(doc):
        raw_stock = doc.get("stock_count")
        if raw_stock is None:
            return 0 if bool(doc.get("is_out_of_stock", False)) else 1
        return max(0, int(raw_stock or 0))

    def get_or_create_pricing_settings():
        default_settings = {
            "_id": "global",
            "target_margin": 0.40,
            "brand_multiplier": 1.10,
            "gst_rate": 0.05,
            "minimum_margin": 0.25,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        settings_doc = pricing_settings.find_one({"_id": "global"})
        if settings_doc:
            missing = {
                key: value
                for key, value in default_settings.items()
                if key not in settings_doc
            }
            if missing:
                pricing_settings.update_one(
                    {"_id": "global"},
                    {"$set": missing}
                )
                settings_doc.update(missing)
            return settings_doc

        pricing_settings.insert_one(default_settings)
        return default_settings

    def get_encryption_key():
        key_source = os.getenv("ENCRYPTION_KEY", os.getenv("SECRET_KEY", "")).strip()
        if not key_source:
            raise RuntimeError("ENCRYPTION_KEY or SECRET_KEY is required for UPI encryption")
        digest = hashlib.sha256(key_source.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    def get_cipher():
        return Fernet(get_encryption_key())

    def encrypt_text(plaintext):
        value = str(plaintext or "").strip()
        if not value:
            return ""
        return get_cipher().encrypt(value.encode("utf-8")).decode("utf-8")

    def decrypt_text(ciphertext):
        value = str(ciphertext or "").strip()
        if not value:
            return ""
        try:
            return get_cipher().decrypt(value.encode("utf-8")).decode("utf-8")
        except (InvalidToken, ValueError):
            return ""

    def get_or_create_payment_settings():
        default_settings = {
            "_id": "global",
            "upi_id_encrypted": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        settings_doc = payment_settings.find_one({"_id": "global"})
        if settings_doc:
            if "created_at" not in settings_doc:
                payment_settings.update_one(
                    {"_id": "global"},
                    {"$set": {"created_at": datetime.now(timezone.utc).isoformat()}},
                )
                settings_doc["created_at"] = settings_doc.get("created_at") or datetime.now(timezone.utc).isoformat()
            if "updated_at" not in settings_doc:
                payment_settings.update_one(
                    {"_id": "global"},
                    {"$set": {"updated_at": datetime.now(timezone.utc).isoformat()}},
                )
                settings_doc["updated_at"] = settings_doc.get("updated_at") or datetime.now(timezone.utc).isoformat()
            return settings_doc

        env_upi = os.getenv("UPI_ID", "").strip()
        if env_upi:
            encrypted = encrypt_text(env_upi)
            settings_doc = {
                "_id": "global",
                "upi_id_encrypted": encrypted,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            payment_settings.insert_one(settings_doc)
            return settings_doc

        payment_settings.insert_one(default_settings)
        return default_settings

    def get_upi_id():
        settings_doc = get_or_create_payment_settings()
        if not settings_doc.get("upi_id_encrypted"):
            return ""
        return decrypt_text(settings_doc["upi_id_encrypted"])

    def normalize_pricing_settings(raw_settings):
        settings = {
            "target_margin": float(raw_settings.get("target_margin", 0.40)),
            "brand_multiplier": float(raw_settings.get("brand_multiplier", 1.10)),
            "gst_rate": float(raw_settings.get("gst_rate", 0.05)),
            "minimum_margin": float(raw_settings.get("minimum_margin", 0.25)),
        }
        if settings["target_margin"] < 0 or settings["target_margin"] >= 1:
            raise ValueError("target_margin must be between 0 and less than 1")
        if settings["brand_multiplier"] <= 0:
            raise ValueError("brand_multiplier must be greater than 0")
        if settings["gst_rate"] < 0:
            raise ValueError("gst_rate cannot be negative")
        if settings["minimum_margin"] < 0 or settings["minimum_margin"] >= 1:
            raise ValueError("minimum_margin must be between 0 and less than 1")
        return settings

    def calculate_prices(cost_price, packaging_cost, delivery_cost, discount_percentage, settings):
        cost_price = float(cost_price or 0)
        packaging_cost = float(packaging_cost or 0)
        delivery_cost = float(delivery_cost or 0)
        discount_percentage = float(discount_percentage or 0)

        if cost_price <= 0:
            return {
                "cost_price": 0.0,
                "packaging_cost": 0.0,
                "delivery_cost": 0.0,
                "total_cost": 0.0,
                "base_price": 0.0,
                "mrp": 0.0,
                "discount_percentage": 0.0,
                "discount_amount": 0.0,
                "discounted_price": 0.0,
                "gst_amount": 0.0,
                "final_price": 0.0,
                "profit": 0.0,
                "margin": 0.0,
                "margin_percentage": 0.0,
            }

        if packaging_cost < 0 or delivery_cost < 0:
            raise ValueError("packaging_cost and delivery_cost cannot be negative")
        if discount_percentage < 0 or discount_percentage > 100:
            raise ValueError("discount_percentage must be between 0 and 100")

        total_cost = cost_price + packaging_cost + delivery_cost
        if total_cost <= 0:
            raise ValueError("total_cost must be greater than 0")

        base_price = total_cost / (1 - settings["target_margin"])
        mrp_raw = base_price * settings["brand_multiplier"]
        mrp = round(mrp_raw, 2)
        discount_amount = mrp * (discount_percentage / 100)
        discounted_price = mrp - discount_amount
        gst = discounted_price * settings["gst_rate"]
        final_price = round(discounted_price + gst, 2)
        profit = final_price - total_cost
        actual_margin = (profit / final_price) if final_price > 0 else 0

        if actual_margin < settings["minimum_margin"]:
            raise ValueError(f"Calculated margin {actual_margin:.1%} is below minimum {settings['minimum_margin']:.1%}")

        return {
            "cost_price": cost_price,
            "packaging_cost": packaging_cost,
            "delivery_cost": delivery_cost,
            "total_cost": total_cost,
            "base_price": base_price,
            "mrp": mrp,
            "discount_percentage": discount_percentage,
            "discount_amount": discount_amount,
            "discounted_price": discounted_price,
            "gst_amount": gst,
            "final_price": final_price,
            "profit": profit,
            "margin": actual_margin,
            "margin_percentage": actual_margin * 100,
        }

    def format_product(doc):
        stock_count = get_stock_count(doc)
        settings = get_or_create_pricing_settings()
        
        # Backward compat
        legacy_price = doc.get("price", 0)
        legacy_discount_pct = doc.get("discount", 0)
        
        result = {
            "id": str(doc["_id"]),
            "slug": doc.get("slug", ""),
            "title": doc.get("title", ""),
            "category": doc.get("category", ""),
            "description": doc.get("description", ""),
            "cost_price": doc.get("cost_price", 0),
            "packaging_cost": doc.get("packaging_cost", doc.get("packaging_charge", 0)),
            "delivery_cost": doc.get("delivery_cost", doc.get("delivery_charge", 0)),
            "discount_percentage": doc.get("discount_percentage", legacy_discount_pct),
            "mrp": doc.get("mrp", legacy_price),  # Legacy base
            "discount_amount": doc.get("discount_amount", 0),
            "discounted_price": doc.get("discounted_price", legacy_price),
            "final_price": doc.get("final_price", legacy_price),
            "gst_amount": doc.get("gst_amount", 0),
            "total_cost": doc.get("total_cost", 0),
            "profit": doc.get("profit", doc.get("net_profit", 0)),
            "margin": doc.get("margin", 0),
            "margin_percentage": doc.get("margin_percentage", 0),
            "stock_count": stock_count,
            "is_out_of_stock": bool(doc.get("is_out_of_stock", False)) or stock_count <= 0,
            "currency": doc.get("currency", "INR"),
            "gradient": doc.get("gradient", "linear-gradient(135deg, #772920, #cf9f64)"),
            "photos": doc.get("photos", []),
            "description_points": doc.get("description_points", []),
            "created_at": doc.get("created_at"),
            "updated_at": doc.get("updated_at"),
        }
        
        # Recalculate if new fields present
        cost_price = result["cost_price"]
        packaging_cost = result["packaging_cost"]
        delivery_cost = result["delivery_cost"]
        disc_pct = result["discount_percentage"]
        if cost_price > 0:
            try:
                prices = calculate_prices(cost_price, packaging_cost, delivery_cost, disc_pct, settings)
                result["mrp"] = prices["mrp"]
                result["discount_amount"] = prices["discount_amount"]
                result["discounted_price"] = prices["discounted_price"]
                result["final_price"] = prices["final_price"]
                result["gst_amount"] = prices["gst_amount"]
                result["total_cost"] = prices["total_cost"]
                result["profit"] = prices["profit"]
                result["margin"] = prices["margin"]
                result["margin_percentage"] = prices["margin_percentage"]
            except ValueError:
                pass  # Keep legacy
        
        return result

    def format_product_with_seo(doc):
        product = format_product(doc)
        seo = build_product_seo(product)
        product["seo"] = seo["meta"]
        product["structured_data"] = seo["structured_data"]
        product["json_ld"] = seo["json_ld"]
        return product

    def sanitize_slug(value):
        return slugify(value)

    def make_unique_product_slug(value, current_product_id=None):
        current_id = str(current_product_id or "").strip()

        def slug_exists(candidate):
            doc = products.find_one({"slug": candidate}, {"_id": 1})
            if not doc:
                return False
            return str(doc.get("_id")) != current_id

        return generate_unique_slug(value, slug_exists)

    def is_allowed_file(filename):
        if "." not in filename:
            return False
        ext = filename.rsplit(".", 1)[1].lower()
        return ext in allowed_extensions

    def build_photo_url(filename):
        return f"/api/uploads/{filename}"

    def format_money(value):
        return round(float(value or 0), 2)

    # Legacy - kept for checkout compat
    def calculate_discounted_price(price, discount):
        base_price = format_money(price)
        percent = format_money(discount)
        discounted = base_price * (1 - (percent / 100))
        return format_money(discounted)

    def build_upi_url(payee_vpa, payee_name, amount, order_ref):
        params = {
            "pa": payee_vpa,
            "pn": payee_name,
            "am": f"{format_money(amount):.2f}",
            "cu": "INR",
            "tn": f"Heritage Hues order {order_ref}",
            "tr": order_ref,
        }
        return f"upi://pay?{urlencode(params)}"

    def build_secure_upi_link(payee_vpa, amount, order_id):
        params = {
            "pa": payee_vpa,
            "pn": "HeritageHue",
            "am": f"{format_money(amount):.2f}",
            "cu": "INR",
            "tn": f"Order#{str(order_id).strip()}",
        }
        return f"upi://pay?{urlencode(params)}"

    def get_email_settings():
        return {
            "host": os.getenv("EMAIL_HOST", "smtp.gmail.com").strip(),
            "port": int(os.getenv("EMAIL_PORT", "587")),
            "username": os.getenv("EMAIL_USERNAME", "care.heritagehues@gmail.com").strip(),
            "password": os.getenv("EMAIL_PASSWORD", "").strip(),
            "use_tls": os.getenv("EMAIL_USE_TLS", "true").strip().lower() in ("1", "true", "yes"),
            "recipients": [addr.strip() for addr in os.getenv("EMAIL_RECIPIENTS", os.getenv("EMAIL_USERNAME", "care.heritagehues@gmail.com")).split(",") if addr.strip()],
        }

    def send_email(subject, body, recipients=None, from_address=None):
        settings = get_email_settings()
        if not settings["password"]:
            raise ValueError("Email password is not configured")
        if recipients is None:
            recipients = settings["recipients"]
        if isinstance(recipients, str):
            recipients = [recipients]
        if not recipients:
            raise ValueError("No email recipients configured")

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = from_address or settings["username"]
        message["To"] = ", ".join(recipients)
        message.set_content(body)

        with smtplib.SMTP(settings["host"], settings["port"], timeout=20) as smtp:
            if settings["use_tls"]:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
            smtp.login(settings["username"], settings["password"])
            smtp.send_message(message)

    def format_contact_email(data):
        return (
            f"New contact request from Heritage Hues:\n\n"
            f"Name: {data['name']}\n"
            f"Email: {data['email']}\n\n"
            f"Message:\n{data['message']}\n"
        )

    fulfillment_statuses = {
        "pending",
        "confirmed",
        "packed",
        "shipped",
        "out_for_delivery",
        "delivered",
        "cancelled",
    }

    def is_admin_request():
        if current_user.is_authenticated and getattr(current_user, "role", "") in {"admin", "superadmin"}:
            return True
        configured_token = os.getenv("ADMIN_API_TOKEN", "").strip()
        if not configured_token:
            return False
        provided = str(request.headers.get("X-Admin-Token", "")).strip()
        return bool(provided) and secrets.compare_digest(provided, configured_token)

    def require_admin_access():
        if not is_admin_request():
            raise PermissionError("Admin access required")

    def create_status_history_entry(order_id, status, note=""):
        order_status_history.insert_one({
            "order_id": order_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": str(note or "").strip(),
        })

    def sanitize_contact_payload(payload):
        name = str(payload.get("name", "") or "").strip()
        email = str(payload.get("email", "") or "").strip()
        message = str(payload.get("message", "") or "").strip()

        if not name:
            return None, "Name is required"
        if not email or "@" not in email or "." not in email:
            return None, "Valid email is required"
        if not message:
            return None, "Message is required"

        return {
            "name": name,
            "email": email,
            "message": message,
        }, None

    def format_contact_message(doc):
        return {
            "id": str(doc.get("_id")),
            "name": doc.get("name", ""),
            "email": doc.get("email", ""),
            "message": doc.get("message", ""),
            "created_at": doc.get("created_at"),
        }

    def get_status_history(order_id):
        try:
            oid = ObjectId(order_id) if not isinstance(order_id, ObjectId) else order_id
        except Exception:
            return []
        docs = list(order_status_history.find({"order_id": oid}).sort("timestamp", ASCENDING))
        return [
            {
                "status": doc.get("status", ""),
                "timestamp": doc.get("timestamp"),
                "note": doc.get("note", ""),
            }
            for doc in docs
        ]

    def update_order_fulfillment_status(order_doc, status, note="", tracking_id=None, tracking_url=None):
        if status not in fulfillment_statuses:
            raise ValueError("Invalid order status")
        updates = {
            "status": status,
            "status_updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if tracking_id is not None:
            updates["tracking_id"] = str(tracking_id).strip()
        if tracking_url is not None:
            updates["tracking_url"] = str(tracking_url).strip()
        updated = orders.find_one_and_update(
            {"_id": order_doc["_id"]},
            {"$set": updates},
            return_document=ReturnDocument.AFTER,
        )
        create_status_history_entry(order_doc["_id"], status, note)
        return updated

    def get_request_session_id(payload=None, required=False):
        payload = payload or {}
        session_id = (
            payload.get("session_id")
            or request.args.get("session_id")
            or request.headers.get("X-Session-Id")
            or ""
        ).strip()
        if not session_id and required:
            raise ValueError("session_id is required")
        return session_id

    def create_session_id():
        return secrets.token_urlsafe(18)

    def get_or_create_cart(session_id=None, temporary=False):
        resolved_session_id = (session_id or "").strip() or create_session_id()
        now = datetime.now(timezone.utc).isoformat()
        cart = carts.find_one({"session_id": resolved_session_id})
        if cart:
            return cart

        cart = {
            "user": None,
            "session_id": resolved_session_id,
            "temporary": bool(temporary),
            "items": [],
            "created_at": now,
            "updated_at": now,
        }
        carts.insert_one(cart)
        return carts.find_one({"session_id": resolved_session_id})

    def resolve_product_reference(product_ref):
        try:
            oid = ObjectId(product_ref)
            return products.find_one({"_id": oid})
        except Exception:
            return products.find_one({"slug": sanitize_slug(product_ref)})

    def sanitize_cart_item_payload(payload):
        product_ref = str(payload.get("product_id") or payload.get("slug") or "").strip()
        if not product_ref:
            raise ValueError("product_id or slug is required")
        try:
            quantity = int(payload.get("quantity", 1))
        except (TypeError, ValueError):
            raise ValueError("quantity must be a whole number")
        if quantity < 1 or quantity > 10:
            raise ValueError("quantity must be between 1 and 10")
        return product_ref, quantity

    def build_cart_summary_from_docs(cart_items):
        summary_items = []
        subtotal = 0.0
        for item in cart_items:
            product_doc = item["product"]
            stock_count = get_stock_count(product_doc)
            quantity = item["quantity"]
            if product_doc.get("is_out_of_stock") or stock_count <= 0:
                raise ValueError(f"{product_doc.get('title', 'A product')} is out of stock")
            if quantity > stock_count:
                raise ValueError(f"Only {stock_count} unit(s) available for {product_doc.get('title', 'this product')}")

            formatted = format_product(product_doc)
            unit_price = float(formatted.get("final_price", 0))
            line_total = unit_price * quantity
            subtotal += line_total
            summary_items.append({
                "product_id": formatted["id"],
                "slug": formatted["slug"],
                "title": formatted["title"],
                "category": formatted["category"],
                "photos": formatted.get("photos", []),
                "quantity": quantity,
                "available_stock": stock_count,
                "unit_price": round(unit_price, 2),
                "line_total": round(line_total, 2),
                "currency": formatted.get("currency", "INR"),
            })

        return {
            "items": summary_items,
            "total_amount": round(subtotal, 2),
            "currency": "INR",
            "notes": [
                "Inclusive of all taxes",
                "Free Delivery",
                "Premium Packaging Included",
            ],
        }

    def build_cart_summary(cart_doc):
        items = cart_doc.get("items", [])
        resolved = []
        for item in items:
            product_doc = None
            if item.get("product_id"):
                try:
                    product_doc = products.find_one({"_id": ObjectId(item["product_id"])})
                except Exception:
                    product_doc = None
            if not product_doc and item.get("slug"):
                product_doc = products.find_one({"slug": item["slug"]})
            if not product_doc:
                continue
            resolved.append({"product": product_doc, "quantity": int(item.get("quantity", 1) or 1)})
        return build_cart_summary_from_docs(resolved)

    def validate_address(address):
        if not isinstance(address, dict):
            raise ValueError("address must be an object")
        required_fields = ["name", "phone", "address", "city", "state", "pincode"]
        normalized = {}
        for field in required_fields:
            value = str(address.get(field, "")).strip()
            if not value:
                raise ValueError(f"{field} is required")
            normalized[field] = value
        email = str(address.get("email", "")).strip().lower()
        if email:
            normalized["email"] = email
        return normalized

    def normalize_user_identity(payload):
        if not isinstance(payload, dict):
            return None
        email = str(payload.get("email", "")).strip().lower()
        if not email or "@" not in email:
            return None
        return {
            "name": str(payload.get("name", "")).strip(),
            "email": email,
        }

    def validate_review_payload(payload):
        if not isinstance(payload, dict):
            return None, "Review payload must be an object"
        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip()
        message = str(payload.get("message", "")).strip()
        rating = payload.get("rating")
        attachments = payload.get("attachments", [])
        try:
            rating = int(rating)
        except (TypeError, ValueError):
            rating = None
        if not name:
            return None, "Name is required"
        if not email or "@" not in email:
            return None, "Valid email is required"
        if not message:
            return None, "Review message is required"
        if rating is None or rating < 1 or rating > 5:
            return None, "Rating must be between 1 and 5"
        if attachments is None:
            attachments = []
        if not isinstance(attachments, list):
            return None, "Attachments must be an array"
        normalized_attachments = []
        for attachment in attachments:
            if not isinstance(attachment, str) or not attachment.strip():
                return None, "Attachments must be valid URLs"
            normalized_attachments.append(attachment.strip())
        if len(normalized_attachments) > 5:
            return None, "Maximum 5 attachments are allowed"
        return {
            "name": name,
            "email": email,
            "message": message,
            "rating": rating,
            "attachments": normalized_attachments,
        }, None

    def format_review(doc):
        return {
            "id": str(doc.get("_id")),
            "product_slug": doc.get("product_slug", ""),
            "product_title": doc.get("product_title", ""),
            "name": doc.get("name", ""),
            "email": doc.get("email", ""),
            "message": doc.get("message", ""),
            "rating": int(doc.get("rating", 0)),
            "attachments": doc.get("attachments", []),
            "created_at": doc.get("created_at"),
            "updated_at": doc.get("updated_at"),
        }

    def build_user_email_query(email):
        cleaned = str(email or "").strip().lower()
        if not cleaned:
            return None
        return {"$regex": f"^{re.escape(cleaned)}$", "$options": "i"}

    def get_user_reviews(email):
        email_query = build_user_email_query(email)
        if not email_query:
            return []
        docs = reviews.find({"email": email_query}).sort("created_at", DESCENDING)
        return [format_review(doc) for doc in docs]

    def count_user_reviews(email):
        email_query = build_user_email_query(email)
        if not email_query:
            return 0
        return int(reviews.count_documents({"email": email_query}))

    def get_user_orders(email):
        email_query = build_user_email_query(email)
        if not email_query:
            return []
        docs = orders.find(
            {
                "$or": [
                    {"customer_email": email_query},
                    {"user.email": email_query},
                    {"address.email": email_query},
                ],
                "is_deleted": {"$ne": True},
            }
        ).sort("created_at", DESCENDING)
        return [format_order(doc) for doc in docs]

    def count_user_orders(email):
        email_query = build_user_email_query(email)
        if not email_query:
            return 0
        return int(
            orders.count_documents(
                {
                    "$or": [
                        {"customer_email": email_query},
                        {"user.email": email_query},
                        {"address.email": email_query},
                    ],
                    "is_deleted": {"$ne": True},
                }
            )
        )

    def create_razorpay_order(amount, receipt):
        key_id = os.getenv("RAZORPAY_KEY_ID", "").strip()
        key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
        if not key_id or not key_secret:
            raise ValueError("Razorpay is not configured on the server")

        payload = json.dumps({
            "amount": int(round(float(amount) * 100)),
            "currency": "INR",
            "receipt": receipt,
            "payment_capture": 1,
        }).encode("utf-8")
        auth = base64.b64encode(f"{key_id}:{key_secret}".encode("utf-8")).decode("utf-8")
        req = urlrequest.Request(
            "https://api.razorpay.com/v1/orders",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth}",
            },
            method="POST",
        )
        with urlrequest.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode("utf-8")), key_id

    def verify_razorpay_signature(razorpay_order_id, razorpay_payment_id, razorpay_signature):
        key_secret = os.getenv("RAZORPAY_KEY_SECRET", "").strip()
        if not key_secret:
            raise ValueError("Razorpay is not configured on the server")
        payload = f"{razorpay_order_id}|{razorpay_payment_id}".encode("utf-8")
        expected = hmac.new(key_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, razorpay_signature or "")

    def validate_checkout_payload(payload):
        items = payload.get("items", [])
        if not isinstance(items, list) or not items:
            return None, "items must be a non-empty array"

        normalized = []
        seen = set()
        for item in items:
            if not isinstance(item, dict):
                return None, "each item must be an object"

            slug = sanitize_slug(item.get("slug"))
            if not slug:
                return None, "each item must include a valid slug"

            try:
                quantity = int(item.get("quantity", 1))
            except (TypeError, ValueError):
                return None, "quantity must be a whole number"

            if quantity < 1 or quantity > 10:
                return None, "quantity must be between 1 and 10"

            if slug in seen:
                return None, "duplicate cart items are not allowed"

            seen.add(slug)
            normalized.append({"slug": slug, "quantity": quantity})

        return normalized, None

    def build_checkout_summary(items):
        slug_map = {item["slug"]: item["quantity"] for item in items}
        docs = list(products.find({"slug": {"$in": list(slug_map.keys())}}))

        if len(docs) != len(items):
            found = {doc.get("slug") for doc in docs}
            missing = [item["slug"] for item in items if item["slug"] not in found]
            return None, f"Products not found: {', '.join(sorted(missing))}"

        summary_items = []
        subtotal = 0.0
        for doc in docs:
            slug = doc.get("slug")
            quantity = slug_map[slug]
            available_stock = get_stock_count(doc)
            if doc.get("is_out_of_stock") or available_stock <= 0:
                return None, f"{doc.get('title', 'A product')} is out of stock"
            if quantity > available_stock:
                return None, f"Only {available_stock} unit(s) available for {doc.get('title', 'this product')}"

            # Use new final_price, fallback to legacy
            unit_price = doc.get("final_price", calculate_discounted_price(doc.get("price", 0), doc.get("discount", 0)))
            line_total = format_money(unit_price * quantity)
            subtotal += line_total
            summary_items.append(
                {
                    "slug": slug,
                    "title": doc.get("title", ""),
                    "quantity": quantity,
                    "available_stock": available_stock,
                    "unit_price": unit_price,
                    "line_total": line_total,
                }
            )

        subtotal = format_money(subtotal)
        # Use product gst_amount logic, but keep 18% for legacy cart totals if no new fields
        gst = format_money(subtotal * 0.18)
        total = format_money(subtotal + gst)

        summary_items.sort(key=lambda item: item["slug"])
        return {
            "items": summary_items,
            "subtotal": subtotal,
            "gst": gst,
            "total": total,
            "currency": "INR",
        }, None

    def validate_payload(payload, partial=False):
        allowed_fields = {
            "slug",
            "title",
            "category",
            "description",
            "price",
            "discount",
            "cost_price",
            "packaging_cost",
            "delivery_cost",
            "discount_percentage",
            "stock_count",
            "is_out_of_stock",
            "currency",
            "gradient",
            "photos",
            "description_points",
        }
        unknown = set(payload.keys()) - allowed_fields
        if unknown:
            return None, f"Unsupported fields: {', '.join(sorted(unknown))}"

        data = {}

        if not partial or "title" in payload:
            title = str(payload.get("title", "")).strip()
            if not title:
                return None, "title is required"
            data["title"] = title

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
            category = str(payload.get("category", "")).strip() or "General"
            data["category"] = category

        if not partial or "description" in payload:
            description = str(payload.get("description", "")).strip()
            data["description"] = description

        if not partial or "description_points" in payload:
            points = payload.get("description_points", [])
            if not isinstance(points, list):
                return None, "description_points must be an array"
            data["description_points"] = []
            for i, point in enumerate(points):
                if isinstance(point, dict) and "point" in point and isinstance(point["point"], str):
                    data["description_points"].append({
                        "order": point.get("order", i),
                        "point": point["point"].strip()
                    })

        if not partial or "cost_price" in payload:
            try:
                cost_price = float(payload.get("cost_price", 0))
            except (TypeError, ValueError):
                return None, "cost_price must be a number"
            if cost_price < 0:
                return None, "cost_price cannot be negative"
            data["cost_price"] = cost_price

        if not partial or "packaging_cost" in payload:
            try:
                packaging_cost = float(payload.get("packaging_cost", 0))
            except (TypeError, ValueError):
                return None, "packaging_cost must be a number"
            if packaging_cost < 0:
                return None, "packaging_cost cannot be negative"
            data["packaging_cost"] = packaging_cost

        if not partial or "delivery_cost" in payload:
            try:
                delivery_cost = float(payload.get("delivery_cost", 0))
            except (TypeError, ValueError):
                return None, "delivery_cost must be a number"
            if delivery_cost < 0:
                return None, "delivery_cost cannot be negative"
            data["delivery_cost"] = delivery_cost

        if not partial or "discount_percentage" in payload:
            try:
                disc_pct = float(payload.get("discount_percentage", 0))
            except (TypeError, ValueError):
                return None, "discount_percentage must be a number"
            if disc_pct < 0 or disc_pct > 100:
                return None, "discount_percentage must be between 0 and 100"
            data["discount_percentage"] = disc_pct

        # Legacy price/discount - kept for backward compat, ignored if new fields present
        if "price" in payload and "cost_price" not in payload:
            try:
                price = float(payload.get("price", 0))
            except (TypeError, ValueError):
                return None, "price must be a number"
            if price < 0:
                return None, "price cannot be negative"
            data["final_price"] = round(price, 2)  # Map to final_price

        if "discount" in payload and "discount_percentage" not in payload:
            try:
                discount = float(payload.get("discount", 0))
            except (TypeError, ValueError):
                return None, "discount must be a number"
            if discount < 0 or discount > 100:
                return None, "discount must be between 0 and 100"
            data["discount_percentage"] = round(discount, 2)

        if not partial or "stock_count" in payload:
            try:
                stock_count = int(payload.get("stock_count", 0))
            except (TypeError, ValueError):
                return None, "stock_count must be a whole number"
            if stock_count < 0:
                return None, "stock_count cannot be negative"
            data["stock_count"] = stock_count

        if not partial or "is_out_of_stock" in payload:
            data["is_out_of_stock"] = bool(payload.get("is_out_of_stock", False))

        if not partial or "currency" in payload:
            currency = str(payload.get("currency", "INR")).strip().upper() or "INR"
            data["currency"] = currency

        if not partial or "gradient" in payload:
            gradient = str(payload.get("gradient", "")).strip() or "linear-gradient(135deg, #772920, #cf9f64)"
            data["gradient"] = gradient

        if not partial or "photos" in payload:
            photos = payload.get("photos", [])
            if not isinstance(photos, list):
                return None, "photos must be an array"
            if len(photos) > 10:
                return None, "maximum 10 photos are allowed"
            data["photos"] = [str(p).strip() for p in photos if str(p).strip()]

        return data, None

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    def build_static_sitemap_entries():
        now = datetime.now(timezone.utc)
        return [
            {
                "loc": page["path"],
                "lastmod": now,
                "priority": page["priority"],
            }
            for page in STATIC_SITEMAP_PAGES
        ]

    def build_blog_sitemap_entries(page=None):
        cursor = blogs.find(
            {"slug": {"$exists": True, "$ne": ""}},
            {"slug": 1, "updated_at": 1},
        ).sort("updated_at", DESCENDING)
        if page is not None:
            cursor = cursor.skip((page - 1) * SITEMAP_MAX_URLS).limit(SITEMAP_MAX_URLS)
        return [
            {
                "loc": f"/blog/{sanitize_slug(blog.get('slug'))}",
                "lastmod": blog.get("updated_at"),
                "priority": "0.7",
            }
            for blog in cursor.batch_size(1000)
        ]

    def build_product_sitemap_entries(page=None):
        cursor = products.find(
            {"slug": {"$exists": True, "$ne": ""}},
            {"slug": 1, "updated_at": 1},
        ).sort("updated_at", DESCENDING)
        if page is not None:
            cursor = cursor.skip((page - 1) * SITEMAP_MAX_URLS).limit(SITEMAP_MAX_URLS)
        return [
            {
                "loc": f"/product/{sanitize_slug(product.get('slug'))}",
                "lastmod": product.get("updated_at"),
                "priority": "0.9",
            }
            for product in cursor.batch_size(1000)
        ]

    def build_sitemap_entries():
        return build_static_sitemap_entries() + build_blog_sitemap_entries() + build_product_sitemap_entries()

    def build_sitemap_index_entries():
        now = datetime.now(timezone.utc)
        entries = [{"loc": "/sitemap-static.xml", "lastmod": now}]
        blog_count = blogs.count_documents({"slug": {"$exists": True, "$ne": ""}})
        product_count = products.count_documents({"slug": {"$exists": True, "$ne": ""}})

        for page in range(1, (blog_count + SITEMAP_MAX_URLS - 1) // SITEMAP_MAX_URLS + 1):
            entries.append({"loc": f"/sitemap-blogs-{page}.xml", "lastmod": now})
        for page in range(1, (product_count + SITEMAP_MAX_URLS - 1) // SITEMAP_MAX_URLS + 1):
            entries.append({"loc": f"/sitemap-products-{page}.xml", "lastmod": now})

        return entries

    def invalidate_sitemap_cache():
        sitemap_cache.clear()

    def get_cached_sitemap(cache_key):
        cached = sitemap_cache.get(cache_key)
        if not cached:
            return None
        if cached["expires_at"] <= datetime.now(timezone.utc):
            sitemap_cache.pop(cache_key, None)
            return None
        return cached["xml"], cached["generated_at"]

    def set_cached_sitemap(cache_key, xml):
        generated_at = datetime.now(timezone.utc)
        sitemap_cache[cache_key] = {
            "xml": xml,
            "generated_at": generated_at,
            "expires_at": generated_at + timedelta(seconds=SITEMAP_CACHE_SECONDS),
        }
        return xml, generated_at

    def make_sitemap_response(xml, generated_at=None):
        generated_at = generated_at or datetime.now(timezone.utc)
        body = xml.encode("utf-8")
        use_gzip = "gzip" in request.headers.get("Accept-Encoding", "").lower()
        response_body = gzip.compress(body) if use_gzip else body
        response = Response(response_body, mimetype="application/xml")
        response.headers["Cache-Control"] = f"public, max-age={SITEMAP_CACHE_SECONDS}, s-maxage={SITEMAP_CACHE_SECONDS}"
        response.headers["Content-Type"] = "application/xml; charset=utf-8"
        response.headers["Last-Modified"] = generated_at.strftime("%a, %d %b %Y %H:%M:%S GMT")
        response.headers["X-Robots-Tag"] = "all"
        response.headers["Vary"] = "Accept-Encoding"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Length"] = str(len(response_body))
        response.set_etag(hashlib.sha256(body).hexdigest())
        if use_gzip:
            response.headers["Content-Encoding"] = "gzip"
        return response

    def cached_sitemap_response(cache_key, builder):
        cached = get_cached_sitemap(cache_key)
        if cached:
            return make_sitemap_response(*cached)
        try:
            xml = builder()
        except Exception:
            app.logger.exception("Failed to generate sitemap: %s", cache_key)
            return jsonify({"error": "Failed to generate sitemap"}), 500
        return make_sitemap_response(*set_cached_sitemap(cache_key, xml))

    @app.get("/sitemap.xml")
    def sitemap_xml():
        def build_root_sitemap():
            total_urls = (
                len(STATIC_SITEMAP_PAGES)
                + blogs.count_documents({"slug": {"$exists": True, "$ne": ""}})
                + products.count_documents({"slug": {"$exists": True, "$ne": ""}})
            )
            if total_urls > SITEMAP_MAX_URLS:
                return build_sitemap_index_xml(build_sitemap_index_entries())
            return build_sitemap_xml(build_sitemap_entries())

        return cached_sitemap_response("root", build_root_sitemap)

    @app.get("/sitemap-static.xml")
    def sitemap_static_xml():
        return cached_sitemap_response(
            "static",
            lambda: build_sitemap_xml(build_static_sitemap_entries()),
        )

    @app.get("/sitemap-blogs-<int:page>.xml")
    def sitemap_blogs_xml(page):
        if page < 1:
            abort(404)
        return cached_sitemap_response(
            f"blogs:{page}",
            lambda: build_sitemap_xml(build_blog_sitemap_entries(page=page)),
        )

    @app.get("/sitemap-products-<int:page>.xml")
    def sitemap_products_xml(page):
        if page < 1:
            abort(404)
        return cached_sitemap_response(
            f"products:{page}",
            lambda: build_sitemap_xml(build_product_sitemap_entries(page=page)),
        )

    @app.get("/robots.txt")
    def robots_txt():
        content = "\n".join(
            [
                "User-agent: *",
                "Allow: /",
                "Disallow: /admin/",
                "Disallow: /dashboard/",
                f"Sitemap: {SITEMAP_URL}",
                "",
            ]
        )
        response = Response(content, mimetype="text/plain")
        response.headers["Cache-Control"] = f"public, max-age={SITEMAP_CACHE_SECONDS}, s-maxage={SITEMAP_CACHE_SECONDS}"
        response.headers["X-Robots-Tag"] = "all"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.post("/api/contact")
    def submit_contact():
        payload = request.get_json(silent=True) or {}
        data, error_message = sanitize_contact_payload(payload)
        if error_message:
            return jsonify({"error": error_message}), 400

        now = datetime.now(timezone.utc).isoformat()
        contact_doc = {
            **data,
            "created_at": now,
            "updated_at": now,
        }
        contact_messages.insert_one(contact_doc)

        email_error = None
        if os.getenv("EMAIL_PASSWORD", "").strip():
            try:
                send_email(
                    subject=f"New contact from {data['name']}",
                    body=format_contact_email(data),
                    recipients=os.getenv("EMAIL_RECIPIENTS", os.getenv("EMAIL_USERNAME", "care.heritagehues@gmail.com")),
                    from_address=os.getenv("EMAIL_USERNAME", "care.heritagehues@gmail.com"),
                )
            except Exception as exc:
                email_error = str(exc)

        response = format_contact_message(contact_doc)
        if email_error:
            response["email_error"] = email_error
        return jsonify(response), 201

    @app.get("/api/admin/contacts")
    def admin_list_contacts():
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

        docs = list(contact_messages.find().sort("created_at", DESCENDING))
        return jsonify([format_contact_message(doc) for doc in docs])

    @app.delete("/api/admin/contacts/<string:message_id>")
    def admin_delete_contact(message_id):
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

        try:
            oid = ObjectId(message_id)
        except Exception:
            return jsonify({"error": "Invalid message id"}), 400

        result = contact_messages.delete_one({"_id": oid})
        if result.deleted_count == 0:
            return jsonify({"error": "Message not found"}), 404

        return jsonify({"message": "Contact message deleted"})

    @app.get("/api/cart")
    def get_cart():
        try:
            session_id = get_request_session_id(required=False)
            cart = get_or_create_cart(session_id=session_id)
            summary = build_cart_summary(cart)
            return jsonify({
                "session_id": cart["session_id"],
                "items": summary["items"],
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
                "notes": summary["notes"],
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.post("/api/cart/items")
    def add_cart_item():
        payload = request.get_json(silent=True) or {}
        try:
            session_id = get_request_session_id(payload)
            product_ref, quantity = sanitize_cart_item_payload(payload)
            product_doc = resolve_product_reference(product_ref)
            if not product_doc:
                return jsonify({"error": "Product not found"}), 404
            stock_count = get_stock_count(product_doc)
            if product_doc.get("is_out_of_stock") or stock_count <= 0:
                return jsonify({"error": "Product is out of stock"}), 400

            cart = get_or_create_cart(session_id=session_id)
            items = list(cart.get("items", []))
            product_id = str(product_doc["_id"])
            existing = next((item for item in items if item.get("product_id") == product_id), None)
            next_quantity = quantity + int(existing.get("quantity", 0) or 0) if existing else quantity
            if next_quantity > stock_count:
                return jsonify({"error": f"Only {stock_count} unit(s) available"}), 400

            if existing:
                existing["quantity"] = next_quantity
            else:
                items.append({
                    "product_id": product_id,
                    "slug": product_doc.get("slug"),
                    "quantity": quantity,
                })

            carts.find_one_and_update(
                {"session_id": cart["session_id"]},
                {"$set": {"items": items, "updated_at": datetime.now(timezone.utc).isoformat()}},
                return_document=ReturnDocument.AFTER,
            )
            updated = carts.find_one({"session_id": cart["session_id"]})
            summary = build_cart_summary(updated)
            return jsonify({
                "session_id": updated["session_id"],
                "items": summary["items"],
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.put("/api/cart/items/<string:item_ref>")
    def update_cart_item(item_ref):
        payload = request.get_json(silent=True) or {}
        try:
            session_id = get_request_session_id(payload, required=True)
            _, quantity = sanitize_cart_item_payload({"product_id": item_ref, "quantity": payload.get("quantity", 1)})
            cart = carts.find_one({"session_id": session_id})
            if not cart:
                return jsonify({"error": "Cart not found"}), 404

            resolved = resolve_product_reference(item_ref)
            product_id = str(resolved["_id"]) if resolved else item_ref
            items = list(cart.get("items", []))
            target = next((item for item in items if item.get("product_id") == product_id or item.get("slug") == sanitize_slug(item_ref)), None)
            if not target:
                return jsonify({"error": "Cart item not found"}), 404

            product_doc = resolve_product_reference(target.get("product_id") or target.get("slug"))
            if not product_doc:
                return jsonify({"error": "Product not found"}), 404
            stock_count = get_stock_count(product_doc)
            if quantity > stock_count:
                return jsonify({"error": f"Only {stock_count} unit(s) available"}), 400

            target["quantity"] = quantity
            carts.update_one({"session_id": session_id}, {"$set": {"items": items, "updated_at": datetime.now(timezone.utc).isoformat()}})
            updated = carts.find_one({"session_id": session_id})
            summary = build_cart_summary(updated)
            return jsonify({
                "session_id": updated["session_id"],
                "items": summary["items"],
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.delete("/api/cart/items/<string:item_ref>")
    def remove_cart_item(item_ref):
        payload = request.get_json(silent=True) or {}
        try:
            session_id = get_request_session_id(payload, required=True)
            cart = carts.find_one({"session_id": session_id})
            if not cart:
                return jsonify({"error": "Cart not found"}), 404
            slug = sanitize_slug(item_ref)
            next_items = [
                item for item in cart.get("items", [])
                if item.get("product_id") != item_ref and item.get("slug") != slug
            ]
            carts.update_one({"session_id": session_id}, {"$set": {"items": next_items, "updated_at": datetime.now(timezone.utc).isoformat()}})
            updated = carts.find_one({"session_id": session_id})
            summary = build_cart_summary(updated)
            return jsonify({
                "session_id": updated["session_id"],
                "items": summary["items"],
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.post("/api/buy-now")
    def buy_now():
        payload = request.get_json(silent=True) or {}
        try:
            product_ref, quantity = sanitize_cart_item_payload(payload)
            product_doc = resolve_product_reference(product_ref)
            if not product_doc:
                return jsonify({"error": "Product not found"}), 404
            stock_count = get_stock_count(product_doc)
            if product_doc.get("is_out_of_stock") or stock_count <= 0:
                return jsonify({"error": "Product is out of stock"}), 400
            if quantity > stock_count:
                return jsonify({"error": f"Only {stock_count} unit(s) available"}), 400

            cart = get_or_create_cart(session_id=create_session_id(), temporary=True)
            carts.update_one(
                {"session_id": cart["session_id"]},
                {"$set": {
                    "items": [{"product_id": str(product_doc["_id"]), "slug": product_doc.get("slug"), "quantity": quantity}],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }},
            )
            return jsonify({
                "session_id": cart["session_id"],
                "checkout_url": f"/checkout?session_id={cart['session_id']}",
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.post("/api/checkout/summary")
    def checkout_summary():
        payload = request.get_json(silent=True) or {}
        try:
            session_id = get_request_session_id(payload, required=True)
            cart = carts.find_one({"session_id": session_id})
            if not cart:
                return jsonify({"error": "Cart not found"}), 404
            address = validate_address(payload.get("address", {})) if payload.get("address") else None
            summary = build_cart_summary(cart)
            return jsonify({
                "session_id": session_id,
                "address": address,
                "items": summary["items"],
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
                "notes": summary["notes"],
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.post("/api/orders")
    def create_order():
        payload = request.get_json(silent=True) or {}
        try:
            session_id = get_request_session_id(payload, required=True)
            address = validate_address(payload.get("address", {}))
            user_identity = normalize_user_identity(payload.get("user"))
            cart = carts.find_one({"session_id": session_id})
            if not cart or not cart.get("items"):
                return jsonify({"error": "Cart is empty"}), 400

            summary = build_cart_summary(cart)
            now = datetime.now(timezone.utc).isoformat()
            order_ref = f"HH{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{secrets.token_hex(3).upper()}"
            razorpay_order, key_id = create_razorpay_order(summary["total_amount"], order_ref)

            order_doc = {
                "user": user_identity,
                "customer_email": str((user_identity or {}).get("email") or address.get("email", "")).strip().lower(),
                "session_id": session_id,
                "order_ref": order_ref,
                "address": address,
                "items": [
                    {
                        "product_id": item["product_id"],
                        "slug": item["slug"],
                        "title": item["title"],
                        "quantity": item["quantity"],
                        "price_at_purchase": item["unit_price"],
                    }
                    for item in summary["items"]
                ],
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
                "status": "pending",
                "status_updated_at": now,
                "tracking_id": "",
                "tracking_url": "",
                "payment_provider": "razorpay",
                "payment_status": "pending",
                "payment_order_id": razorpay_order.get("id"),
                "created_at": now,
                "updated_at": now,
            }
            orders.insert_one(order_doc)
            created = orders.find_one({"order_ref": order_ref})
            create_status_history_entry(created["_id"], "pending", "Order created")
            return jsonify({
                "order_id": str(created["_id"]),
                "order_ref": order_ref,
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
                "items": summary["items"],
                "notes": summary["notes"],
                "razorpay": {
                    "key": key_id,
                    "order_id": razorpay_order.get("id"),
                    "amount": razorpay_order.get("amount"),
                    "currency": razorpay_order.get("currency", "INR"),
                    "name": "Heritage Hues",
                    "description": f"Order {order_ref}",
                    "prefill": {
                        "name": address["name"],
                        "contact": address["phone"],
                    },
                },
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/orders/upi")
    def create_upi_order():
        payload = request.get_json(silent=True) or {}
        payee_vpa = get_upi_id()
        payee_name = os.getenv("UPI_PAYEE_NAME", "Heritage Hues").strip() or "Heritage Hues"
        if not payee_vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500

        try:
            session_id = get_request_session_id(payload, required=True)
            address = validate_address(payload.get("address", {}))
            user_identity = normalize_user_identity(payload.get("user"))
            cart = carts.find_one({"session_id": session_id})
            if not cart or not cart.get("items"):
                return jsonify({"error": "Cart is empty"}), 400

            summary = build_cart_summary(cart)
            now = datetime.now(timezone.utc).isoformat()
            order_ref = f"HH{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{secrets.token_hex(3).upper()}"
            upi_url = build_upi_url(payee_vpa, payee_name, summary["total_amount"], order_ref)

            order_doc = {
                "user": user_identity,
                "customer_email": str((user_identity or {}).get("email") or address.get("email", "")).strip().lower(),
                "session_id": session_id,
                "order_ref": order_ref,
                "address": address,
                "items": [
                    {
                        "product_id": item["product_id"],
                        "slug": item["slug"],
                        "title": item["title"],
                        "quantity": item["quantity"],
                        "price_at_purchase": item["unit_price"],
                    }
                    for item in summary["items"]
                ],
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
                "status": "pending",
                "status_updated_at": now,
                "tracking_id": "",
                "tracking_url": "",
                "payment_provider": "upi",
                "payment_status": "payment_pending",
                "created_at": now,
                "updated_at": now,
            }
            orders.insert_one(order_doc)
            created = orders.find_one({"order_ref": order_ref})
            create_status_history_entry(created["_id"], "pending", "Order created")
            return jsonify({
                "order_id": str(created["_id"]),
                "order_ref": order_ref,
                "total_amount": summary["total_amount"],
                "currency": summary["currency"],
                "items": summary["items"],
                "notes": summary["notes"],
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            return jsonify({"error": str(e)}), 500

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

        payee_vpa = get_upi_id()
        if not payee_vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500

        upi_link = build_secure_upi_link(payee_vpa, amount, order_id)
        return jsonify({"upi_link": upi_link})

    @app.post("/api/orders/confirm-upi")
    def confirm_upi_order():
        payload = request.get_json(silent=True) or {}
        order_id = str(payload.get("order_id", "")).strip()
        transaction_id = str(payload.get("transaction_id", "")).strip()
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
            {
                "$set": {
                    "payment_status": "verification_pending",
                    "payment_id": transaction_id,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return jsonify({
            "order_id": str(updated["_id"]),
            "order_ref": updated["order_ref"],
            "status": updated["status"],
            "payment_id": updated["payment_id"],
            "message": "Payment submitted for verification",
        })

    def format_order(doc):
        return {
            "id": str(doc["_id"]),
            "order_id": str(doc["_id"]),
            "order_ref": doc.get("order_ref", ""),
            "status": doc.get("status", ""),
            "status_updated_at": doc.get("status_updated_at"),
            "payment_status": doc.get("payment_status", ""),
            "payment_provider": doc.get("payment_provider", ""),
            "payment_id": doc.get("payment_id"),
            "transaction_id": doc.get("payment_id"),
            "total_amount": doc.get("total_amount", doc.get("total", 0)),
            "currency": doc.get("currency", "INR"),
            "items": doc.get("items", []),
            "address": doc.get("address", {}),
            "tracking_id": doc.get("tracking_id", ""),
            "tracking_url": doc.get("tracking_url", ""),
            "is_deleted": bool(doc.get("is_deleted", False)),
            "deleted_at": doc.get("deleted_at"),
            "created_at": doc.get("created_at"),
            "updated_at": doc.get("updated_at"),
        }

    @app.get("/api/order/<string:order_id>")
    def get_order_details(order_id):
        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400

        order = orders.find_one({"_id": oid})
        if not order or bool(order.get("is_deleted", False)):
            return jsonify({"error": "Order not found"}), 404

        request_session_id = get_request_session_id(required=False)
        if not is_admin_request() and request_session_id != str(order.get("session_id", "")).strip():
            return jsonify({"error": "You can only view your own orders"}), 403

        response = format_order(order)
        response["status_history"] = get_status_history(oid)
        return jsonify(response)

    @app.get("/api/admin/orders")
    def admin_list_orders():
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

        status = str(request.args.get("status", "")).strip()
        payment_status = str(request.args.get("payment_status", "")).strip()
        include_deleted = str(request.args.get("include_deleted", "")).strip().lower() in {"1", "true", "yes"}
        query = {} if include_deleted else {"is_deleted": {"$ne": True}}
        if status:
            query["status"] = status
        if payment_status:
            query["payment_status"] = payment_status
        docs = list(orders.find(query).sort("created_at", DESCENDING))
        return jsonify([format_order(doc) for doc in docs])

    @app.patch("/api/admin/orders/<string:order_id>/status")
    def admin_update_order_status(order_id):
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

        payload = request.get_json(silent=True) or {}
        status = str(payload.get("status", "")).strip()
        note = str(payload.get("note", "")).strip()
        tracking_id = payload.get("tracking_id")
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
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        response = format_order(updated)
        response["status_history"] = get_status_history(oid)
        return jsonify(response)

    @app.post("/api/admin/orders/<string:order_id>/soft-delete")
    def admin_soft_delete_order(order_id):
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400

        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        if bool(order.get("is_deleted", False)):
            return jsonify({"error": "Order is already deleted"}), 400

        updated = orders.find_one_and_update(
            {"_id": oid},
            {
                "$set": {
                    "is_deleted": True,
                    "deleted_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return jsonify(format_order(updated))

    @app.post("/api/admin/orders/<string:order_id>/approve-payment")
    def admin_approve_order_payment(order_id):
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

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

        for item in order.get("items", []):
            product_doc = products.find_one({"_id": ObjectId(item["product_id"])})
            if not product_doc:
                return jsonify({"error": "Ordered product not found"}), 404
            available = get_stock_count(product_doc)
            if int(item.get("quantity", 0) or 0) > available:
                return jsonify({"error": f"Insufficient stock for {product_doc.get('title', 'product')}"}), 400

        for item in order.get("items", []):
            products.find_one_and_update(
                {"_id": ObjectId(item["product_id"])},
                {
                    "$inc": {"stock_count": -int(item["quantity"])},
                    "$set": {"updated_at": datetime.now(timezone.utc).isoformat()},
                },
            )

        updated = orders.find_one_and_update(
            {"_id": oid},
            {
                "$set": {
                    "payment_status": "paid",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        carts.update_one(
            {"session_id": order.get("session_id")},
            {"$set": {"items": [], "updated_at": datetime.now(timezone.utc).isoformat()}},
        )
        return jsonify(format_order(updated))

    @app.post("/api/orders/verify-payment")
    def verify_order_payment():
        payload = request.get_json(silent=True) or {}
        order_id = str(payload.get("order_id", "")).strip()
        razorpay_order_id = str(payload.get("razorpay_order_id", "")).strip()
        razorpay_payment_id = str(payload.get("razorpay_payment_id", "")).strip()
        razorpay_signature = str(payload.get("razorpay_signature", "")).strip()
        if not order_id or not razorpay_order_id or not razorpay_payment_id or not razorpay_signature:
            return jsonify({"error": "order_id, razorpay_order_id, razorpay_payment_id, and razorpay_signature are required"}), 400

        try:
            oid = ObjectId(order_id)
        except Exception:
            return jsonify({"error": "Invalid order id"}), 400

        order = orders.find_one({"_id": oid})
        if not order:
            return jsonify({"error": "Order not found"}), 404
        if order.get("payment_order_id") != razorpay_order_id:
            return jsonify({"error": "Payment order mismatch"}), 400

        try:
            if not verify_razorpay_signature(razorpay_order_id, razorpay_payment_id, razorpay_signature):
                return jsonify({"error": "Invalid payment signature"}), 400
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        for item in order.get("items", []):
            product_doc = products.find_one({"_id": ObjectId(item["product_id"])})
            if not product_doc:
                return jsonify({"error": "Ordered product not found"}), 404
            available = get_stock_count(product_doc)
            if item["quantity"] > available:
                return jsonify({"error": f"Insufficient stock for {product_doc.get('title', 'product')}"}), 400

        for item in order.get("items", []):
            products.find_one_and_update(
                {"_id": ObjectId(item["product_id"])},
                {
                    "$inc": {"stock_count": -int(item["quantity"])},
                    "$set": {"updated_at": datetime.now(timezone.utc).isoformat()},
                },
            )

        updated = orders.find_one_and_update(
            {"_id": oid},
            {
                "$set": {
                    "payment_status": "paid",
                    "payment_id": razorpay_payment_id,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        carts.update_one({"session_id": order.get("session_id")}, {"$set": {"items": [], "updated_at": datetime.now(timezone.utc).isoformat()}})
        return jsonify({
            "order_id": str(updated["_id"]),
            "order_ref": updated["order_ref"],
            "status": updated["status"],
            "payment_id": updated["payment_id"],
        })

    @app.get("/api/products")
    def list_products():
        docs = products.find().sort("updated_at", DESCENDING)
        return jsonify([format_product(doc) for doc in docs])


    @app.get("/api/uploads/<filename>")
    def serve_upload(filename):
        file_path = UPLOAD_DIR / filename

        print("SERVE FILE:", filename)
        print("FULL PATH:", file_path.resolve())
        print("EXISTS:", file_path.exists())

        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404

        return send_file(file_path)

    @app.get("/api/debug/uploads")
    def debug_uploads():
        return jsonify(
            {
                "upload_dir": str(UPLOAD_DIR),
                "files": [file.name for file in UPLOAD_DIR.glob("*")],
            }
        )

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

    @app.get("/api/products/<string:slug>/reviews")
    def get_product_reviews(slug):
        clean_slug = sanitize_slug(slug)
        query = {"product_slug": clean_slug}
        docs = reviews.find(query).sort("created_at", DESCENDING)
        return jsonify([format_review(doc) for doc in docs])

    def format_user(doc, include_activity=True):
        if not doc:
            return {}
        response = {
            "id": str(doc.get("_id", "")),
            "name": doc.get("name", ""),
            "email": doc.get("email", ""),
            "address": doc.get("address", ""),
            "joined_at": doc.get("joined_at", ""),
            "last_seen_at": doc.get("last_seen_at", ""),
            "updated_at": doc.get("updated_at", ""),
        }
        if include_activity:
            review_list = get_user_reviews(response["email"])
            order_list = get_user_orders(response["email"])
            response["review_count"] = len(review_list)
            response["order_count"] = len(order_list)
            response["reviews"] = review_list
            response["orders"] = order_list
        return response

    @app.post("/api/users")
    def create_or_update_user():
        payload = request.get_json(silent=True) or {}
        name = str(payload.get("name", "")).strip()
        email = str(payload.get("email", "")).strip().lower()
        address = str(payload.get("address", "")).strip()

        if not name:
            return jsonify({"error": "Name is required."}), 400
        if not email or "@" not in email:
            return jsonify({"error": "A valid email address is required."}), 400

        now = datetime.now(timezone.utc).isoformat()
        try:
            users.update_one(
                {"email": email},
                {
                    "$set": {
                        "name": name,
                        "address": address,
                        "last_seen_at": now,
                        "updated_at": now,
                    },
                    "$setOnInsert": {
                        "email": email,
                        "joined_at": now,
                    },
                },
                upsert=True,
            )
            user_doc = users.find_one({"email": email})
            return jsonify(format_user(user_doc)), 200
        except Exception:
            return jsonify({"error": "Failed to save user record."}), 500

    @app.post("/api/products/<string:slug>/reviews")
    def create_product_review(slug):
        payload = request.get_json(silent=True) or {}
        review_data, error = validate_review_payload(payload)
        if error:
            return jsonify({"error": error}), 400

        review_data["email"] = str(review_data.get("email", "")).strip().lower()

        product_doc = products.find_one({"slug": sanitize_slug(slug)})
        if not product_doc:
            return jsonify({"error": "Product not found"}), 404

        now = datetime.now(timezone.utc).isoformat()
        review_doc = {
            "product_id": product_doc["_id"],
            "product_slug": product_doc.get("slug", ""),
            "product_title": product_doc.get("title", ""),
            "name": review_data["name"],
            "email": review_data["email"],
            "message": review_data["message"],
            "rating": review_data["rating"],
            "attachments": review_data.get("attachments", []),
            "created_at": now,
            "updated_at": now,
        }
        result = reviews.insert_one(review_doc)
        created = reviews.find_one({"_id": result.inserted_id})
        return jsonify(format_review(created)), 201

    @app.get("/api/admin/reviews")
    def get_admin_reviews():
        docs = reviews.find().sort("created_at", DESCENDING)
        return jsonify([format_review(doc) for doc in docs])

    @app.delete("/api/admin/reviews/<string:review_id>")
    def delete_admin_review(review_id):
        try:
            oid = ObjectId(review_id)
        except Exception:
            return jsonify({"error": "Invalid review id"}), 400

        result = reviews.delete_one({"_id": oid})
        if result.deleted_count == 0:
            return jsonify({"error": "Review not found"}), 404

        return jsonify({"message": "Review deleted"})

    @app.get("/api/admin/users")
    def get_admin_users():
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

        docs = users.find().sort([("last_seen_at", DESCENDING), ("updated_at", DESCENDING), ("joined_at", DESCENDING)])
        user_list = []
        for doc in docs:
            email = str(doc.get("email", "")).strip()
            if not email:
                continue
            user_data = format_user(doc, include_activity=False)
            user_data["review_count"] = count_user_reviews(email)
            user_data["order_count"] = count_user_orders(email)
            user_list.append(user_data)
        return jsonify(user_list)

    @app.delete("/api/admin/users/<string:email>")
    def delete_admin_user(email):
        try:
            require_admin_access()
        except PermissionError as e:
            return jsonify({"error": str(e)}), 403

        cleaned = str(email).strip().lower()
        if not cleaned:
            return jsonify({"error": "Invalid email address"}), 400

        users.delete_one({"email": cleaned})
        result = reviews.delete_many({"email": cleaned})
        return jsonify({"message": f"Deleted user record and {result.deleted_count} review(s) for {cleaned}"})

    @app.post("/api/pricing/calculate")
    def pricing_calculate():
        payload = request.get_json(silent=True) or {}
        try:
            base_settings = get_or_create_pricing_settings()
            settings = normalize_pricing_settings({**base_settings, **(payload.get("settings") or {})})
            prices = calculate_prices(
                float(payload.get("cost_price", 0)),
                float(payload.get("packaging_cost", 0)),
                float(payload.get("delivery_cost", 0)),
                float(payload.get("discount_percentage", 0)),
                settings
            )
            return jsonify(prices)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.get("/api/admin/pricing-settings")
    def get_pricing_settings():
        try:
            settings = normalize_pricing_settings(get_or_create_pricing_settings())
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        payment_doc = get_or_create_payment_settings()
        settings["upi_id"] = decrypt_text(payment_doc.get("upi_id_encrypted", ""))
        return jsonify(settings)

    @app.put("/api/admin/pricing-settings")
    def update_pricing_settings():
        payload = request.get_json(silent=True) or {}
        upi_id = payload.get("upi_id")
        try:
            current = get_or_create_pricing_settings()
            merged = {**current, **payload}
            normalized = normalize_pricing_settings(merged)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        normalized["updated_at"] = datetime.now(timezone.utc).isoformat()
        pricing_settings.find_one_and_update(
            {"_id": "global"},
            {"$set": normalized},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )

        if upi_id is not None:
            encrypted = encrypt_text(upi_id)
            now = datetime.now(timezone.utc).isoformat()
            payment_settings.find_one_and_update(
                {"_id": "global"},
                {
                    "$set": {
                        "upi_id_encrypted": encrypted,
                        "updated_at": now,
                    },
                    "$setOnInsert": {"created_at": now},
                },
                upsert=True,
            )
            normalized["upi_id"] = str(upi_id or "").strip()
        else:
            payment_doc = get_or_create_payment_settings()
            normalized["upi_id"] = decrypt_text(payment_doc.get("upi_id_encrypted", ""))

        return jsonify(normalized)

    @app.post("/api/admin/products")
    def create_product():
        payload = request.get_json(silent=True) or {}
        data, error = validate_payload(payload, partial=False)
        if error:
            return jsonify({"error": error}), 400
        data["slug"] = make_unique_product_slug(data.get("slug") or data.get("title"))
        
        # Auto-calculate prices
        try:
            settings = normalize_pricing_settings(get_or_create_pricing_settings())
            prices = calculate_prices(
                data["cost_price"],
                data.get("packaging_cost", 0),
                data.get("delivery_cost", 0),
                data["discount_percentage"],
                settings,
            )
            data["mrp"] = prices["mrp"]
            data["discount_amount"] = prices["discount_amount"]
            data["discounted_price"] = prices["discounted_price"]
            data["final_price"] = prices["final_price"]
            data["gst_amount"] = prices["gst_amount"]
            data["total_cost"] = prices["total_cost"]
            data["profit"] = prices["profit"]
            data["margin"] = prices["margin"]
            data["margin_percentage"] = prices["margin_percentage"]
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        
        data["is_out_of_stock"] = int(data.get("stock_count", 0) or 0) <= 0

        now = datetime.now(timezone.utc).isoformat()
        data["created_at"] = now
        data["updated_at"] = now

        try:
            result = products.insert_one(data)
        except DuplicateKeyError:
            return jsonify({"error": "A product with this slug already exists"}), 409

        created = products.find_one({"_id": result.inserted_id})
        invalidate_sitemap_cache()
        ping_google_sitemap_async()
        return jsonify(format_product(created)), 201

    @app.put("/api/admin/products/<string:product_id>")
    def update_product(product_id):
        payload = request.get_json(silent=True) or {}
        data, error = validate_payload(payload, partial=True)
        if error:
            return jsonify({"error": error}), 400
        if not data:
            return jsonify({"error": "No valid fields to update"}), 400

        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        try:
            oid = ObjectId(product_id)
        except Exception:
            return jsonify({"error": "Invalid product id"}), 400

        existing = products.find_one({"_id": oid})
        if not existing:
            return jsonify({"error": "Product not found"}), 404
        if "slug" in data:
            data["slug"] = make_unique_product_slug(data["slug"], current_product_id=oid)

        # Recalculate if pricing inputs changed
        if {"cost_price", "packaging_cost", "delivery_cost", "discount_percentage"} & set(data.keys()):
            cost_price = data.get("cost_price", existing.get("cost_price", 0))
            packaging_cost = data.get("packaging_cost", existing.get("packaging_cost", existing.get("packaging_charge", 0)))
            delivery_cost = data.get("delivery_cost", existing.get("delivery_cost", existing.get("delivery_charge", 0)))
            disc_pct = data.get("discount_percentage", existing.get("discount_percentage", existing.get("discount", 0)))
            try:
                settings = normalize_pricing_settings(get_or_create_pricing_settings())
                prices = calculate_prices(float(cost_price), float(packaging_cost), float(delivery_cost), float(disc_pct), settings)
                data["mrp"] = prices["mrp"]
                data["discount_amount"] = prices["discount_amount"]
                data["discounted_price"] = prices["discounted_price"]
                data["final_price"] = prices["final_price"]
                data["gst_amount"] = prices["gst_amount"]
                data["total_cost"] = prices["total_cost"]
                data["profit"] = prices["profit"]
                data["margin"] = prices["margin"]
                data["margin_percentage"] = prices["margin_percentage"]
            except ValueError as e:
                return jsonify({"error": str(e)}), 400

        resulting_stock = int(data.get("stock_count", existing.get("stock_count", 0)) or 0)
        data["is_out_of_stock"] = resulting_stock <= 0

        try:
            updated = products.find_one_and_update(
                {"_id": oid},
                {"$set": data},
                return_document=ReturnDocument.AFTER,
            )
        except DuplicateKeyError:
            return jsonify({"error": "A product with this slug already exists"}), 409

        if not updated:
            return jsonify({"error": "Product not found"}), 404

        invalidate_sitemap_cache()
        return jsonify(format_product(updated))

    @app.delete("/api/admin/products/<string:product_id>")
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

    @app.post("/api/admin/uploads")
    def upload_product_photos():
        files = request.files.getlist("photos")
        if not files:
            return jsonify({"error": "No files uploaded"}), 400
        if len(files) > 10:
            return jsonify({"error": "maximum 10 photos are allowed"}), 400

        uploaded = []
        for file in files:
            filename = secure_filename(file.filename or "")
            if not filename:
                return jsonify({"error": "Invalid file name"}), 400
            if not is_allowed_file(filename):
                return jsonify({"error": "Only jpg, jpeg, png, and webp files are allowed"}), 400

            ext = filename.rsplit(".", 1)[1].lower()
            stored_name = f"{secrets.token_hex(12)}.{ext}"
            file_path = UPLOAD_DIR / stored_name
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            file.save(file_path)
            print("SAVED PRODUCT PHOTO:", file_path, "EXISTS:", file_path.exists())
            print("FILES:", [saved_file.name for saved_file in UPLOAD_DIR.glob("*")])
            uploaded.append(build_photo_url(stored_name))

        return jsonify({"photos": uploaded}), 201

    @app.post("/api/uploads/review-images")
    def upload_review_attachment():
        attachment = request.files.get("attachment")
        if not attachment:
            return jsonify({"error": "No attachment file uploaded"}), 400

        filename = secure_filename(attachment.filename or "")
        if not filename:
            return jsonify({"error": "Invalid file name"}), 400
        if not is_allowed_file(filename):
            return jsonify({"error": "Only jpg, jpeg, png, and webp files are allowed"}), 400

        ext = filename.rsplit(".", 1)[1].lower()
        stored_name = f"{secrets.token_hex(12)}.{ext}"
        file_path = UPLOAD_DIR / stored_name
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        attachment.save(file_path)
        print("SAVED REVIEW ATTACHMENT:", file_path, "EXISTS:", file_path.exists())
        print("FILES:", [saved_file.name for saved_file in UPLOAD_DIR.glob("*")])
        return jsonify({"url": build_photo_url(stored_name)}), 201

    @app.post("/api/checkout/upi-intent")
    def create_upi_intent():
        payee_vpa = get_upi_id()
        payee_name = os.getenv("UPI_PAYEE_NAME", "Heritage Hues").strip() or "Heritage Hues"

        if not payee_vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500

        payload = request.get_json(silent=True) or {}
        items, error = validate_checkout_payload(payload)
        if error:
            return jsonify({"error": error}), 400

        summary, error = build_checkout_summary(items)
        if error:
            return jsonify({"error": error}), 400

        now = datetime.now(timezone.utc).isoformat()
        order_ref = f"HH{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}{secrets.token_hex(3).upper()}"
        upi_url = build_upi_url(payee_vpa, payee_name, summary["total"], order_ref)

        order_doc = {
            "order_ref": order_ref,
            "items": summary["items"],
            "subtotal": summary["subtotal"],
            "gst": summary["gst"],
            "total": summary["total"],
            "currency": summary["currency"],
            "payment_method": "upi_intent",
            "payment_status": "pending",
            "created_at": now,
            "updated_at": now,
        }
        orders.insert_one(order_doc)

        return jsonify(
            {
                "order_ref": order_ref,
                "upi_url": upi_url,
                "summary": summary,
                "message": "Redirecting to your default UPI app.",
            }
        )

    @app.post("/api/checkout/upi-link")
    def create_upi_link():
        payload = request.get_json(silent=True) or {}
        order_id = str(payload.get("order_id", "")).strip()
        amount = payload.get("amount")

        if not order_id:
            return jsonify({"error": "order_id is required"}), 400

        try:
            amount = float(amount)
        except (TypeError, ValueError):
            return jsonify({"error": "amount must be a number"}), 400

        if amount <= 0:
            return jsonify({"error": "amount must be greater than zero"}), 400

        payee_vpa = get_upi_id()
        if not payee_vpa:
            return jsonify({"error": "UPI is not configured on the server"}), 500

        upi_link = build_secure_upi_link(payee_vpa, amount, order_id)
        return jsonify({"upi_link": upi_link})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
