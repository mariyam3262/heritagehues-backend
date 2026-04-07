from datetime import datetime, timezone
from html import escape
import json
import logging
import os
import re
import threading
from urllib import request as urlrequest


SITE_URL = os.getenv("SITE_URL", "https://heritagehues.net").rstrip("/")
BRAND_NAME = os.getenv("SEO_BRAND_NAME", "Heritage Hues").strip() or "Heritage Hues"
SITEMAP_URL = f"{SITE_URL}/sitemap.xml"
SITEMAP_MAX_URLS = 50000
SITEMAP_CACHE_SECONDS = 300
logger = logging.getLogger(__name__)

STATIC_SITEMAP_PAGES = (
    {"path": "/", "priority": "1.0"},
    {"path": "/categories", "priority": "0.8"},
    {"path": "/category/bandhani-sarees", "priority": "0.9"},
    {"path": "/category/bandhani-dupattas", "priority": "0.8"},
    {"path": "/wholesale", "priority": "0.8"},
    {"path": "/blog", "priority": "0.7"},
)


def absolute_url(path_or_url):
    value = str(path_or_url or "").strip()
    if not value:
        return SITE_URL
    if value.startswith(("http://", "https://")):
        return value
    if not value.startswith("/"):
        value = f"/{value}"
    return f"{SITE_URL}{value}"


def slugify(value):
    cleaned = str(value or "").strip().lower()
    cleaned = re.sub(r"[^a-z0-9\s-]", "", cleaned)
    cleaned = re.sub(r"[\s_-]+", "-", cleaned)
    return cleaned.strip("-")


def generate_unique_slug(value, exists_func):
    base_slug = slugify(value) or "product"
    candidate = base_slug
    suffix = 2
    while exists_func(candidate):
        candidate = f"{base_slug}-{suffix}"
        suffix += 1
    return candidate


def _plain_text(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _product_name(product):
    return _plain_text(product.get("title") or product.get("name") or "Bandhani Product")


def _product_description(product):
    description = _plain_text(product.get("description"))
    if description:
        return description
    return f"Shop {_product_name(product)} from {BRAND_NAME}, crafted for Bandhani lovers and ethnic wear collections."


def _meta_description(text):
    text = _plain_text(text)
    additions = (
        " Buy handmade Gujarat Bandhani online from Heritage Hues.",
        " Explore sarees, dupattas and wholesale ethnic styles.",
        " Fast checkout and curated artisan-inspired designs.",
    )
    for addition in additions:
        if len(text) >= 150:
            break
        text = f"{text}{addition}"
    if len(text) <= 160:
        return text
    return f"{text[:157].rsplit(' ', 1)[0]}..."


def generate_meta(product):
    name = _product_name(product)
    slug = slugify(product.get("slug") or name)
    category = _plain_text(product.get("category")) or "Bandhani"
    title = f"Buy {name} Online | Handmade Gujarat Bandhej"
    if len(title) > 65:
        title = f"{name} | {BRAND_NAME}"
    keywords = [
        name,
        category,
        "Bandhani saree",
        "Bandhani dupatta",
        "Bandhej",
        "Gujarat handmade ethnic wear",
        "Bandhani wholesale",
        BRAND_NAME,
    ]
    return {
        "title": title,
        "description": _meta_description(_product_description(product)),
        "keywords": ", ".join(dict.fromkeys(keyword for keyword in keywords if keyword)),
        "canonical_url": absolute_url(f"/product/{slug}"),
    }


def build_product_schema(product):
    name = _product_name(product)
    price = product.get("final_price", product.get("price", 0))
    photos = product.get("photos") or []
    image = product.get("image_url") or (photos[0] if photos else "")
    availability = "https://schema.org/InStock"
    if bool(product.get("is_out_of_stock")) or int(product.get("stock_count", 0) or 0) <= 0:
        availability = "https://schema.org/OutOfStock"

    return {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": name,
        "image": absolute_url(image) if image else absolute_url("/"),
        "description": _product_description(product),
        "brand": {"@type": "Brand", "name": BRAND_NAME},
        "offers": {
            "@type": "Offer",
            "url": generate_meta(product)["canonical_url"],
            "priceCurrency": product.get("currency", "INR"),
            "price": f"{float(price or 0):.2f}",
            "availability": availability,
        },
    }


def build_product_seo(product):
    schema = build_product_schema(product)
    return {
        "meta": generate_meta(product),
        "structured_data": schema,
        "json_ld": json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
    }


def format_lastmod(value=None):
    if isinstance(value, datetime):
        resolved = value
    elif value:
        try:
            resolved = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            resolved = datetime.now(timezone.utc)
    else:
        resolved = datetime.now(timezone.utc)
    if resolved.tzinfo is None:
        resolved = resolved.replace(tzinfo=timezone.utc)
    return resolved.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_sitemap_xml(entries):
    url_nodes = []
    for entry in entries:
        loc = escape(absolute_url(entry.get("loc") or entry.get("path") or "/"))
        lastmod = escape(format_lastmod(entry.get("lastmod")))
        priority = escape(str(entry.get("priority", "0.5")))
        url_nodes.append(
            "  <url>\n"
            f"    <loc>{loc}</loc>\n"
            f"    <lastmod>{lastmod}</lastmod>\n"
            f"    <priority>{priority}</priority>\n"
            "  </url>"
        )
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        + "\n".join(url_nodes)
        + "\n</urlset>\n"
    )


def build_sitemap_index_xml(entries):
    sitemap_nodes = []
    for entry in entries:
        loc = escape(absolute_url(entry.get("loc") or "/sitemap.xml"))
        lastmod = escape(format_lastmod(entry.get("lastmod")))
        sitemap_nodes.append(
            "  <sitemap>\n"
            f"    <loc>{loc}</loc>\n"
            f"    <lastmod>{lastmod}</lastmod>\n"
            "  </sitemap>"
        )
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        + "\n".join(sitemap_nodes)
        + "\n</sitemapindex>\n"
    )


def ping_google_sitemap():
    ping_url = f"https://www.google.com/ping?sitemap={SITEMAP_URL}"
    try:
        with urlrequest.urlopen(ping_url, timeout=3) as response:
            return 200 <= int(response.status) < 300
    except Exception as exc:
        logger.warning("Google sitemap ping failed: %s", exc)
        return False


def ping_google_sitemap_async():
    thread = threading.Thread(target=ping_google_sitemap, daemon=True)
    thread.start()
