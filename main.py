import os
from dotenv import load_dotenv
load_dotenv() 
import asyncio
import subprocess
import json
import logging
import hmac
import hashlib
import time
import html
from typing import Optional, Literal, List, Dict, Any
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import re
import uuid
from datetime import datetime, timedelta, timezone
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

import stripe  
from scanner_api.zap_scanner import router as zap_router

from fastapi import FastAPI, HTTPException, Request , UploadFile, File , Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from starlette.responses import PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import joblib
import pandas as pd
import httpx
from urllib.parse import urlparse, urlencode
from io import BytesIO
from weasyprint import HTML
from openpyxl import Workbook
from bson import ObjectId
# Load environment variables from front2/.env (preferred) and backend/.env if present.
# Loading backend after front lets backend-only secrets (webhook, SMTP, etc.) fill in
# without overriding values already defined for the frontend.
try:
    from dotenv import load_dotenv
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    front_env = os.path.join(project_root, 'front2', '.env')
    backend_env = os.path.join(project_root, 'backend', '.env')
    if os.path.exists(front_env):
        load_dotenv(front_env)
    if os.path.exists(backend_env):
        load_dotenv(backend_env)
except Exception:
    pass
# === MODULES INTERNES ===
from domainAnalyzer.service import router as domain_analyzer_router 
from domainAnalyzer.analyzer import DomainAnalyzer
from scanner_api.save_to_mongo import get_scan_from_mongo
from ia_cms_detection.IA.scraping import extract_features
from scanner_api.routes import scan_router
from scanner_api.medianet_routes import register_report_generation_routes, medianet_router
from scanner_api.wordpress_scanner import build_wpprobe_table
from scanner_api.nuclei_parser import parse_nuclei_output
sandbox_router = None
_SANDBOX_IMPORT_ERROR: Exception | None = None
try:
    from scanner_api.sandbox.routes import router as sandbox_router
except ModuleNotFoundError as exc:
    _SANDBOX_IMPORT_ERROR = exc
except Exception as exc:  # pragma: no cover - unexpected import failure
    _SANDBOX_IMPORT_ERROR = exc
from DB.database import (
    scan_drupal_collection,
    scan_wp_collection,
    scan_presta_collection,
    scan_generic_collection,
    free_scan_emails_collection,
    db
)
from scanner_api.utils import convert_objectid  # ou utils.json_helpers si tu fais un sous-dossier
from fastapi import Body
from fastapi.responses import StreamingResponse
import zipfile
import io
from starlette.middleware.wsgi import WSGIMiddleware
from pymongo.errors import PyMongoError

# === CHARGEMENT MODELE IA (optionnel) ===
# Le serveur ne doit pas planter si les fichiers du modèle manquent en dev/local.
model = None
feature_order = None
label_encoder = None
MODEL_AVAILABLE = False
try:
    model = joblib.load("ia_cms_detection/models/cms_detector_model.pkl")
    feature_order = joblib.load("ia_cms_detection/models/feature_names.pkl")
    label_encoder = joblib.load("ia_cms_detection/models/label_encoder.pkl")
    MODEL_AVAILABLE = True
except Exception as e:
    # Ne pas stopper le démarrage du serveur — afficher un avertissement pour debug.
    print(f"[WARN] IA model not loaded or missing files: {e}")
    MODEL_AVAILABLE = False

DOMAIN_ANALYZER_AVAILABLE = True

CMS_UNKNOWN_VALUES = {"unknown", "inconnu"}

# === CONFIG FASTAPI ===
app = FastAPI(
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)


stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SEUIL = 0.5  # Seuil de confiance
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(BASE_DIR, "templates")
templates = Jinja2Templates(directory=templates_dir)

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PRICE_BASIC = os.environ.get("STRIPE_PRICE_BASIC")
STRIPE_PRICE_PRO = os.environ.get("STRIPE_PRICE_PRO")
STRIPE_PRICE_ENTERPRISE = os.environ.get("STRIPE_PRICE_ENTERPRISE")
STRIPE_PRODUCT_NAME_PREFIX = os.environ.get("STRIPE_PRODUCT_NAME_PREFIX") or "Cyber Scan"
STRIPE_CURRENCY = (os.environ.get("STRIPE_CURRENCY") or "eur").lower()
STRIPE_BILLING_INTERVAL = (os.environ.get("STRIPE_BILLING_INTERVAL") or "month").lower()
try:
    STRIPE_BILLING_INTERVAL_COUNT = int(os.environ.get("STRIPE_BILLING_INTERVAL_COUNT") or 1)
except ValueError:
    STRIPE_BILLING_INTERVAL_COUNT = 1
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
STRIPE_WEBHOOK_SECRET_SECONDARY = os.environ.get("STRIPE_WEBHOOK_SECRET_SECONDARY")
_extra_webhook_secrets_raw = os.environ.get("STRIPE_WEBHOOK_ADDITIONAL_SECRETS") or ""
STRIPE_WEBHOOK_SECRETS: list[str] = []
for candidate in [STRIPE_WEBHOOK_SECRET, STRIPE_WEBHOOK_SECRET_SECONDARY]:
    if candidate:
        STRIPE_WEBHOOK_SECRETS.append(candidate)
if _extra_webhook_secrets_raw:
    STRIPE_WEBHOOK_SECRETS.extend(
        secret.strip()
        for secret in _extra_webhook_secrets_raw.split(",")
        if secret.strip()
    )
try:
    STRIPE_WEBHOOK_TOLERANCE = int(os.environ.get("STRIPE_WEBHOOK_TOLERANCE") or 300)
except ValueError:
    STRIPE_WEBHOOK_TOLERANCE = 300
STRIPE_ENABLE_AUTOMATIC_TAX = (os.environ.get("STRIPE_ENABLE_AUTOMATIC_TAX") or "true").lower() in {"1", "true", "yes", "on"}
_billing_address_collection = (os.environ.get("STRIPE_BILLING_ADDRESS_COLLECTION") or "auto").lower()
STRIPE_BILLING_ADDRESS_COLLECTION = _billing_address_collection if _billing_address_collection in {"auto", "required"} else "auto"
_stripe_tax_ids_raw = os.environ.get("STRIPE_TAX_RATE_IDS") or os.environ.get("STRIPE_TAX_RATE_ID") or ""
STRIPE_TAX_RATE_IDS = [rate.strip() for rate in _stripe_tax_ids_raw.split(",") if rate.strip()]
STRIPE_ACCOUNT_COUNTRY = (os.environ.get("STRIPE_ACCOUNT_COUNTRY") or "FR").upper()
SUPABASE_INVOICES_TABLE = ((os.environ.get("SUPABASE_INVOICES_TABLE") or "invoices").strip() or "invoices")
try:
    STRIPE_PROCESSING_FEE_PERCENT = Decimal(os.environ.get("STRIPE_PROCESSING_FEE_PERCENT") or "0")
except (InvalidOperation, TypeError):
    STRIPE_PROCESSING_FEE_PERCENT = Decimal("0")
try:
    STRIPE_PROCESSING_FEE_FIXED_CENTS = int(
        (Decimal(os.environ.get("STRIPE_PROCESSING_FEE_FIXED") or "0") * 100).to_integral_value(rounding=ROUND_HALF_UP)
    )
except (InvalidOperation, TypeError):
    STRIPE_PROCESSING_FEE_FIXED_CENTS = 0

STRIPE_FEE_RULES = {
    "domestic_card": {
        "percent": "2.9",
        "fixed": "0.30",
        "note": "Carte nationale (domestique)",
    },
    "manual_entry": {
        "extra_percent": "0.5",
        "fixed": "0.0",
        "note": "Carte saisie manuellement (ajout de 0,5 %)",
    },
    "international_card": {
        "extra_percent": "1.5",
        "fixed": "0.0",
        "note": "Carte internationale (ajout de 1,5 %)",
    },
    "currency_conversion": {
        "extra_percent": "1.0",
        "fixed": "0.0",
        "note": "Conversion de devise (ajout de 1 %)",
    },
    "instant_bank": {
        "percent": "2.6",
        "fixed": "0.30",
        "note": "Paiement bancaire instantané (frais réduits)",
    },
    "klarna": {
        "percent": "5.99",
        "fixed": "0.30",
        "note": "Klarna / Paiement différé (frais élevés)",
    },
    "ach_debit": {
        "percent": "0.8",
        "fixed": "0.0",
        "fixed_cap": "5.0",
        "note": "Prélèvement bancaire US (ACH Direct Debit, 0,8 % plafonné à 5 $)",
    },
    "stablecoin": {
        "percent": "1.5",
        "fixed": "0.0",
        "note": "Paiement en stablecoins (USDC, USDT...)",
    },
}

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY")
BACKEND_API_KEY = os.environ.get("BACKEND_API_KEY")
DEHASHED_API_KEY = os.environ.get("DEHASHED_API_KEY") or os.environ.get("DEHASHED_APIKEY")
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_SENDER_EMAIL = os.environ.get("SMTP_SENDER_EMAIL") or os.environ.get("SMTP_FROM")
SMTP_SENDER_NAME = (os.environ.get("SMTP_SENDER_NAME") or "CyberScan").strip()
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
SMTP_TIMEOUT = int(os.environ.get("SMTP_TIMEOUT", "30"))
SUPPORT_ALERT_EMAIL = (os.environ.get("SUPPORT_ALERT_EMAIL") or "support@cyberscan.fr").strip()

logger = logging.getLogger("cyber_scan.backend")
if not logger.handlers:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

if STRIPE_SECRET_KEY and stripe:
    stripe.api_key = STRIPE_SECRET_KEY

if _SANDBOX_IMPORT_ERROR:
    logger.warning(
        "Sandbox routes disabled: %s. Install optional dependency `docker` to enable.",
        _SANDBOX_IMPORT_ERROR,
    )

# === CORS ===
app.add_middleware(
    CORSMiddleware,
    allow_origins=[  
         "http://108.181.1.247",       # ton frontend en prod
         "http://localhost:5173",
         "http://localhost:3000",],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_raw_allowed_origins = [
    "http://108.181.1.247",
    "http://localhost:5173",
    "http://localhost:3000",
    os.environ.get("NEXT_PUBLIC_APP_URL"),
    os.environ.get("NEXT_PUBLIC_SITE_URL"),
]
ALLOWED_WEB_ORIGINS = {origin.rstrip('/') for origin in _raw_allowed_origins if origin}

def _read_timeout_env(var_name: str, default: float) -> float:
    """Safely parse timeout values from environment without crashing the server."""
    raw = os.environ.get(var_name)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        logging.warning(f"Invalid value for {var_name}={raw!r}; falling back to {default}s")
        return default

SCAN_HTTP_TIMEOUT = _read_timeout_env("SCAN_HTTP_TIMEOUT", 45.0)

# === MODELE POUR ENTRÉE nnewww ===
class SiteInput(BaseModel):
    urls: list[str]

class DehashedQueryPayload(BaseModel):
    query: str | None = None

class MultiReportRequest(BaseModel):
    scan_ids: list[str]


class PasswordResetRequest(BaseModel):
    email: str


class FreeScanReportRequest(BaseModel):
    email: str
    scan_id: str | None = None
    mongo_report_id: str | None = None
    report_format: str = "pdf"
    site_url: str | None = None
    display_cms: str | None = None
    display_risk: str | None = None


class RefundRequest(BaseModel):
    invoiceId: str | None = None
    userId: str | None = None
    paymentIntentId: str | None = None
    reason: str | None = None


class RefundDecisionPayload(BaseModel):
    decision: Literal['approve', 'reject']
    note: str | None = None


class StripeCheckoutPayload(BaseModel):
    planId: str
    billingInterval: str = "monthly"
    userId: str | None = None
    email: str | None = None
# === VALIDATION URL ===
def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return all([parsed.scheme, parsed.netloc])

FIREWALL_KEYWORDS = [
    "access denied", "firewall", "forbidden", "cloudflare", "sucuri",
    "incapsula", "akamai", "blocked", "security service"
]

# === SCRAPING + EXTRACTION DES FEATURES ===
async def fetch_and_extract(url: str) -> dict:
    timeout = httpx.Timeout(SCAN_HTTP_TIMEOUT)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers=headers) as client:
        try:
            response = await client.get(url)
            status_code = response.status_code
            html = response.text.lower()
            header_data = response.headers

            # 🔎 Détection firewall via code HTTP et contenu
            if status_code in (403, 406, 451, 499, 503):
                for keyword in FIREWALL_KEYWORDS:
                    if keyword in html:
                        raise HTTPException(status_code=403, detail="Firewall detected")
                raise HTTPException(status_code=status_code, detail=f"Accès refusé ({status_code})")

            # 🔎 Timeout / erreurs réseau
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Timeout: le site est trop lent ou n'a pas répondu")
        except httpx.ConnectError:
            raise HTTPException(status_code=502, detail="Erreur réseau: connexion refusée ou DNS invalide")
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Erreur requête: {e}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erreur inattendue: {e}")

        # 🔎 Tentative robots.txt
        try:
            robots_response = await client.get(url.rstrip("/") + "/robots.txt")
            robots_txt = robots_response.text.lower()
        except Exception:
            robots_txt = ""

    return extract_features(url, html, header_data, robots_txt)


def normalize_cms_label(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned or cleaned.lower() in CMS_UNKNOWN_VALUES:
        return None
    return cleaned


async def fallback_cms_detection(url: str) -> str:
    if not DOMAIN_ANALYZER_AVAILABLE:
        return "Inconnu"

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path or url

    def _analyze():
        analyzer = DomainAnalyzer(timeout=8)
        return analyzer.analyze_domain(domain)

    try:
        result = await asyncio.to_thread(_analyze)
        cms_list = result.get("cms") or []
        for candidate in cms_list:
            normalized = normalize_cms_label(candidate)
            if normalized:
                return normalized
    except Exception as exc:
        logger.warning(f"Echec détection CMS fallback pour {url}: {exc}")

    return "Inconnu"
# === ROUTE IA CMS DETECTION ===




@app.post("/predict")
async def predict_cms(data: SiteInput):
    MAX_URLS = 10
    SEUIL = 0.5
    if not data.urls:
        raise HTTPException(status_code=400, detail="Liste d'URLs vide.")
    if len(data.urls) > MAX_URLS:
        raise HTTPException(status_code=400, detail=f"Limite de {MAX_URLS} URLs dépassée.")

    results = []

    for url in data.urls:
        if not is_valid_url(url):
            results.append({"url": url, "error": "URL invalide", "status": "error"})
            continue

        try:
            if MODEL_AVAILABLE:
                features = await fetch_and_extract(url)
                input_df = pd.DataFrame([features])
                input_df = input_df.reindex(columns=feature_order, fill_value=0)
                pred_encoded = model.predict(input_df)[0]
                proba = model.predict_proba(input_df).max()
                pred_label = label_encoder.inverse_transform([pred_encoded])[0]
                cms = pred_label if proba >= SEUIL else await fallback_cms_detection(url)
                confidence = round(float(proba), 3)
            else:
                cms = await fallback_cms_detection(url)
                confidence = 0.0

            results.append({
                "url": url,
                "cms": cms,
                "confiance": confidence,
                "status": "success"
            })

        except Exception as e:
            results.append({"url": url, "error": str(e), "status": "error"})

    return {"resultats": results}

# === ROUTE SANTÉ ===
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# === DEHASHED CHECK DOMAIN ===
@app.api_route("/dehashed/check-domain", methods=["GET", "POST"])
async def dehashed_check_domain(
    query: str | None = Query(None),
    payload: DehashedQueryPayload | None = Body(None),
):
    query_value = query
    if not query_value and payload:
        query_value = payload.query

    if not query_value:
        return JSONResponse(status_code=400, content={"error": "Missing query parameter"})

    if not DEHASHED_API_KEY:
        return JSONResponse(status_code=500, content={"error": "DeHashed API key not configured"})

    headers = {
        "Content-Type": "application/json",
        "Dehashed-Api-Key": DEHASHED_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://api.dehashed.com/v2/search",
                json={"query": query_value},
                headers=headers,
            )
    except httpx.TimeoutException:
        return JSONResponse(status_code=504, content={"error": "DeHashed API timeout"})
    except httpx.RequestError as exc:
        logger.error("DeHashed API request error: %s", exc)
        return JSONResponse(
            status_code=502,
            content={"error": "DeHashed API request failed", "message": str(exc)},
        )
    except Exception as exc:
        logger.exception("Internal error while calling DeHashed API: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "message": str(exc)},
        )

    if response.status_code >= 400:
        try:
            details = response.json()
        except ValueError:
            details = response.text
        logger.error("DeHashed API error: %s %s", response.status_code, details)
        return JSONResponse(
            status_code=response.status_code,
            content={"error": "DeHashed API failed", "details": details},
        )

    try:
        payload = response.json()
    except ValueError as exc:
        logger.error("DeHashed API invalid JSON: %s", exc)
        return JSONResponse(
            status_code=502,
            content={"error": "DeHashed API returned invalid JSON"},
        )

    return {"success": True, "data": payload}

def collect_vulnerabilities(scan: dict):
    vulns = []

    # Vulnérabilités dans le thème principal
    theme = scan.get("main_theme", {})
    for v in theme.get("vulnerabilities", []):
        vulns.append({
            "id": ", ".join(v.get("references", {}).get("cve", [])) or "N/A",
            "severity": "N/A",
            "description": v.get("title", "Sans description")
        })

    # Vulnérabilités dans les plugins
    plugins = scan.get("plugins", {})
    for plugin in plugins.values():
        for v in plugin.get("vulnerabilities", []):
            vulns.append({
                "id": ", ".join(v.get("references", {}).get("cve", [])) or "N/A",
                "severity": "N/A",
                "description": v.get("title", "Sans description")
            })

    return vulns

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
ZAP_SEVERITY_MAP = {
    "informational": "low",
    "info": "low",
    "low": "low",
    "warning": "medium",
    "medium": "medium",
    "high": "high",
    "severe": "high",
    "critical": "critical",
}


def _bump_severity(counts: dict[str, int], current: str | None, candidate: str | None) -> str | None:
    if not candidate:
        return current
    sev = candidate.lower()
    if sev not in counts:
        return current
    counts[sev] += 1
    if current is None:
        return sev
    return sev if SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(current) else current


def compute_vulnerability_summary(scan: dict) -> tuple[dict[str, int], str | None]:
    counts = {key: 0 for key in SEVERITY_ORDER}
    highest = None

    cms_scan = scan.get("cms_scan") or {}
    if isinstance(cms_scan, dict):
        for cve in cms_scan.get("cves", []) or []:
            highest = _bump_severity(counts, highest, cve.get("severity"))

    nuclei_scan = scan.get("nuclei_scan") or {}
    parsed_results = nuclei_scan.get("parsed_results")
    if not parsed_results and nuclei_scan.get("nuclei_stdout"):
        parsed_results = parse_nuclei_output(nuclei_scan.get("nuclei_stdout", ""))
    for item in parsed_results or []:
        if isinstance(item, dict):
            highest = _bump_severity(counts, highest, item.get("severity"))

    zap_scan = scan.get("zap_scan") or {}
    for alert in zap_scan.get("alerts", []) or []:
        if not isinstance(alert, dict):
            continue
        mapped = ZAP_SEVERITY_MAP.get((alert.get("risk") or alert.get("severity") or "").lower())
        highest = _bump_severity(counts, highest, mapped or alert.get("risk") or alert.get("severity"))

    return counts, highest


_generate_report_file = register_report_generation_routes(
    medianet_router,
    get_scan_from_mongo_fn=get_scan_from_mongo,
    convert_objectid_fn=convert_objectid,
    compute_summary_fn=compute_vulnerability_summary,
    build_wpprobe_table_fn=build_wpprobe_table,
    parse_nuclei_output_fn=parse_nuclei_output,
    templates=templates,
    severity_order=SEVERITY_ORDER,
)


_PLAN_PRICE_RAW: dict[str, str | None] = {
    "basic": STRIPE_PRICE_BASIC or "9",
    "pro": STRIPE_PRICE_PRO or "19",
    "enterprise": STRIPE_PRICE_ENTERPRISE or "39",  # Premium / Full Access
}

# Credits alignés avec la grille affichée côté front
PLAN_CREDITS: dict[str, int] = {
    "free": 3,
    "basic": 20,
    "pro": 50,
    "enterprise": 999999,  # Premium illimité
}
FREE_PLAN_CREDITS = PLAN_CREDITS.get("free", 0)


_PLAN_PRICE_ANNUAL_RAW: dict[str, str | None] = {
    "basic": os.environ.get("STRIPE_PRICE_BASIC_YEARLY"),
    "pro": os.environ.get("STRIPE_PRICE_PRO_YEARLY"),
    "enterprise": os.environ.get("STRIPE_PRICE_ENTERPRISE_YEARLY"),
}

def _resolve_plan_pricing(plan_id: str, interval: str = "monthly") -> dict[str, int | str | None]:
    interval = (interval or "monthly").lower()
    raw_map = _PLAN_PRICE_ANNUAL_RAW if interval in {"annual", "yearly", "year"} else _PLAN_PRICE_RAW
    raw_value = raw_map.get(plan_id)
    if raw_value is None:
        return {"price_id": None, "unit_amount": None}
    value = str(raw_value).strip()
    if not value:
        return {"price_id": None, "unit_amount": None}
    if value.startswith("price_"):
        return {"price_id": value, "unit_amount": None}
    try:
        amount_decimal = Decimal(value)
    except (InvalidOperation, TypeError):
        # Consider non-numeric strings as already configured Stripe IDs
        return {"price_id": value, "unit_amount": None}
    cents = int((amount_decimal * 100).to_integral_value(rounding=ROUND_HALF_UP))
    if cents <= 0:
        raise ValueError(f"Montant Stripe invalide pour le plan {plan_id}: {value}")
    return {"price_id": None, "unit_amount": cents}


def _processing_fee_cents(amount_cents: int) -> int:
    if amount_cents <= 0:
        return 0
    fee = Decimal(0)
    if STRIPE_PROCESSING_FEE_PERCENT:
        fee += (Decimal(amount_cents) * STRIPE_PROCESSING_FEE_PERCENT) / Decimal(100)
    if STRIPE_PROCESSING_FEE_FIXED_CENTS:
        fee += Decimal(STRIPE_PROCESSING_FEE_FIXED_CENTS)
    return int(fee.to_integral_value(rounding=ROUND_HALF_UP)) if fee > 0 else 0


def _with_tax_rates(line_item: dict) -> dict:
    if STRIPE_TAX_RATE_IDS and not STRIPE_ENABLE_AUTOMATIC_TAX:
        line_item["tax_rates"] = STRIPE_TAX_RATE_IDS
    return line_item


def _build_line_items(plan_id: str, pricing: dict[str, int | str | None], interval: str = "monthly") -> list[dict]:
    price_id = pricing.get("price_id")
    unit_amount = pricing.get("unit_amount")
    interval = (interval or "monthly").lower()
    recurring_interval = "year" if interval in {"annual", "yearly", "year"} else STRIPE_BILLING_INTERVAL
    recurring_interval_count = STRIPE_BILLING_INTERVAL_COUNT if recurring_interval == STRIPE_BILLING_INTERVAL else 1

    if price_id:
        return [_with_tax_rates({
            "price": price_id,
            "quantity": 1,
            "tax_behavior": "exclusive",
        })]
    if unit_amount:
        recurring: dict[str, int | str] = {"interval": recurring_interval}
        if recurring_interval_count > 1:
            recurring["interval_count"] = recurring_interval_count
        surcharge = _processing_fee_cents(unit_amount)
        total_unit_amount = unit_amount + surcharge
        return [_with_tax_rates({
            "price_data": {
                "currency": STRIPE_CURRENCY,
                "tax_behavior": "exclusive",
                "recurring": recurring,
                "product_data": {
                    "name": f"{STRIPE_PRODUCT_NAME_PREFIX} {plan_id.capitalize()} Plan",
                },
                "unit_amount": total_unit_amount,
            },
            "quantity": 1,
        })]
    raise HTTPException(status_code=500, detail=f"Plan {plan_id} non configuré pour Stripe")


async def _create_price_from_price_data(price_data: dict) -> str:
    if stripe:
        def _sync_create():
            return stripe.Price.create(**price_data)
        price_obj = await asyncio.to_thread(_sync_create)
    else:
        price_obj = await _stripe_api_request("POST", "/v1/prices", price_data)
    price_id = (price_obj or {}).get("id")
    if not price_id:
        raise HTTPException(status_code=500, detail="Stripe n'a pas renvoyé d'identifiant de prix")
    return price_id


async def _line_items_to_subscription_items(line_items: list[dict]) -> list[dict]:
    items: list[dict] = []
    for entry in line_items:
        base_item = {
            "quantity": entry.get("quantity", 1) or 1,
        }
        if "price" in entry:
            base_item["price"] = entry["price"]
        elif "price_data" in entry:
            price_id = await _create_price_from_price_data(entry["price_data"])
            base_item["price"] = price_id
        else:
            raise HTTPException(status_code=500, detail="Line item Stripe invalide pour un abonnement")
        if entry.get("tax_rates"):
            base_item["tax_rates"] = entry["tax_rates"]
        items.append(base_item)
    return items


async def _create_subscription_intent_with_httpx(
    customer_payload: dict,
    subscription_items: list[dict],
    metadata: dict,
    auto_tax_enabled: bool,
) -> tuple[dict, dict, dict, str]:
    customer = await _stripe_api_request("POST", "/v1/customers", customer_payload)
    if not isinstance(customer, dict):
        raise RuntimeError("Stripe n'a pas renvoyé le client créé")
    customer_id = customer.get("id")
    if not customer_id:
        raise RuntimeError("Stripe n'a pas retourné d'identifiant client")

    subscription_payload = {
        "customer": customer_id,
        "items": subscription_items,
        "collection_method": "charge_automatically",
        "payment_behavior": "default_incomplete",
        "automatic_tax": {"enabled": auto_tax_enabled},
        "payment_settings": {
            "payment_method_types": ["card"],
            "save_default_payment_method": "on_subscription",
        },
        "metadata": metadata,
        "expand": ["latest_invoice.payment_intent", "pending_setup_intent"],
    }
    if STRIPE_BILLING_ADDRESS_COLLECTION == "required" and auto_tax_enabled:
        subscription_payload["customer_update"] = {"address": "auto"}

    subscription = await _stripe_api_request("POST", "/v1/subscriptions", subscription_payload)
    if not isinstance(subscription, dict):
        raise RuntimeError("Stripe n'a pas renvoyé l'abonnement créé")
    latest_invoice = subscription.get("latest_invoice")
    if isinstance(latest_invoice, str):
        latest_invoice = await _stripe_api_request(
            "GET",
            f"/v1/invoices/{latest_invoice}",
                    {"expand": ["payment_intent"]},
                )

    payment_intent = None
    pending_setup_intent = subscription.get("pending_setup_intent")
    if isinstance(latest_invoice, dict):
        payment_intent = latest_invoice.get("payment_intent")

    subscription_id = subscription.get("id")
    invoice_id = latest_invoice.get("id") if isinstance(latest_invoice, dict) else None
    invoice_amount_due = None
    if isinstance(latest_invoice, dict):
        invoice_amount_due = (
            latest_invoice.get("amount_due")
            or latest_invoice.get("amount_remaining")
            or latest_invoice.get("total")
        )

    if subscription_id and not payment_intent:
        for attempt in range(5):
            try:
                refreshed = await _stripe_api_request(
                    "GET",
                    f"/v1/subscriptions/{subscription_id}",
                    {"expand": ["latest_invoice.payment_intent", "pending_setup_intent"]},
                )
                latest_invoice = refreshed.get("latest_invoice") or latest_invoice
                pending_setup_intent = refreshed.get("pending_setup_intent") or pending_setup_intent
                if isinstance(latest_invoice, dict):
                    payment_intent = latest_invoice.get("payment_intent")
                    invoice_id = latest_invoice.get("id") or invoice_id
                if payment_intent:
                    break
                await asyncio.sleep(1.0)
            except RuntimeError as exc:  # pragma: no cover - non bloquant
                logger.warning("Impossible de rafraîchir l'abonnement Stripe %s: %s", subscription_id, exc)
                break

    if invoice_id and not payment_intent:
        try:
            invoice_fetched = await _stripe_api_request(
                "GET",
                f"/v1/invoices/{invoice_id}",
                {"expand": ["payment_intent"]},
            )
            if isinstance(invoice_fetched, dict):
                latest_invoice = invoice_fetched
                payment_intent = invoice_fetched.get("payment_intent") or payment_intent
                invoice_amount_due = (
                    invoice_fetched.get("amount_due")
                    or invoice_fetched.get("amount_remaining")
                    or invoice_fetched.get("total")
                )
        except RuntimeError as exc:  # pragma: no cover - non bloquant
            logger.warning("Impossible de récupérer la facture Stripe %s: %s", invoice_id, exc)

    if invoice_id and not payment_intent and invoice_amount_due:
        try:
            payment_intent = await _stripe_api_request(
                "POST",
                "/v1/payment_intents",
                {
                    "amount": invoice_amount_due,
                    "currency": STRIPE_CURRENCY,
                    "customer": customer_id,
                    "payment_method_types": ["card"],
                    "setup_future_usage": "off_session",
                    "metadata": metadata,
                },
            )
            if payment_intent and payment_intent.get("id"):
                try:
                    await _stripe_api_request(
                        "POST",
                        f"/v1/invoices/{invoice_id}",
                        {"payment_intent": payment_intent["id"]},
                    )
                except RuntimeError as exc:
                    logger.warning("Impossible d'associer le PaymentIntent %s à la facture %s: %s", payment_intent["id"], invoice_id, exc)
        except RuntimeError as exc:
            logger.warning("Impossible de créer un PaymentIntent manuel pour la facture %s: %s", invoice_id, exc)

    if isinstance(payment_intent, str):
        payment_intent = await _stripe_api_request("GET", f"/v1/payment_intents/{payment_intent}")

    client_secret = payment_intent.get("client_secret") if isinstance(payment_intent, dict) else None
    if not client_secret:
        raise RuntimeError("Stripe n'a pas fourni de PaymentIntent valide pour l'abonnement créé")

    invoice_id = latest_invoice.get("id") if isinstance(latest_invoice, dict) else None
    if invoice_id:
        try:
            await _stripe_api_request("POST", f"/v1/invoices/{invoice_id}", {"metadata": metadata})
        except RuntimeError as exc:  # pragma: no cover - non bloquant
            logger.warning("Impossible de définir les métadonnées sur la facture %s: %s", invoice_id, exc)

    payment_intent_id = payment_intent.get("id") if isinstance(payment_intent, dict) else None
    if payment_intent_id:
        try:
            await _stripe_api_request("POST", f"/v1/payment_intents/{payment_intent_id}", {"metadata": metadata})
        except RuntimeError as exc:  # pragma: no cover - non bloquant
            logger.warning("Impossible de définir les métadonnées sur le PaymentIntent %s: %s", payment_intent_id, exc)

    return customer, subscription, latest_invoice, client_secret


def _flatten_payload(prefix: str, value) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, val in value.items():
            child_prefix = f"{prefix}[{key}]" if prefix else key
            items.extend(_flatten_payload(child_prefix, val))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child_prefix = f"{prefix}[{index}]"
            items.extend(_flatten_payload(child_prefix, item))
    elif value is not None:
        items.append((prefix, str(value)))
    return items


def _encode_stripe_payload(payload: dict | None) -> list[tuple[str, str]]:
    flattened: list[tuple[str, str]] = []
    if not payload:
        return flattened
    for key, val in payload.items():
        flattened.extend(_flatten_payload(key, val))
    return flattened


def _stripe_api_request_sync(method: str, path: str, payload: dict | None = None) -> dict:
    if not STRIPE_SECRET_KEY:
        raise RuntimeError("Stripe n'est pas configuré")
    url = f"https://api.stripe.com{path}"
    headers = {
        "Authorization": f"Bearer {STRIPE_SECRET_KEY}",
    }
    flattened = _encode_stripe_payload(payload)

    def _send() -> dict:
        try:
            if method.upper() == "GET":
                response = httpx.request(
                    method,
                    url,
                    params=flattened or None,
                    headers=headers,
                    timeout=30.0,
                )
            else:
                headers_with_ct = dict(headers)
                headers_with_ct["Content-Type"] = "application/x-www-form-urlencoded"
                encoded_body = urlencode(flattened)
                response = httpx.request(
                    method,
                    url,
                    data=encoded_body or None,
                    headers=headers_with_ct,
                    timeout=30.0,
                )
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Erreur réseau Stripe: {exc}") from exc

        if response.status_code >= 400:
            try:
                error_json = response.json()
                message = error_json.get("error", {}).get("message") or response.text
            except ValueError:
                message = response.text
            raise RuntimeError(f"Erreur Stripe ({response.status_code}): {message}")
        try:
            return response.json()
        except ValueError as exc:
            raise RuntimeError("Réponse Stripe invalide") from exc

    return _send()


async def _stripe_api_request(method: str, path: str, payload: dict | None = None) -> dict:
    try:
        return await asyncio.to_thread(_stripe_api_request_sync, method, path, payload)
    except RuntimeError:
        raise


async def _create_stripe_session_with_httpx(payload: dict) -> dict:
    url = "https://api.stripe.com/v1/checkout/session"
    headers = {
        "Authorization": f"Bearer {STRIPE_SECRET_KEY}",
    }
    flattened: list[tuple[str, str]] = []
    for key, val in payload.items():
        flattened.extend(_flatten_payload(key, val))

    # Stripe expects classic form-encoded payload
    form_encoded = urlencode(flattened)
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    def _send() -> dict:
        try:
            with httpx.Client(timeout=20.0) as client:
                response = client.post(url, content=form_encoded, headers=headers)
        except httpx.HTTPError as exc:  # pragma: no cover - network layer
            raise HTTPException(status_code=400, detail=f"Stripe: {exc}") from exc
        if response.status_code >= 400:
            try:
                error_payload = response.json()
                message = error_payload.get("error", {}).get("message") or response.text
            except ValueError:
                message = response.text
            raise HTTPException(status_code=400, detail=f"Stripe: {message}")
        try:
            return response.json()
        except ValueError as exc:
            raise HTTPException(status_code=500, detail=f"Réponse Stripe invalide: {exc}") from exc

    try:
        return await asyncio.to_thread(_send)
    except AttributeError:  # Python <3.9
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _send)


def _decimal_from_config(value):
    if value is None:
        return Decimal("0")
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def _normalize_payment_method_details(details: dict | None) -> tuple[str | None, dict]:
    if not isinstance(details, dict):
        return None, {}
    pm_type = details.get("type")
    if pm_type and isinstance(details.get(pm_type), dict):
        return pm_type, details.get(pm_type) or {}
    for candidate in ("card", "card_present", "klarna", "ach_debit", "us_bank_account", "link", "instant_bank", "cashapp", "crypto", "stablecoin"):
        candidate_payload = details.get(candidate)
        if isinstance(candidate_payload, dict):
            return candidate, candidate_payload
    first_key = next((key for key, value in details.items() if isinstance(value, dict)), None)
    if first_key:
        return first_key, details.get(first_key) or {}
    return pm_type, {}


def _determine_fee_rules(
    payment_type: str | None,
    payment_payload: dict,
    session_currency: str | None,
) -> dict:
    percent = Decimal("0")
    fixed = Decimal("0")
    cap: Decimal | None = None
    applied_keys: list[str] = []
    notes: list[str] = []

    def apply_rule(key: str):
        nonlocal percent, fixed, cap
        rule = STRIPE_FEE_RULES.get(key)
        if not rule:
            return
        applied_keys.append(key)
        note = rule.get("note")
        if note:
            notes.append(note)
        if "percent" in rule:
            percent += _decimal_from_config(rule.get("percent"))
        if "fixed" in rule:
            fixed += _decimal_from_config(rule.get("fixed"))
        if "extra_percent" in rule:
            percent += _decimal_from_config(rule.get("extra_percent"))
        if "extra_fixed" in rule:
            fixed += _decimal_from_config(rule.get("extra_fixed"))
        if "fixed_cap" in rule:
            rule_cap = _decimal_from_config(rule.get("fixed_cap"))
            cap = rule_cap if cap is None else min(cap, rule_cap)

    normalized_currency = (session_currency or STRIPE_CURRENCY or "").lower()
    normalized_payment_type = (payment_type or "").lower()

    if normalized_payment_type in {"klarna"}:
        apply_rule("klarna")
    elif normalized_payment_type in {"ach_debit", "us_bank_account"}:
        apply_rule("ach_debit")
    elif normalized_payment_type in {"link", "instant_bank"}:
        apply_rule("instant_bank")
    elif normalized_payment_type in {"crypto", "stablecoin"}:
        apply_rule("stablecoin")
    else:
        apply_rule("domestic_card")
        card_country = (payment_payload.get("country") or "").upper()
        entry_mode = (payment_payload.get("entry_mode") or "").lower()
        if card_country and STRIPE_ACCOUNT_COUNTRY and card_country != STRIPE_ACCOUNT_COUNTRY:
            apply_rule("international_card")
        if entry_mode in {"keyed", "manual"}:
            apply_rule("manual_entry")

    if normalized_currency and normalized_currency != (STRIPE_CURRENCY or "").lower():
        apply_rule("currency_conversion")

    return {
        "percent": percent,
        "fixed": fixed,
        "fixed_cap": cap,
        "applied_keys": applied_keys,
        "notes": " + ".join(notes),
    }


def _estimate_fee_amount_cents(amount_cents: int, percent: Decimal, fixed: Decimal, cap: Decimal | None = None) -> int:
    if amount_cents <= 0:
        return 0
    amount_dec = Decimal(amount_cents) / Decimal("100")
    fee_dec = (amount_dec * percent / Decimal("100")) + fixed
    if cap is not None:
        fee_dec = min(fee_dec, cap)
    return int((fee_dec * Decimal("100")).to_integral_value(rounding=ROUND_HALF_UP))


def _format_decimal(value: Decimal) -> str:
    normalized = value.quantize(Decimal("0.01")).normalize()
    as_str = format(normalized, "f")
    if "." in as_str:
        as_str = as_str.rstrip("0").rstrip(".")
    return as_str or "0"


def _format_fee_label(percent: Decimal, fixed: Decimal, currency: str | None, notes: str | None) -> str:
    parts: list[str] = []
    if percent > 0:
        parts.append(f"{_format_decimal(percent)}%")
    if fixed > 0:
        curr = (currency or STRIPE_CURRENCY or "eur").upper()
        parts.append(f"+ {_format_decimal(fixed)} {curr}")
    label = " ".join(parts).strip()
    if notes:
        return f"{label} ({notes})" if label else notes
    return label or "0"


def _retrieve_payment_intent_snapshot(payment_intent_id: str | None) -> tuple[dict | None, dict | None, dict | None]:
    if not stripe or not payment_intent_id:
        return None, None, None
    try:
        intent = stripe.PaymentIntent.retrieve(
            payment_intent_id,
            expand=[
                "latest_charge.balance_transaction",
                "latest_charge.payment_method_details",
            ],
        )
    except Exception as exc:  # pragma: no cover - Stripe SDK failure
        logger.warning("Impossible de récupérer le PaymentIntent %s: %s", payment_intent_id, exc)
        return None, None, None

    charge = intent.get("latest_charge")
    if isinstance(charge, str):
        try:
            charge = stripe.Charge.retrieve(
                charge,
                expand=["balance_transaction", "payment_method_details", "payment_method"],
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("Impossible de récupérer la charge Stripe %s: %s", charge, exc)
            charge = None
    elif charge is None:
        charges = intent.get("charges", {}).get("data") or []
        if charges:
            charge = charges[-1]

    balance_tx = None
    if isinstance(charge, dict):
        balance_tx_obj = charge.get("balance_transaction")
        if isinstance(balance_tx_obj, dict):
            balance_tx = balance_tx_obj
        elif isinstance(balance_tx_obj, str):
            try:
                balance_tx = stripe.BalanceTransaction.retrieve(balance_tx_obj)
            except Exception as exc:  # pragma: no cover
                logger.warning("Impossible de récupérer la balance transaction %s: %s", balance_tx_obj, exc)
                balance_tx = None
    return intent, charge, balance_tx


def _collect_payment_summary(session: dict) -> dict:
    amount_total_cents = int(session.get("amount_total") or 0)
    amount_subtotal_cents = int(session.get("amount_subtotal") or 0)
    currency = (session.get("currency") or STRIPE_CURRENCY or "").lower()
    payment_intent_id = session.get("payment_intent")
    _, charge, balance_tx = _retrieve_payment_intent_snapshot(payment_intent_id)
    payment_details = (charge or {}).get("payment_method_details") or {}
    payment_method_type, method_payload = _normalize_payment_method_details(payment_details)

    fee_rules = _determine_fee_rules(payment_method_type, method_payload, currency)
    estimated_fee_cents = _estimate_fee_amount_cents(
        amount_total_cents,
        fee_rules["percent"],
        fee_rules["fixed"],
        fee_rules.get("fixed_cap"),
    )
    actual_fee_cents = balance_tx.get("fee") if isinstance(balance_tx, dict) else None
    actual_net_cents = balance_tx.get("net") if isinstance(balance_tx, dict) else None
    fee_label = _format_fee_label(fee_rules["percent"], fee_rules["fixed"], currency, fee_rules.get("notes"))

    card_payload = method_payload if (payment_method_type or "").startswith("card") else {}

    return {
        "payment_intent_id": payment_intent_id,
        "charge_id": (charge or {}).get("id"),
        "balance_transaction_id": (balance_tx or {}).get("id"),
        "amount_total_cents": amount_total_cents,
        "amount_subtotal_cents": amount_subtotal_cents,
        "currency": currency,
        "payment_method_type": payment_method_type,
        "card_brand": card_payload.get("brand"),
        "card_country": card_payload.get("country"),
        "card_funding": card_payload.get("funding"),
        "card_network": card_payload.get("network"),
        "card_last4": card_payload.get("last4"),
        "card_entry_mode": card_payload.get("entry_mode"),
        "estimated_fee_cents": estimated_fee_cents,
        "estimated_net_cents": amount_total_cents - estimated_fee_cents if amount_total_cents else 0,
        "actual_fee_cents": actual_fee_cents,
        "actual_net_cents": actual_net_cents,
        "fee_label": fee_label,
        "fee_notes": fee_rules.get("notes"),
        "applied_fee_keys": fee_rules.get("applied_keys") or [],
        "percent_applied": str(fee_rules["percent"]),
        "fixed_applied": str(fee_rules["fixed"]),
        "balance_currency": (balance_tx or {}).get("currency"),
    }


def _extract_bearer_token(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    if header_value.lower().startswith("bearer "):
        return header_value.split(" ", 1)[1].strip()
    return None


def _normalize_origin(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}".rstrip('/')
    return value.rstrip('/')


def _public_app_base_url() -> str:
    base = (
        os.environ.get("NEXT_PUBLIC_SITE_URL")
        or os.environ.get("NEXT_PUBLIC_APP_URL")
        or os.environ.get("APP_BASE_URL")
        or "https://cyberscan.fr"
    )
    return base.rstrip('/')


def _build_frontend_url(path: str) -> str:
    base = _public_app_base_url()
    normalized = path or ""
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return f"{base}{normalized}"

def _send_smtp_email(
    subject: str,
    recipient: str,
    html_body: str,
    text_body: str | None = None,
    attachments: list[dict[str, str | bytes]] | None = None,
):
    
    if not SMTP_HOST or not SMTP_SENDER_EMAIL:
        raise RuntimeError("SMTP server is not configured on the backend")

    import ssl
    context = ssl.create_default_context()

    # Construction du message
    message = EmailMessage()
    message["Subject"] = subject
    sender_name = (SMTP_SENDER_NAME or "CyberScan").strip() or "CyberScan"
    message["From"] = formataddr((sender_name, SMTP_SENDER_EMAIL))
    message["To"] = recipient
    support_copy = SUPPORT_ALERT_EMAIL
    if support_copy and support_copy.lower() != recipient.lower():
        message["Cc"] = support_copy
    if text_body:
        message.set_content(text_body)
    else:
        message.set_content("Consultez la version HTML de cet email.")
    message.add_alternative(html_body, subtype="html")

    for attachment in attachments or []:
        content = attachment.get("content")
        if content is None:
            continue
        filename = attachment.get("filename") or "rapport.pdf"
        content_type = attachment.get("content_type") or "application/octet-stream"
        maintype, subtype = content_type.split("/", 1) if "/" in content_type else ("application", "octet-stream")
        if isinstance(content, str):
            content = content.encode("utf-8")
        message.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)

    try:
        # --- Cas 1 : port 465 (SSL direct)
        if int(SMTP_PORT) == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT) as server:
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD or "")
                server.send_message(message)

        # --- Cas 2 : port 587 (STARTTLS)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
                if SMTP_USE_TLS:
                    server.starttls(context=context)
                if SMTP_USERNAME:
                    server.login(SMTP_USERNAME, SMTP_PASSWORD or "")
                server.send_message(message)

    except smtplib.SMTPAuthenticationError as exc:
        raise RuntimeError(f"Erreur d'authentification SMTP : {exc}") from exc
    except smtplib.SMTPConnectError as exc:
        raise RuntimeError(f"Impossible de se connecter au serveur SMTP : {exc}") from exc
    except smtplib.SMTPException as exc:
        raise RuntimeError(f"Erreur SMTP : {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Impossible d'envoyer l'email : {exc}") from exc


def _enforce_request_origin(request: Request):
    origin_header = request.headers.get('origin') or request.headers.get('referer')
    origin = _normalize_origin(origin_header)
    if origin and origin not in ALLOWED_WEB_ORIGINS:
        raise HTTPException(status_code=403, detail="Origine de la requête non autorisée")


async def _fetch_supabase_user(access_token: str) -> dict:
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise HTTPException(status_code=500, detail="Supabase auth non configuré sur le serveur")

    url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/user"
    headers = {
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": f"Bearer {access_token}",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Supabase auth indisponible: {exc}") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=401, detail="Session Supabase invalide")

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=f"Réponse Supabase invalide: {exc}") from exc

    if isinstance(payload, dict) and payload.get("id"):
        return payload
    if isinstance(payload, dict) and payload.get("user"):
        user_payload = payload.get("user")
        if isinstance(user_payload, dict) and user_payload.get("id"):
            return user_payload
    raise HTTPException(status_code=401, detail="Impossible de valider l'utilisateur Supabase")


async def _fetch_profile(user_id: str | None) -> dict | None:
    if not user_id:
        return None
    return await _supabase_fetch_first("profiles", {"id": user_id})


async def _require_admin_user(request: Request) -> dict:
    session_user = await _require_user_session(request)
    profile = await _fetch_profile(session_user.get("id"))
    if not profile or profile.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return session_user


async def _require_user_session(request: Request) -> dict:
    token = _extract_bearer_token(request.headers.get('authorization'))
    if not token:
        token = request.cookies.get('sb-access-token')
    if not token:
        raise HTTPException(status_code=401, detail="Authentification requise")
    return await _fetch_supabase_user(token)


def _require_csrf_token(request: Request):
    header_token = request.headers.get('x-csrf-token')
    cookie_token = request.cookies.get('csrf-token')
    if not header_token or not cookie_token or header_token != cookie_token:
        raise HTTPException(status_code=403, detail="CSRF token manquant ou invalide")


def _construct_event_without_sdk(payload: bytes, sig_header: str, secret: str) -> dict:
    if not secret:
        raise ValueError("Stripe webhook secret non configuré")

    if not sig_header:
        raise ValueError("En-tête Stripe-Signature manquant")

    parts = sig_header.split(",")
    timestamp = None
    signatures: list[str] = []
    for part in parts:
        key, _, value = part.partition("=")
        if key == "t":
            timestamp = value
        elif key.startswith("v"):
            signatures.append(value)

    if not timestamp or not signatures:
        raise ValueError("En-tête Stripe-Signature invalide")

    try:
        timestamp_int = int(timestamp)
    except ValueError as exc:
        raise ValueError("Horodatage Stripe invalide") from exc

    current_time = int(time.time())
    if abs(current_time - timestamp_int) > STRIPE_WEBHOOK_TOLERANCE:
        raise ValueError("Horodatage Stripe hors tolérance")

    payload_text = payload.decode("utf-8")
    signed_payload = f"{timestamp}.{payload_text}".encode("utf-8")
    computed = hmac.new(
        secret.encode("utf-8"),
        msg=signed_payload,
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not any(hmac.compare_digest(computed, signature) for signature in signatures):
        raise ValueError("Signature Stripe invalide")

    try:
        return json.loads(payload_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Charge utile Stripe invalide: {exc}") from exc


def _construct_stripe_event(payload: bytes, sig_header: str) -> dict:
    if not STRIPE_WEBHOOK_SECRETS:
        raise HTTPException(status_code=500, detail="Stripe webhook non configuré sur le serveur")

    payload_text = payload.decode("utf-8")
    if stripe:
        last_sdk_error: Exception | None = None
        for secret in STRIPE_WEBHOOK_SECRETS:
            try:
                return stripe.Webhook.construct_event(payload, sig_header, secret)
            except AttributeError:
                last_sdk_error = None
                break
            except Exception as exc:
                last_sdk_error = exc
                continue
        if last_sdk_error is not None:
            logger.warning("Stripe SDK a rejeté la signature: %s", last_sdk_error)
            raise HTTPException(status_code=400, detail=f"Signature Stripe invalide: {last_sdk_error}") from last_sdk_error

    last_manual_error: Exception | None = None
    for secret in STRIPE_WEBHOOK_SECRETS:
        try:
            return _construct_event_without_sdk(payload, sig_header, secret)
        except ValueError as exc:
            last_manual_error = exc
            continue

    raise HTTPException(status_code=400, detail=f"Signature Stripe invalide: {last_manual_error}") from last_manual_error


def _supabase_headers() -> dict[str, str]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase n'est pas configuré sur le serveur")
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }


async def _supabase_request(method: str, endpoint: str, *, params: dict | None = None, json_payload: dict | None = None):
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase n'est pas configuré sur le serveur")

    url = f"{SUPABASE_URL.rstrip('/')}/{endpoint.lstrip('/')}"
    headers = _supabase_headers()

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.request(method, url, params=params, json=json_payload, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Supabase indisponible: {exc}") from exc

    if response.status_code >= 400:
        try:
            error_payload = response.json()
            message = error_payload.get("message") or error_payload
        except ValueError:
            message = response.text
        raise HTTPException(status_code=500, detail=f"Erreur Supabase ({response.status_code}): {message}")

    if response.content:
        try:
            return response.json()
        except ValueError:
            return None
    return None


_PROFILE_NAME_STRIP_RE = re.compile(r"[^A-Za-z0-9 ._'\-]")
_PROFILE_NAME_SUSPICIOUS_RE = re.compile(r"(<|>|script|alert|onerror|onload|select|insert|update|delete|drop|union|sleep|--|;|/\*|\*/)", re.IGNORECASE)


def _sanitize_profile_name(value: str | None) -> tuple[str | None, bool]:
    if not value:
        return None, False
    trimmed = value.strip()
    if not trimmed:
        return None, False
    collapsed = re.sub(r"\s+", " ", trimmed)
    suspicious = bool(_PROFILE_NAME_SUSPICIOUS_RE.search(trimmed))
    sanitized = _PROFILE_NAME_STRIP_RE.sub("", collapsed)[:64]
    return (sanitized or None), suspicious


async def _ensure_profile_exists(user_id: str, *, email: str | None = None, full_name: str | None = None) -> bool:
    """
    Guarantee that the given user_id has a corresponding row in the profiles table.
    Prevents FK errors when other tables (invoices, refunds) try to reference users that
    may have been deleted or never bootstrapped correctly.
    """
    if not user_id:
        return False

    params = {
        "select": "id",
        "id": f"eq.{user_id}",
        "limit": 1,
    }
    try:
        existing = await _supabase_request("GET", "rest/v1/profiles", params=params)
    except HTTPException as exc:
        logger.warning("Impossible de vérifier le profil %s: %s", user_id, exc.detail)
        return False

    if existing:
        return True

    now_iso = datetime.now(timezone.utc).isoformat()
    fallback_name = full_name or email or f"CyberScan client {user_id[:8]}"
    sanitized_name, suspicious = _sanitize_profile_name(fallback_name)
    final_name = sanitized_name or fallback_name

    if suspicious:
        logger.warning(
            "Profil Supabase: nom suspect détecté pour user=%s (input tronqué=%s)",
            user_id,
            (fallback_name or "")[:80],
        )
    elif sanitized_name and sanitized_name != fallback_name:
        logger.info(
            "Profil Supabase: nom nettoyé user=%s (%s → %s)",
            user_id,
            (fallback_name or "")[:80],
            sanitized_name,
        )

    payload = {
        "id": user_id,
        "full_name": final_name,
        "email": email,
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    try:
        await _supabase_request("POST", "rest/v1/profiles", json_payload=payload)
        logger.info("Profil Supabase recréé automatiquement pour user=%s", user_id)
        return True
    except HTTPException as exc:
        logger.error("Impossible de créer un profil pour user %s: %s", user_id, exc.detail)
        return False


async def _generate_supabase_recovery_link(email: str, redirect_url: str) -> str:
    payload = {
        "type": "recovery",
        "email": email,
        "redirect_to": redirect_url,
    }
    data = await _supabase_request("POST", "auth/v1/admin/generate_link", json_payload=payload)
    if isinstance(data, dict):
        action_link = data.get("action_link")
        if not action_link:
            properties = data.get("properties") or {}
            action_link = properties.get("action_link")
        if action_link:
            return action_link
    raise HTTPException(status_code=500, detail="Supabase n'a pas retourné de lien de réinitialisation")


async def _supabase_fetch_first(table: str, filters: dict[str, str]) -> dict | None:
    params = {key: f"eq.{value}" for key, value in filters.items()}
    params.update({"select": "*", "limit": 1})
    data = await _supabase_request("GET", f"rest/v1/{table}", params=params)
    if isinstance(data, list) and data:
        return data[0]
    return None


async def _resolve_user_id_from_email(email: str | None) -> str | None:
    if not email:
        return None
    normalized = email.strip().lower()
    if not normalized:
        return None
    try:
        profile = await _supabase_fetch_first("profiles", {"email": normalized})
    except HTTPException as exc:
        logger.warning(
            "Impossible de résoudre l'utilisateur via email %s: %s",
            normalized,
            exc.detail,
        )
        return None
    profile_id = profile.get("id") if isinstance(profile, dict) else None
    if profile_id:
        return str(profile_id)
    return None


def _is_uuid(value: str | None) -> bool:
    if not value:
        return False
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError):
        return False


def _extract_missing_column(error_message: str | None) -> str | None:
    if not error_message:
        return None
    match = re.search(r"'([^']+)' column", error_message)
    if match:
        return match.group(1)
    return None

async def _fetch_invoice_record(
    invoice_id: str | None = None,
    user_id: str | None = None,
    payment_intent_id: str | None = None,
    status: str | None = None,
    checkout_session_id: str | None = None,
):
    """
    Version améliorée :
    - détecte automatiquement si l’ID est un invoice_id Stripe (in_...)
      ou un UUID local Supabase.
    - effectue une seconde recherche automatiquement si la première ne donne rien.
    """

    if not invoice_id and not user_id and not payment_intent_id and not checkout_session_id:
        return None

    params = ["select=*","limit=1"]

    # ---------------------------
    # 1️⃣ Si invoice_id fourni
    # ---------------------------
    if invoice_id:
        # On détecte si c'est un ID Stripe
        is_stripe_id = invoice_id.startswith("in_")

        if is_stripe_id:
            # Recherche sur invoice_id (Stripe)
            url = f"rest/v1/invoices?invoice_id=eq.{invoice_id}"
            if user_id:
                url += f"&user_id=eq.{user_id}"
            if status:
                url += f"&payment_status=eq.{status}"
            url += "&" + "&".join(params)

            data = await _supabase_request("GET", url)
            if data:
                return data[0]

        else:
            # C'est un UUID → on cherche d’abord dans id (clé primaire)
            url = f"rest/v1/invoices?id=eq.{invoice_id}"
            if user_id:
                url += f"&user_id=eq.{user_id}"
            if status:
                url += f"&payment_status=eq.{status}"
            url += "&" + "&".join(params)

            data = await _supabase_request("GET", url)
            if data:
                return data[0]

            # 🔄 fallback : essayer dans invoice_id Stripe
            url = f"rest/v1/invoices?invoice_id=eq.{invoice_id}"
            if user_id:
                url += f"&user_id=eq.{user_id}"
            url += "&" + "&".join(params)

            data = await _supabase_request("GET", url)
            if data:
                return data[0]

    # ---------------------------
    # 2️⃣ Recherche par payment_intent (si disponible)
    # ---------------------------
    if payment_intent_id:
        base_filters = ""
        if user_id:
            base_filters += f"&user_id=eq.{user_id}"
        if status:
            base_filters += f"&payment_status=eq.{status}"

        payment_endpoints = [
            f"rest/v1/invoices?stripe_payment_intent_id=eq.{payment_intent_id}",
            f"rest/v1/invoices?stripe_charge_id=eq.{payment_intent_id}",
        ]

        for endpoint in payment_endpoints:
            url = endpoint
            if base_filters:
                url += base_filters
            url += "&" + "&".join(params)
            data = await _supabase_request("GET", url)
            if data:
                return data[0]

    # ---------------------------
    # 3️⃣ Recherche par session Checkout
    # ---------------------------
    if checkout_session_id:
        url = f"rest/v1/invoices?stripe_checkout_session_id=eq.{checkout_session_id}"
        if user_id:
            url += f"&user_id=eq.{user_id}"
        if status:
            url += f"&payment_status=eq.{status}"
        url += "&" + "&".join(params)
        data = await _supabase_request("GET", url)
        if data:
            return data[0]

    # ---------------------------
    # 4️⃣ Recherche par user_id (si aucun identifiant direct)
    # ---------------------------
    if user_id:
        url = f"rest/v1/invoices?user_id=eq.{user_id}"
        if status:
            url += f"&payment_status=eq.{status}"
        url += "&order=created_at.desc&limit=1"

        data = await _supabase_request("GET", url)
        if data:
            return data[0]

    return None


async def _fetch_refund_request(request_id: str) -> dict | None:
    if not request_id:
        return None
    return await _supabase_fetch_first("refund_requests", {"id": request_id})

async def _fetch_subscription_record(subscription_id: str) -> dict | None:
    """
    Récupère une subscription locale (Supabase) à partir du stripe subscription_id
    """
    if not subscription_id:
        return None

    try:
        return await _supabase_fetch_first(
            "subscriptions",
            {"stripe_subscription_id": subscription_id},
        )
    except HTTPException as exc:
        logger.warning(
            "Erreur récupération subscription %s: %s",
            subscription_id,
            exc.detail,
        )
        return None

async def _update_invoice_record(invoice_id: str | None, payload: dict | None):
    if not SUPABASE_INVOICES_TABLE or not invoice_id or not payload:
        return

    target_id = invoice_id
    if not _is_uuid(target_id):
        existing = await _fetch_invoice_record(invoice_id=invoice_id)
        if not existing:
            logger.warning(
                "Impossible de mettre à jour la facture %s : aucune entrée locale trouvée",
                invoice_id,
            )
            return
        target_id = existing.get("id")
        if not target_id:
            logger.warning(
                "Impossible de mettre à jour la facture %s : identifiant Supabase introuvable",
                invoice_id,
            )
            return

    filtered_payload = dict(payload)
    while filtered_payload:
        try:
            await _supabase_request(
                "PATCH",
                f"rest/v1/{SUPABASE_INVOICES_TABLE}",
                params={"id": f"eq.{target_id}"},
                json_payload=filtered_payload,
            )
            return
        except HTTPException as exc:  # pragma: no cover - diagnostic only
            column = _extract_missing_column(exc.detail)
            if column and column in filtered_payload:
                logger.warning(
                    "Colonne Supabase manquante (%s) ignorée pour la facture %s",
                    column,
                    target_id,
                )
                filtered_payload.pop(column, None)
                continue
            logger.warning("Impossible de mettre à jour la facture %s: %s", target_id, exc.detail)
            return


async def _upsert_supabase_record(table: str, user_id: str, payload: dict, *, insert_extras: dict | None = None):
    existing = await _supabase_fetch_first(table, {"user_id": user_id})
    if existing:
        await _supabase_request(
            "PATCH",
            f"rest/v1/{table}",
            params={"user_id": f"eq.{user_id}"},
            json_payload=payload,
        )
        logger.info("Supabase %s mis à jour pour user %s", table, user_id)
    else:
        body = {"user_id": user_id, **payload}
        if insert_extras:
            body.update(insert_extras)
        await _supabase_request("POST", f"rest/v1/{table}", json_payload=body)
        logger.info("Supabase %s créé pour user %s", table, user_id)


async def _reset_subscription_after_refund(user_id: str):
    if not user_id:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    subscription_payload = {
        "plan_type": "free",
        "status": "cancelled",
        "credits_limit": FREE_PLAN_CREDITS,
        "expires_at": None,
        "updated_at": now_iso,
    }
    credits_payload = {
        "total_credits": FREE_PLAN_CREDITS,
        "used_credits": 0,
        "last_reset_at": now_iso,
        "updated_at": now_iso,
    }
    try:
        await _supabase_request(
            "PATCH",
            "rest/v1/subscriptions",
            params={"user_id": f"eq.{user_id}"},
            json_payload=subscription_payload,
        )
        logger.info("Subscription reset after refund for user %s", user_id)
    except HTTPException as exc:
        logger.warning("Impossible de réinitialiser l'abonnement pour user %s: %s", user_id, exc.detail)
    try:
        await _supabase_request(
            "PATCH",
            "rest/v1/credits",
            params={"user_id": f"eq.{user_id}"},
            json_payload=credits_payload,
        )
        logger.info("Credits reset after refund for user %s", user_id)
    except HTTPException as exc:
        logger.warning("Impossible de réinitialiser les crédits pour user %s: %s", user_id, exc.detail)


async def _insert_invoice_row(payload: dict, *, on_conflict: str | None = None) -> bool:
    if not SUPABASE_INVOICES_TABLE:
        return False
    filtered_payload = dict(payload)
    while filtered_payload:
        try:
            params = {"on_conflict": on_conflict} if on_conflict else None
            await _supabase_request(
                "POST",
                f"rest/v1/{SUPABASE_INVOICES_TABLE}",
                json_payload=filtered_payload,
                params=params,
            )
            return True
        except HTTPException as exc:
            column = _extract_missing_column(exc.detail)
            if column and column in filtered_payload:
                logger.warning(
                    "Colonne Supabase manquante (%s) ignorée lors de l'insertion facture",
                    column,
                )
                filtered_payload.pop(column, None)
                continue
            logger.warning("Insertion facture impossible: %s", exc.detail)
            return False
    logger.warning("Insertion facture annulée: aucun champ valide après filtrage")
    return False
async def _record_invoice_entry(user_id: str, plan_id: str, session: dict, email: str | None = None):
    if not SUPABASE_INVOICES_TABLE:
        return None

    session_snapshot = dict(session)
    try:
        try:
            payment_summary = await asyncio.to_thread(_collect_payment_summary, session_snapshot)
        except AttributeError:  # pragma: no cover - Python <3.9
            loop = asyncio.get_running_loop()
            payment_summary = await loop.run_in_executor(None, _collect_payment_summary, session_snapshot)
    except Exception as exc:  # pragma: no cover - diagnostic only
        logger.warning("Impossible de calculer les frais Stripe pour l'utilisateur %s : %s", user_id, exc)
        return

    if not payment_summary:
        return

    total_details = session.get("total_details") or {}
    tax_amount_cents = total_details.get("amount_tax")
    discount = (session.get("discounts") or []) or []
    coupon_id = None
    if discount:
        coupon = (discount[0] or {}).get("coupon")
        if isinstance(coupon, dict):
            coupon_id = coupon.get("id")

    invoice_payload = {
        "user_id": user_id,
        "plan_type": plan_id,
        "customer_email": email or session.get("customer_email"),
        "stripe_checkout_session_id": session.get("id"),
        "invoice_id": session.get("invoice"),
        "stripe_customer_id": session.get("customer"),
        "payment_status": session.get("payment_status"),
        "currency": (payment_summary.get("currency") or STRIPE_CURRENCY or "eur").upper(),
        "amount_total_cents": payment_summary.get("amount_total_cents"),
        "amount_subtotal_cents": payment_summary.get("amount_subtotal_cents"),
        "tax_amount_cents": tax_amount_cents,
        "coupon_id": coupon_id,
        "stripe_payment_intent_id": payment_summary.get("payment_intent_id"),
        "stripe_charge_id": payment_summary.get("charge_id"),
        "stripe_balance_transaction_id": payment_summary.get("balance_transaction_id"),
        "payment_method_type": payment_summary.get("payment_method_type"),
        "card_brand": payment_summary.get("card_brand"),
        "card_country": payment_summary.get("card_country"),
        "card_funding": payment_summary.get("card_funding"),
        "card_network": payment_summary.get("card_network"),
        "card_last4": payment_summary.get("card_last4"),
        "card_entry_mode": payment_summary.get("card_entry_mode"),
        "stripe_fee_percent": payment_summary.get("percent_applied"),
        "stripe_fee_fixed": payment_summary.get("fixed_applied"),
        "stripe_fee_label": payment_summary.get("fee_label"),
        "stripe_fee_notes": payment_summary.get("fee_notes"),
        "stripe_fee_keys": ",".join(payment_summary.get("applied_fee_keys") or []),
        "stripe_fee_estimated_cents": payment_summary.get("estimated_fee_cents"),
        "net_amount_estimated_cents": payment_summary.get("estimated_net_cents"),
        "stripe_fee_actual_cents": payment_summary.get("actual_fee_cents"),
        "net_amount_actual_cents": payment_summary.get("actual_net_cents"),
        "balance_currency": payment_summary.get("balance_currency"),
        "hosted_invoice_url": session.get("hosted_invoice_url"),
        "invoice_pdf_url": session.get("invoice_pdf"),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        existing_invoice = None
        primary_invoice_id = session.get("invoice")
        payment_intent_id = payment_summary.get("payment_intent_id")

        if primary_invoice_id:
            existing_invoice = await _fetch_invoice_record(invoice_id=primary_invoice_id, user_id=user_id)
        if not existing_invoice and payment_intent_id:
            existing_invoice = await _fetch_invoice_record(payment_intent_id=payment_intent_id, user_id=user_id)
        if not existing_invoice:
            existing_invoice = await _fetch_invoice_record(
                checkout_session_id=session.get("id"),
                user_id=user_id,
            )

        if existing_invoice:
            await _update_invoice_record(existing_invoice["id"], invoice_payload)
            logger.info(
                "Facture Supabase mise à jour user=%s plan=%s montant=%s",
                user_id,
                plan_id,
                invoice_payload.get("amount_total_cents"),
            )
        else:
            created = await _insert_invoice_row(invoice_payload)
            if created:
                logger.info(
                    "Facture Supabase enregistrée user=%s plan=%s montant=%s",
                    user_id,
                    plan_id,
                    invoice_payload.get("amount_total_cents"),
                )
            else:
                logger.warning(
                    "Enregistrement de la facture impossible pour l'utilisateur %s: payload filtré/erreur",
                    user_id,
                )
    except HTTPException as exc:
        logger.warning("Enregistrement de la facture impossible pour l'utilisateur %s: %s", user_id, exc.detail)
    return payment_summary

async def _record_invoice_entry_fallback(
    invoice: dict,
    payment_intent_id: str | None = None,
    charge: str | None = None,
):
    invoice_data = dict(invoice or {})
    invoice_id = invoice_data.get("id")

    # --------------------------------------------------
    # Stripe raw fields
    # --------------------------------------------------
    payment_intent = payment_intent_id or invoice_data.get("payment_intent")
    charge_id = charge or invoice_data.get("charge")
    stripe_customer_id = invoice_data.get("customer")
    subscription_id = invoice_data.get("subscription")

    customer_email = (
        invoice_data.get("customer_email")
        or invoice_data.get("receipt_email")
    )

    metadata = dict(invoice_data.get("metadata") or {})
    plan_id = metadata.get("planId")

    # --------------------------------------------------
    # 🟩 USER_ID RESOLUTION (CRITICAL)
    # --------------------------------------------------
    user_id = None

    # 1️⃣ metadata.userId (source forte)
    meta_user_id = metadata.get("userId")
    if meta_user_id:
        meta_user_id = str(meta_user_id).strip()
        if _is_uuid(meta_user_id):
            user_id = meta_user_id
        else:
            logger.warning(
                "Invoice %s metadata.userId invalide: %s",
                invoice_id or "unknown",
                meta_user_id,
            )

    # 2️⃣ subscription.user_id (OBLIGATOIRE)
    if not user_id and subscription_id:
        try:
            sub = await _fetch_subscription_record(subscription_id=subscription_id)
            if sub and sub.get("user_id") and _is_uuid(sub["user_id"]):
                user_id = sub["user_id"]
                logger.info(
                    "Invoice %s héritée du user %s via subscription %s",
                    invoice_id or "unknown",
                    user_id,
                    subscription_id,
                )
        except Exception as exc:
            logger.warning(
                "Impossible de résoudre user_id via subscription %s: %s",
                subscription_id,
                exc,
            )

    # 3️⃣ Stripe customer.metadata.userId
    if not user_id and stripe_customer_id:
        try:
            if stripe:
                customer = stripe.Customer.retrieve(stripe_customer_id)
            else:
                customer = await _stripe_api_request(
                    "GET", f"/v1/customers/{stripe_customer_id}"
                )

            if isinstance(customer, dict):
                cust_user_id = customer.get("metadata", {}).get("userId")
                if cust_user_id and _is_uuid(cust_user_id):
                    user_id = cust_user_id
                    logger.info(
                        "Invoice %s héritée du user %s via customer metadata",
                        invoice_id or "unknown",
                        user_id,
                    )
        except Exception as exc:
            logger.warning(
                "Impossible de résoudre user_id via customer %s: %s",
                stripe_customer_id,
                exc,
            )

    # 4️⃣ Email → profiles (dernier recours)
    if not user_id and customer_email:
        resolved_user_id = await _resolve_user_id_from_email(customer_email)
        if resolved_user_id and _is_uuid(resolved_user_id):
            user_id = resolved_user_id
            logger.info(
                "Invoice %s rattachée au user %s via email (fallback final)",
                invoice_id or "unknown",
                user_id,
            )

    # --------------------------------------------------
    # Amounts / currency
    # --------------------------------------------------
    amount_total_cents = (
        invoice_data.get("amount_paid")
        or invoice_data.get("amount_due")
        or invoice_data.get("total")
        or 0
    )
    amount_subtotal_cents = (
        invoice_data.get("subtotal")
        or invoice_data.get("amount_subtotal")
    )
    tax_amount_cents = (
        invoice_data.get("tax")
        or invoice_data.get("tax_amount")
    )

    currency = (
        invoice_data.get("currency")
        or STRIPE_CURRENCY
        or "eur"
    ).upper()

    # --------------------------------------------------
    # Normalize Stripe IDs
    # --------------------------------------------------
    def _normalize_id(value):
        if isinstance(value, dict):
            return value.get("id")
        return value

    payment_intent = _normalize_id(payment_intent)
    charge_id = _normalize_id(charge_id)

    # --------------------------------------------------
    # 🟦 Stripe enrichment (PI + latest_charge)
    # --------------------------------------------------
    if invoice_id and (not payment_intent or not charge_id):
        try:
            logger.info(
                "Invoice %s → enrichissement Stripe (fallback)",
                invoice_id,
            )

            if stripe:
                refreshed = stripe.Invoice.retrieve(
                    invoice_id,
                    expand=[
                        "payment_intent",
                        "payment_intent.latest_charge",
                    ],
                )
            else:
                refreshed = await _stripe_api_request(
                    "GET",
                    f"/v1/invoices/{invoice_id}",
                    params={
                        "expand[]": [
                            "payment_intent",
                            "payment_intent.latest_charge",
                        ]
                    },
                )

            if isinstance(refreshed, dict):
                invoice_data.update(refreshed)

                if not payment_intent:
                    payment_intent = _normalize_id(
                        refreshed.get("payment_intent")
                    )

                if not charge_id:
                    charge_id = _normalize_id(refreshed.get("charge"))

                pi_obj = refreshed.get("payment_intent")
                if isinstance(pi_obj, dict):
                    latest_charge = pi_obj.get("latest_charge")
                    charge_id = _normalize_id(latest_charge)

            logger.info(
                "Invoice %s enrichie (pi=%s charge=%s)",
                invoice_id,
                payment_intent or "absent",
                charge_id or "absent",
            )

        except Exception as exc:
            logger.warning(
                "Erreur enrichissement invoice %s: %s",
                invoice_id,
                exc,
            )

    # --------------------------------------------------
    # 🟩 Payload Supabase
    # --------------------------------------------------
    payload = {
        "invoice_id": invoice_id,
        "stripe_payment_intent_id": payment_intent,
        "stripe_charge_id": charge_id,
        "stripe_customer_id": stripe_customer_id,
        "subscription_id": subscription_id,
        "customer_email": customer_email,
        "user_id": user_id,  # 🔥 AUTH USER ID ONLY
        "plan_type": plan_id,
        "payment_status": "paid",
        "currency": currency,
        "amount_total_cents": int(amount_total_cents),
        "amount_subtotal_cents": (
            int(amount_subtotal_cents)
            if amount_subtotal_cents is not None
            else None
        ),
        "tax_amount_cents": (
            int(tax_amount_cents)
            if tax_amount_cents is not None
            else None
        ),
        "hosted_invoice_url": invoice_data.get("hosted_invoice_url"),
        "invoice_pdf_url": invoice_data.get("invoice_pdf"),
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    # --------------------------------------------------
    # Upsert logic (safe)
    # --------------------------------------------------
    existing_invoice = None
    if invoice_id:
        existing_invoice = await _fetch_invoice_record(invoice_id=invoice_id)
    if not existing_invoice and payment_intent:
        existing_invoice = await _fetch_invoice_record(
            payment_intent_id=payment_intent
        )

    if existing_invoice:
        update_payload = {
             k: v for k, v in payload.items()
             if v is not None
             and k not in ("created_at", "user_id")
        }
        update_payload["updated_at"] = datetime.utcnow().isoformat() + "Z"
        await _update_invoice_record(existing_invoice["id"], update_payload)
    else:
        await _insert_invoice_row(payload, on_conflict="invoice_id")

    logger.info(
        "Invoice fallback stored → %s (user_id=%s pi=%s charge=%s)",
        invoice_id,
        user_id,
        payment_intent,
        charge_id,
    )

    # --------------------------------------------------
    # Email sending (non-blocking)
    # --------------------------------------------------
    try:
        await send_invoice_email_from_invoice(
            invoice_data, None, payload
        )
    except Exception as exc:
        logger.warning(
            "Erreur envoi email fallback invoice %s: %s",
            invoice_id,
            exc,
        )



async def _send_invoice_email(invoice: dict, plan_id: str, user_id: str):
    customer_email = invoice.get("customer_email") or invoice.get("receipt_email")
    if not customer_email:
        logger.info(
            "Invoice %s not emailed because customer_email missing (user=%s)",
            invoice.get("id"),
            user_id,
        )
        return
    if not SMTP_HOST:
        logger.info(
            "Invoice %s not emailed because SMTP is not configured.",
            invoice.get("id"),
        )
        return

    invoice_payload = dict(invoice)
    invoice_id = invoice_payload.get("id")
    pdf_url = None
    if invoice_id:
        try:
            logger.info("Refreshing Stripe invoice %s before emailing plan %s", invoice_id, plan_id or "unknown")
            if stripe:
                refreshed_invoice = stripe.Invoice.retrieve(invoice_id)
            else:
                refreshed_invoice = await _stripe_api_request("GET", f"/v1/invoices/{invoice_id}")
            if isinstance(refreshed_invoice, dict):
                merged_invoice = dict(refreshed_invoice)
                merged_invoice.update(invoice_payload)
                invoice_payload = merged_invoice
                pdf_url = refreshed_invoice.get("invoice_pdf")
                invoice_id = invoice_payload.get("id") or invoice_id
                logger.info("Stripe invoice %s refreshed successfully (pdf=%s)", invoice_id, "yes" if pdf_url else "missing")
        except Exception as exc:
            logger.warning("Impossible de rafraîchir la facture %s: %s", invoice_id, exc)

    amount_cents = (
        invoice_payload.get("amount_paid")
        or invoice_payload.get("amount_due")
        or invoice_payload.get("total")
        or 0
    )
    currency = (invoice_payload.get("currency") or STRIPE_CURRENCY or "eur").upper()
    amount_value = Decimal(amount_cents or 0) / Decimal("100")
    amount_label = f"{amount_value:.2f} {currency}"

    invoice_number = invoice_payload.get("number") or invoice_payload.get("id")
    hosted_url = invoice_payload.get("hosted_invoice_url") or invoice_payload.get("invoice_pdf")

    issued_ts = invoice_payload.get("created")
    issued_at = None
    if isinstance(issued_ts, (int, float)):
        try:
            issued_at = datetime.fromtimestamp(issued_ts, timezone.utc).strftime("%d/%m/%Y")
        except Exception:
            issued_at = None
    issued_label = issued_at or datetime.utcnow().strftime("%d/%m/%Y")

    subject = f"Your CyberScan invoice — {invoice_number}"
    link_markup = ""
    if hosted_url:
        link_markup = f'<p><a href="{hosted_url}" target="_blank" style="color:#2563eb;">Download the invoice</a></p>'

    html_body = f"""
        <p>Hello,</p>
        <p>Your payment for <strong>{plan_id or "CyberScan"}</strong> has been confirmed.</p>
        <ul>
            <li><strong>Invoice:</strong> {invoice_number}</li>
            <li><strong>Amount:</strong> {amount_label}</li>
            <li><strong>Date:</strong> {issued_label}</li>
        </ul>
        {link_markup}
        <p>The link above opens the secure Stripe invoice you can keep for your records.</p>
        <p>— The CyberScan team</p>
    """

    text_body = (
        f"Hello,\n\n"
        f"Your invoice {invoice_number} for the {plan_id or 'CyberScan'} plan is ready.\n"
        f"Amount: {amount_label}\n"
        f"Date: {issued_label}\n"
        f"Link: {hosted_url or 'Log in to your account to download it.'}\n\n"
        "— The CyberScan team\n"
    )

    pdf_attachment = None
    if pdf_url:
        try:
            logger.info(
                "Tentative de récupération du PDF Stripe pour la facture %s via %s",
                invoice_id or invoice_number,
                pdf_url,
            )
            pdf_headers = {
                "Accept": "application/pdf,application/octet-stream;q=0.9,*/*;q=0.5",
                "User-Agent": "CyberScan-InvoiceBot/1.0",
                "Pragma": "no-cache",
                "Cache-Control": "no-cache",
            }
            async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
                response = await client.get(pdf_url, headers=pdf_headers)
            response.raise_for_status()
            content_type = (response.headers.get("content-type") or "").lower()
            body = response.content or b""
            is_pdf_header = body.startswith(b"%PDF")
            if response.status_code == 200 and (is_pdf_header or "pdf" in content_type):
                filename = f"{str(invoice_number).replace(' ', '_')}.pdf"
                pdf_attachment = {
                    "filename": filename,
                    "content": body,
                    "content_type": content_type or "application/pdf",
                }
                logger.info(
                    "Fetched invoice PDF for %s (%s) — %s bytes",
                    invoice_id or invoice_number,
                    pdf_url,
                    len(body),
                )
            else:
                logger.warning(
                    "Invoice PDF fetch failed for %s (status=%s type=%s length=%s)",
                    invoice_id or invoice_number,
                    response.status_code,
                    content_type or "unknown",
                    len(body),
                )
        except httpx.HTTPStatusError as exc:
            logger.warning("HTTP error while downloading invoice PDF %s: %s", pdf_url, exc)
        except httpx.HTTPError as exc:
            logger.warning("Unable to download invoice PDF from %s: %s", pdf_url, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Unexpected error downloading invoice PDF %s: %s", pdf_url, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Unexpected error downloading invoice PDF %s: %s", pdf_url, exc)

    await asyncio.to_thread(
        _send_smtp_email,
        subject,
        customer_email,
        html_body.strip(),
        text_body.strip(),
        [pdf_attachment] if pdf_attachment else None,
    )
    logger.info(
        "Invoice email sent to %s for invoice %s (plan=%s user=%s attachment=%s)",
        customer_email,
        invoice_id,
        plan_id,
        user_id,
        "pdf" if pdf_attachment else "none",
    )


async def send_invoice_email_from_invoice(
    invoice: dict | None,
    subscription: dict | None,
    purchase_request: dict | None,
) -> bool:

    # -----------------------------------------
    # 0. Vérification entrée
    # -----------------------------------------
    if not invoice:
        raise ValueError("invoice is required to send the billing email")

    invoice_data = dict(invoice or {})
    subscription_data = subscription or {}
    purchase_request_data = purchase_request or {}

    invoice_id = invoice_data.get("id")
    pdf_url = None

    # -----------------------------------------
    # 1. Rafraîchir la facture depuis Stripe
    # -----------------------------------------
    if invoice_id:
        try:
            logger.info("Refreshing Stripe invoice %s", invoice_id)

            refreshed_invoice = (
                stripe.Invoice.retrieve(invoice_id)
                if stripe else
                await _stripe_api_request("GET", f"/v1/invoices/{invoice_id}")
            )

            if isinstance(refreshed_invoice, dict):
                invoice_data = {**invoice_data, **refreshed_invoice}
                pdf_url = refreshed_invoice.get("invoice_pdf")

            logger.info(
                "Invoice %s refreshed. invoice_pdf=%s",
                invoice_id,
                "yes" if pdf_url else "no"
            )

        except Exception as exc:
            logger.warning("Impossible de rafraîchir la facture %s: %s", invoice_id, exc)

    # -----------------------------------------
    # 2. PDF fallback garanti par Stripe
    # -----------------------------------------
    if not pdf_url and invoice_id:
        pdf_url = f"https://pay.stripe.com/invoice/{invoice_id}/pdf"
        logger.info("Fallback PDF URL generated for invoice %s: %s", invoice_id, pdf_url)

    # -----------------------------------------
    # 3. Télécharger le PDF
    # -----------------------------------------
    pdf_attachment = None
    if pdf_url:
        try:
            logger.info("Téléchargement du PDF depuis %s", pdf_url)

            headers = {
                "Accept": "application/pdf",
                "User-Agent": "CyberScan-InvoiceBot/1.0",
            }

            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                response = await client.get(pdf_url, headers=headers)

            response.raise_for_status()
            content = response.content

            if content.startswith(b"%PDF"):
                pdf_attachment = {
                    "filename": f"{invoice_id}.pdf",
                    "content": content,
                    "content_type": "application/pdf",
                }
                logger.info("PDF %s téléchargé (%d bytes)", invoice_id, len(content))
            else:
                logger.warning("Contenu non-PDF reçu pour %s", invoice_id)

        except Exception as exc:
            logger.warning("Erreur lors du téléchargement du PDF %s: %s", invoice_id, exc)

    attachments = [pdf_attachment] if pdf_attachment else None

    # ----------------------------------------------------------------------
    # 4. EXTRACTION DES DONNÉES (robuste)
    # ----------------------------------------------------------------------

    def _extract(obj, *keys):
        if not obj:
            return None
        for key in keys:
            val = obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)
            if isinstance(val, str):
                val = val.strip()
            if val not in (None, "", []):
                return val
        return None

    def _coalesce(*vals):
        for v in vals:
            if isinstance(v, str):
                v = v.strip()
            if v not in (None, "", []):
                return v
        return None

    # Plan
    plan_label = _coalesce(
        _extract(purchase_request_data, "plan_id", "plan_type"),
        _extract(subscription_data, "plan_type"),
        _extract(invoice_data, "planId"),
        "CyberScan",
    )

    # Customer email
    customer_email = _coalesce(
        _extract(invoice_data, "customer_email", "receipt_email"),
        _extract(purchase_request_data, "billing_email", "contact_email"),
        _extract(subscription_data, "email"),
    )
    if not customer_email:
        logger.warning("No customer email, invoice=%s", invoice_id)
        return False

    # Montant
    cents = int(_coalesce(
        _extract(invoice_data, "amount_paid"),
        _extract(invoice_data, "amount_due"),
        _extract(invoice_data, "total"),
        0
    ))
    amount_label = f"{Decimal(cents)/100:.2f} {invoice_data.get('currency','EUR').upper()}"

    # Numéro
    invoice_number = _coalesce(_extract(invoice_data, "number"), invoice_id)

    # Date
    created = invoice_data.get("created")
    issued_date = datetime.utcfromtimestamp(created).strftime("%d/%m/%Y") if created else datetime.utcnow().strftime("%d/%m/%Y")

    # Dashboard
    try:
        base = _public_app_base_url()
    except:
        base = "https://app.cyberscan.cloud"
    dashboard_url = f"{base}/dashboard/subscription"

    # ----------------------------------------------------------------------
    # 5. Construction des emails
    # ----------------------------------------------------------------------

    html_body = f"""
        <p>Hello,</p>
        <p>Thank you for your payment. Here is your CyberScan invoice:</p>
        <ul>
            <li><strong>Invoice:</strong> {invoice_number}</li>
            <li><strong>Amount:</strong> {amount_label}</li>
            <li><strong>Date:</strong> {issued_date}</li>
            <li><strong>Plan:</strong> {plan_label}</li>
        </ul>
        <p>
            {"The PDF is attached." if pdf_attachment else ""}
        </p>
        <p>
            Access your dashboard:
            <a href="{dashboard_url}">{dashboard_url}</a>
        </p>
        <p>— The CyberScan team</p>
    """

    text_body = f"""
Hello,

Your invoice {invoice_number} for the {plan_label} plan is ready.
Amount: {amount_label}
Date: {issued_date}
{"The PDF is attached." if pdf_attachment else ""}

Dashboard: {dashboard_url}

— The CyberScan team
""".strip()

    subject = f"Invoice {invoice_number} — {plan_label}"

    # ----------------------------------------------------------------------
    # 6. Envoi email
    # ----------------------------------------------------------------------
    await asyncio.to_thread(
        _send_smtp_email,
        subject,
        customer_email,
        html_body,
        text_body,
        attachments,
    )

    logger.info(
        "Invoice email sent to %s (pdf=%s)",
        customer_email,
        "yes" if pdf_attachment else "no",
    )
    return True


async def _handle_checkout_session_completed(session: dict):
    logger.debug("Checkout session payload: %s", session)
    metadata = session.get("metadata") or {}
    plan_id = str(metadata.get("planId") or "").lower()
    user_id = str(metadata.get("userId") or "").strip()
    billing_interval = str(metadata.get("billingInterval") or "monthly").lower()
    email = session.get("customer_email")
    if not email:
        customer_details = session.get("customer_details") or {}
        email = customer_details.get("email")

    if user_id and not _is_uuid(user_id):
        logger.warning(
            "Metadata userId invalide (session=%s): %s",
            session.get("id") or "unknown",
            user_id,
        )
        user_id = ""

    logger.info(
        "Webhook reçu: plan=%s interval=%s user=%s metadata=%s",
        plan_id,
        billing_interval,
        user_id,
        metadata,
    )

    # -------------------------
    # 1️⃣ Sécurité metadata
    # -------------------------
    if (not user_id or not plan_id) and session.get("subscription"):
        subscription_id = session.get("subscription")
        try:
            subscription = stripe.Subscription.retrieve(subscription_id)
            subscription_metadata = subscription.get("metadata") or {}

            metadata = {**subscription_metadata, **metadata}
            plan_id = plan_id or str(subscription_metadata.get("planId") or "").lower()
            user_id = user_id or str(subscription_metadata.get("userId") or "").strip()
            billing_interval = (
                billing_interval
                or str(subscription_metadata.get("billingInterval") or "monthly").lower()
            )
            if user_id and not _is_uuid(user_id):
                logger.warning(
                    "Metadata subscription userId invalide (session=%s): %s",
                    session.get("id") or "unknown",
                    user_id,
                )
                user_id = ""
        except Exception as exc:
            logger.warning("Impossible de récupérer Metadata Subscription %s: %s", subscription_id, exc)

    if not user_id and email:
        resolved_user_id = await _resolve_user_id_from_email(email)
        if resolved_user_id:
            user_id = resolved_user_id
            metadata["userId"] = user_id
            session["metadata"] = metadata
            logger.info("userId résolu via email %s → %s", email, user_id)

    if not user_id:
        logger.warning("Webhook ignoré : userId manquant")
        return
    if not plan_id:
        logger.warning("Webhook ignoré : planId manquant")
        return

    # ------------------------------------
    # 2️⃣ Mise à jour abonnement Supabase
    # ------------------------------------
    base_credits = PLAN_CREDITS.get(plan_id, 0)
    credits_limit = base_credits * (12 if billing_interval in {"annual", "yearly", "year"} else 1)
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    expires_at = (
        now + timedelta(days=365)
        if billing_interval in {"annual", "yearly", "year"}
        else now + timedelta(days=30)
    )
    expires_iso = expires_at.isoformat()

    subscription_payload = {
        "plan_type": plan_id,
        "credits_limit": credits_limit,
        "status": "active",
        "started_at": now_iso,
        "expires_at": expires_iso,
        "updated_at": now_iso,
    }

    await _upsert_supabase_record(
        "subscriptions", user_id, subscription_payload, insert_extras={"created_at": now_iso}
    )

    credits_payload = {
        "total_credits": credits_limit,
        "used_credits": 0,
        "last_reset_at": now_iso,
        "updated_at": now_iso,
    }

    await _upsert_supabase_record(
        "credits", user_id, credits_payload, insert_extras={"created_at": now_iso}
    )

    # -------------------------
    # 3️⃣ Notification utilisateur
    # -------------------------
    alert_payload = {
        "user_id": user_id,
        "title": "Abonnement mis à jour",
        "message": f"Votre abonnement a été confirmé pour le plan {plan_id}",
        "type": "subscription",
        "severity": "info",
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    await _supabase_request("POST", "rest/v1/alerts", json_payload=alert_payload)

    # ------------------------------
    # 4️⃣ Enregistrement facture locale
    # ------------------------------
    await _record_invoice_entry(user_id, plan_id, session, email)

    logger.info(
        "Checkout complété → user=%s plan=%s interval=%s",
        user_id,
        plan_id,
        billing_interval,
    )
async def _handle_invoice_payment_succeeded(invoice_payload: dict, *, send_email: bool = True):
    logger.debug("Invoice payload: %s", invoice_payload)

    payment_payload = invoice_payload.get("payment") or {}
    logger.debug(
        "invoice.payment payload=%s payment.payment_intent=%s",
        payment_payload,
        payment_payload.get("payment_intent"),
    )

    invoice_id = invoice_payload.get("invoice") or invoice_payload.get("id")
    invoice_obj = invoice_payload if invoice_payload.get("object") == "invoice" else None

    raw_payment_intent = invoice_payload.get("payment_intent")
    payment_intent_id = payment_payload.get("payment_intent")
    if not payment_intent_id:
        if isinstance(raw_payment_intent, dict):
            payment_intent_id = raw_payment_intent.get("id")
        else:
            payment_intent_id = raw_payment_intent

    if not invoice_obj and invoice_id:
        try:
            invoice_obj = stripe.Invoice.retrieve(invoice_id, expand=["payment_intent"])
            logger.info("Invoice %s récupérée via Stripe API pour l'événement payment", invoice_id)
        except Exception as exc:
            logger.warning("Impossible de récupérer la facture Stripe %s: %s", invoice_id, exc)

    invoice_obj = invoice_obj or invoice_payload
    invoice_id = invoice_id or invoice_obj.get("id")
    charge = invoice_obj.get("charge")

    if not payment_intent_id:
        pi_field = invoice_obj.get("payment_intent")
        if isinstance(pi_field, dict):
            payment_intent_id = pi_field.get("id")
        else:
            payment_intent_id = pi_field

    if not payment_intent_id:
        logger.warning(
            "Invoice %s sans payment_intent — événement ignoré",
            invoice_id or "unknown",
        )
        return

    payment_intent_obj = None
    try:
        payment_intent_obj = stripe.PaymentIntent.retrieve(payment_intent_id)
        logger.info(
            "PaymentIntent %s récupéré (status=%s)",
            payment_intent_id,
            payment_intent_obj.get("status") if isinstance(payment_intent_obj, dict) else "unknown",
        )
        if isinstance(payment_intent_obj, dict):
            payment_intent_id = payment_intent_obj.get("id", payment_intent_id)
    except Exception as exc:
        logger.warning("Impossible de récupérer PaymentIntent %s: %s", payment_intent_id, exc)

    billing_reason = invoice_obj.get("billing_reason")
    pdf_url = invoice_obj.get("invoice_pdf")
    customer_email = invoice_obj.get("customer_email") or invoice_obj.get("receipt_email")

    # 🟥 1. Éviter les factures fantômes Stripe (subscription_create sans PDF)
    if billing_reason == "subscription_create" and not pdf_url:
        logger.info(
            "Invoice %s ignorée (ghost invoice Stripe — aucune metadata, aucune PDF)",
            invoice_id,
        )
        return

    # ---------------------------
    # 🟦 2. Extraction metadata
    # ---------------------------
    metadata = dict(invoice_obj.get("metadata") or {})
    plan_id = metadata.get("planId")
    user_id = metadata.get("userId")
    if user_id:
        user_id = str(user_id).strip()
    if user_id and not _is_uuid(user_id):
        logger.warning(
            "Invoice %s metadata userId invalide: %s",
            invoice_id or "unknown",
            user_id,
        )
        user_id = None

    # Stripe n’envoie pas toujours metadata → enrichir depuis subscription
    if not plan_id or not user_id:
        subscription_id = invoice_obj.get("subscription")
        if subscription_id:
            try:
                subscription = stripe.Subscription.retrieve(subscription_id)
                sub_meta = subscription.get("metadata") or {}

                plan_id = plan_id or sub_meta.get("planId")
                user_id = user_id or sub_meta.get("userId")
                if user_id:
                    user_id = str(user_id).strip()
                if user_id and not _is_uuid(user_id):
                    logger.warning(
                        "Invoice %s metadata userId invalide (subscription): %s",
                        invoice_id or "unknown",
                        user_id,
                    )
                    user_id = None

                logger.info(
                    "Metadata enrichies via subscription: user=%s plan=%s",
                    user_id, plan_id
                )
            except Exception as exc:
                logger.warning("Impossible de récupérer metadata depuis subscription: %s", exc)

    if not user_id and customer_email:
        resolved_user_id = await _resolve_user_id_from_email(customer_email)
        if resolved_user_id:
            user_id = resolved_user_id
            logger.info(
                "Invoice %s rattachée au user %s via email",
                invoice_id or "unknown",
                user_id,
            )

    # ---------------------------
    # 🟥 3. Si toujours pas de metadata → fallback remboursable
    # ---------------------------
    if not plan_id or not user_id:
        logger.warning(
            "Invoice %s sans metadata — enregistrée en mode fallback pour permettre refund",
            invoice_id,
        )

        await _record_invoice_entry_fallback(
            invoice_obj,
            payment_intent_id=payment_intent_id,
            charge=charge,
        )
        return

    logger.info("Invoice validée pour user=%s plan=%s", user_id, plan_id)

    # ---------------------------
    # 🟦 4. Mise à jour DB : payment_intent / charge
    # ---------------------------
    if isinstance(payment_intent_obj, dict):
        latest_charge = payment_intent_obj.get("latest_charge")
        if isinstance(latest_charge, dict):
            charge = charge or latest_charge.get("id")
        else:
            charge = charge or latest_charge

    # Stripe n’envoie PAS toujours charge → fallback PaymentIntent simple
    if not charge and isinstance(payment_intent_obj, dict):
        try:
            refreshed_pi = stripe.PaymentIntent.retrieve(payment_intent_id)
            latest_charge = refreshed_pi.get("latest_charge")
            if isinstance(latest_charge, dict):
                charge = latest_charge.get("id")
            else:
                charge = latest_charge
            logger.info("Charge fallback récupérée: %s", charge)
        except Exception as exc:
            logger.warning("Impossible de récupérer charge via PaymentIntent: %s", exc)

    # ---------------------------
    # 📌 Mise à jour Supabase
    # ---------------------------
    target_invoice = await _fetch_invoice_record(
        invoice_id=invoice_id,
        user_id=user_id,
        payment_intent_id=payment_intent_id,
    )
    if not target_invoice and payment_intent_id:
        target_invoice = await _fetch_invoice_record(payment_intent_id=payment_intent_id)
    if not target_invoice:
        logger.warning(
            "Invoice %s reçue mais introuvable en DB (payment_intent=%s) — création fallback",
            invoice_id or "unknown",
            payment_intent_id or "absent",
        )
        await _record_invoice_entry_fallback(
            invoice_obj,
            payment_intent_id=payment_intent_id,
            charge=charge,
        )
        target_invoice = await _fetch_invoice_record(
            invoice_id=invoice_id,
            payment_intent_id=payment_intent_id,
        )
        if not target_invoice:
            return

    amount_total_cents = (
        invoice_obj.get("amount_paid")
        or invoice_obj.get("amount_due")
        or invoice_obj.get("total")
        or 0
    )
    amount_subtotal_cents = invoice_obj.get("subtotal") or invoice_obj.get("amount_subtotal")
    tax_amount_cents = invoice_obj.get("tax") or invoice_obj.get("tax_amount")
    currency = (invoice_obj.get("currency") or STRIPE_CURRENCY or "eur").upper()
    stripe_customer_id = invoice_obj.get("customer")
    hosted_invoice_url = invoice_obj.get("hosted_invoice_url") or invoice_obj.get("invoice_pdf")

    await _update_invoice_record(
        target_invoice["id"],
        {
            "user_id": user_id,
            "plan_type": plan_id,
            "invoice_id": invoice_id,
            "stripe_payment_intent_id": payment_intent_id,
            "stripe_charge_id": charge,
            "stripe_customer_id": stripe_customer_id,
            "customer_email": customer_email,
            "payment_status": "paid",
            "currency": currency,
            "amount_total_cents": int(amount_total_cents) if amount_total_cents is not None else None,
            "amount_subtotal_cents": int(amount_subtotal_cents) if amount_subtotal_cents is not None else None,
            "tax_amount_cents": int(tax_amount_cents) if tax_amount_cents is not None else None,
            "hosted_invoice_url": hosted_invoice_url,
            "invoice_pdf_url": invoice_obj.get("invoice_pdf"),
        },
    )

    if send_email:
        try:
            await send_invoice_email_from_invoice(invoice_obj, None, target_invoice)
        except Exception as exc:
            logger.warning("Erreur envoi email facture %s: %s", invoice_id, exc)


def _validate_backend_key(request: Request) -> bool:
    if not BACKEND_API_KEY:
        return False
    header_key = request.headers.get('x-backend-api-key')
    if header_key == BACKEND_API_KEY:
        return True
    token = _extract_bearer_token(request.headers.get('authorization'))
    if token == BACKEND_API_KEY:
        return True
    return False

def _require_backend_key(request: Request):
    if not _validate_backend_key(request):
        raise HTTPException(status_code=401, detail="Clé backend invalide")

async def _generate_supabase_recovery_otp(email: str, redirect_url: str) -> str:
    otp_payload = {
        "type": "recovery",
        "email": email,
        "redirect_to": redirect_url,
    }

    try:
        response_data = await _supabase_request("POST", "auth/v1/admin/generate_link", json_payload=otp_payload)
    except HTTPException as exc:
        raise exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Supabase Error: {exc}") from exc

    properties = response_data.get("properties") if isinstance(response_data, dict) else None
    otp_code = None
    if isinstance(properties, dict):
        otp_code = properties.get("email_otp")
    if not otp_code and isinstance(response_data, dict):
        otp_code = response_data.get("email_otp")

    if not otp_code:
        raise HTTPException(status_code=500, detail="Unable to generate OTP code")
    return otp_code

@app.post("/auth/send-password-reset")
async def send_password_reset_email(request: Request, payload: PasswordResetRequest):
    _require_backend_key(request)

    email = (payload.email or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email required")

    profile = await _supabase_fetch_first("profiles", {"email": email})
    if not profile:
        logger.info("Password reset requested for unknown user %s", email)
        return {"message": "If the account exists, a code has been sent"}

    redirect_url = _build_frontend_url("/forgot-password")
    otp_code = await _generate_supabase_recovery_otp(email, redirect_url)

    app_base = _public_app_base_url()
    forgot_url = _build_frontend_url("/forgot-password")
    subject = "CyberScan • Password reset code"
    html_body = f"""
    <p>Hello,</p>
    <p>You requested to reset the password for the account <strong>{email}</strong>.</p>
    <p>Use the code below to confirm the operation:</p>
    <p style="font-size:28px;font-weight:700;letter-spacing:6px;margin:20px 0;color:#111827;">{otp_code}</p>
    <p>If you did not make this request, simply ignore this email.</p>
    <p>— The CyberScan team<br/>{app_base}</p>
    """
    text_body = (
        "Hello,\n\n"
        "You requested a CyberScan password reset.\n"
        "Confirmation code: {otp}\n"
        "Enter it at {url} to set a new secure password.\n\n"
        "If you did not make this request, simply ignore this email.\n"
        "— The CyberScan team"
    ).format(otp=otp_code, url=forgot_url)

    try:
        await asyncio.to_thread(
            _send_smtp_email,
            subject,
            email,
            html_body.strip(),
            text_body,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"message": "Code sent"}

@app.post("/auth/send-password-change")
async def send_password_change_email(request: Request, payload: PasswordResetRequest):
    _require_backend_key(request)

    email = (payload.email or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Email required")

    profile = await _supabase_fetch_first("profiles", {"email": email})
    if not profile:
        logger.info("Password change requested for unknown user %s", email)
        return {"message": "If the account exists, a code has been sent"}

    redirect_url = _build_frontend_url("/dashboard/profile")
    otp_code = await _generate_supabase_recovery_otp(email, redirect_url)

    app_base = _public_app_base_url()
    subject = "CyberScan • Password change confirmation code"
    html_body = f"""
    <p>Hello,</p>
    <p>You requested to change the password for the account <strong>{email}</strong>.</p>
    <p>Use the code below to confirm the operation:</p>
    <p style="font-size:28px;font-weight:700;letter-spacing:6px;margin:20px 0;color:#111827;">{otp_code}</p>
    <p>If you did not make this request, simply ignore this email.</p>
    <p>— The CyberScan team.</p>
    """
    text_body = (
        "Hello,\n\n"
        "You requested to change your CyberScan password.\n"
        f"Confirmation code: {otp_code}\n"
        "If you did not make this request, simply ignore this email.\n"
        "— The CyberScan team"
    )

    try:
        await asyncio.to_thread(
            _send_smtp_email,
            subject,
            email,
            html_body.strip(),
            text_body,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"message": "Code sent"}


@app.post("/stripe/create-checkout")
async def create_stripe_checkout(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe n'est pas configuré sur le serveur")

    is_service_call = _validate_backend_key(request)
    session_user: Optional[dict] = None

    if not is_service_call:
        _enforce_request_origin(request)
        _require_csrf_token(request)
        session_user = await _require_user_session(request)

    body = await request.json()
    plan_id = body.get("planId")
    billing_interval = str(body.get("billingInterval") or "monthly").lower()
    user_id = body.get("userId", "")
    email = body.get("email")

    if not plan_id:
        raise HTTPException(status_code=400, detail="planId manquant")

    # ---------------------------
    # Vérification session utilisateur
    # ---------------------------
    if session_user:
        authenticated_user_id = session_user.get("id")
        if not authenticated_user_id:
            raise HTTPException(status_code=401, detail="Session utilisateur invalide")

        if user_id and user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="userId ne correspond pas à la session authentifiée")

        user_id = authenticated_user_id
        email = email or session_user.get("email")

    # ---------------------------
    # Résolution du pricing du plan
    # ---------------------------
    try:
        pricing = _resolve_plan_pricing(plan_id, billing_interval)
    except ValueError as exc:
        logger.error("Checkout pricing error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not pricing.get("price_id") and not pricing.get("unit_amount"):
        logger.error("Plan %s non configuré pour Stripe", plan_id)
        raise HTTPException(status_code=400, detail=f"Plan {plan_id} non configuré pour Stripe")

    line_items = _build_line_items(plan_id, pricing, billing_interval)
    amount_query = None
    if pricing.get("unit_amount"):
        try:
            base_amount = int(pricing["unit_amount"] or 0)
            total_cents = base_amount + _processing_fee_cents(base_amount)
            amount_query = f"{Decimal(total_cents) / Decimal(100):.2f}"
        except Exception:
            amount_query = None

    logger.info(
        "Checkout subscription demandé plan=%s interval=%s user=%s",
        plan_id,
        billing_interval,
        user_id,
    )

    # ---------------------------
    # Préparer les metadata
    # ---------------------------
    metadata = {
        "planId": str(plan_id),
        "billingInterval": billing_interval,
    }

    if user_id:
        metadata["userId"] = str(user_id)

    subscription_metadata = dict(metadata)

    # ---------------------------
    # URL d'origine
    # ---------------------------
    origin = (
        request.headers.get('origin')
        or os.environ.get('NEXT_PUBLIC_APP_URL')
        or os.environ.get('NEXT_PUBLIC_SITE_URL')
        or 'http://localhost:3000'
    )

    # ---------------------------
    # Payload Stripe Checkout
    # ---------------------------
    payload = {
        "mode": "subscription",
        "payment_method_types": ["card"],
        "customer_email": email or None,
        "metadata": metadata,
        "subscription_data": {
            "metadata": subscription_metadata
        },
        "line_items": line_items,
        "success_url": (
            f"{origin}/dashboard/payment_succeeded?plan={plan_id}"
            f"&interval={billing_interval}&session_id={{CHECKOUT_SESSION_ID}}"
            + (f"&amount={amount_query}" if amount_query else "")
        ),
        "cancel_url": f"{origin}/dashboard/subscription?canceled=true&plan={plan_id}",
    }

    # Automatic Tax si activé
    if STRIPE_ENABLE_AUTOMATIC_TAX:
        payload["automatic_tax"] = {"enabled": True}
        payload["billing_address_collection"] = "required"

    # ---------------------------
    # Création Checkout Session Stripe
    # ---------------------------
    try:
        if stripe:
            sdk_payload = {key: value for key, value in payload.items() if value is not None}
            session = stripe.checkout.Session.create(**sdk_payload)
        else:
            session = await _create_stripe_session_with_httpx(payload)

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Erreur Stripe: {exc}") from exc

    if not session or not session.get("url"):
        raise HTTPException(status_code=500, detail="Stripe n'a pas retourné d'URL de redirection")

    logger.info("Checkout créé plan=%s interval=%s user=%s", plan_id, billing_interval, user_id)

    return {"url": session["url"]}


@app.post("/stripe/confirm-checkout-session")
async def confirm_checkout_session(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe n'est pas configuré sur le serveur")

    is_service_call = _validate_backend_key(request)
    session_user: Optional[dict] = None

    if not is_service_call:
        _enforce_request_origin(request)
        _require_csrf_token(request)
        session_user = await _require_user_session(request)

    try:
        body = await request.json()
    except Exception:
        body = {}

    session_id = str(body.get("sessionId") or body.get("checkoutSessionId") or "").strip()
    user_id = str(body.get("userId") or "").strip()
    plan_hint = str(body.get("plan") or body.get("planId") or "").lower().strip()
    interval_hint = str(body.get("interval") or body.get("billingInterval") or "").lower().strip()

    if session_user:
        authenticated_user_id = session_user.get("id")
        if not authenticated_user_id:
            raise HTTPException(status_code=401, detail="Session utilisateur invalide")
        if user_id and user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="userId ne correspond pas à la session authentifiée")
        user_id = authenticated_user_id

    if not session_id:
        raise HTTPException(status_code=400, detail="sessionId manquant")

    session_data = await _retrieve_checkout_session(session_id)
    if not session_data:
        raise HTTPException(status_code=404, detail="Session Stripe introuvable")

    status = str(session_data.get("status") or "").lower()
    payment_status = str(session_data.get("payment_status") or "").lower()
    if status not in {"complete", "completed"} and payment_status not in {"paid", "paid_out"}:
        raise HTTPException(status_code=400, detail="Session de paiement non complétée")

    metadata = dict(session_data.get("metadata") or {})
    if plan_hint and not metadata.get("planId"):
        metadata["planId"] = plan_hint
    if interval_hint and not metadata.get("billingInterval"):
        metadata["billingInterval"] = interval_hint
    if user_id:
        metadata["userId"] = user_id
    session_data["metadata"] = metadata

    subscription = session_data.get("subscription")
    if isinstance(subscription, dict):
        subscription_meta = dict(subscription.get("metadata") or {})
        for key in ("planId", "billingInterval", "userId"):
            if metadata.get(key) and not subscription_meta.get(key):
                subscription_meta[key] = metadata[key]
        subscription["metadata"] = subscription_meta
        session_data["subscription"] = subscription

    await _handle_checkout_session_completed(session_data)

    return {"status": "synced"}


@app.post("/stripe/create-checkout-subscription")
async def create_checkout_subscription(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe non configuré")

    # Auth utilisateur
    is_service_call = _validate_backend_key(request)
    session_user = None
    if not is_service_call:
        try:
            _enforce_request_origin(request)
            _require_csrf_token(request)
            session_user = await _require_user_session(request)
        except HTTPException as exc:
            logger.warning("Checkout refusé (session manquante ou invalide): %s", exc.detail)
            raise HTTPException(status_code=401, detail="Authentification requise. Connectez-vous ou utilisez la clé backend.")

    body = await request.json()
    plan_id = body.get("planId")
    billing_interval = str(body.get("billingInterval") or "monthly").lower()
    user_id = body.get("userId")
    email = body.get("email")

    if not plan_id:
        raise HTTPException(status_code=400, detail="planId manquant")

    if session_user:
        user_id = session_user["id"]
        email = session_user["email"]
    elif not user_id or not email:
        raise HTTPException(status_code=400, detail="userId ou email manquant pour la session Stripe")

    # Récup prix stripe
    pricing = _resolve_plan_pricing(plan_id, billing_interval)
    if not pricing.get("price_id") and not pricing.get("unit_amount"):
        raise HTTPException(status_code=400, detail="Plan non configuré")

    line_items = _build_line_items(plan_id, pricing, billing_interval)

    # URL front
    origin = (
        request.headers.get("origin")
        or os.environ.get("NEXT_PUBLIC_APP_URL")
        or "http://localhost:3000"
    )

    metadata = {
        "planId": plan_id,
        "userId": user_id,
        "billingInterval": billing_interval,
    }

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=email,
            line_items=line_items,
            automatic_tax={"enabled": True},
            billing_address_collection="required",
            metadata=metadata,
            subscription_data={"metadata": metadata},
            success_url=f"{origin}/dashboard/subscription?success=true&plan={plan_id}&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{origin}/dashboard/subscription?canceled=true&plan={plan_id}",
        )
    except Exception as exc:
        logger.exception("Erreur Stripe lors du checkout subscription: %s", exc)
        raise HTTPException(status_code=500, detail=f"Stripe error: {exc}")

    return {"url": session.url}

@app.post("/stripe/create-subscription-intent")
async def create_subscription_intent(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe n'est pas configuré sur le serveur")

    # ----------------------------
    # VALIDATION SESSION / USER
    # ----------------------------
    is_service_call = _validate_backend_key(request)
    session_user: Optional[dict] = None

    if not is_service_call:
        _enforce_request_origin(request)
        _require_csrf_token(request)
        session_user = await _require_user_session(request)

    body = await request.json()
    plan_id = body.get("planId")
    billing_interval = str(body.get("billingInterval") or "monthly").lower()
    user_id = body.get("userId", "")
    email = body.get("email")

    if not plan_id:
        raise HTTPException(status_code=400, detail="planId manquant")

    if session_user:
        authenticated_user_id = session_user.get("id")
        if not authenticated_user_id:
            raise HTTPException(status_code=401, detail="Session utilisateur invalide")

        if user_id and user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="userId ne correspond pas à la session authentifiée")

        user_id = authenticated_user_id
        email = email or session_user.get("email")

    # ----------------------------
    # RESOLUTION PLAN / PRIX
    # ----------------------------
    try:
        pricing = _resolve_plan_pricing(plan_id, billing_interval)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if not pricing.get("price_id") and not pricing.get("unit_amount"):
        raise HTTPException(status_code=400, detail=f"Plan {plan_id} non configuré pour Stripe")

    line_items = _build_line_items(plan_id, pricing)
    subscription_items = await _line_items_to_subscription_items(line_items)

    # ----------------------------
    # METADATA
    # ----------------------------
    metadata = {"planId": str(plan_id), "billingInterval": billing_interval}
    if user_id:
        metadata["userId"] = str(user_id)

    # ----------------------------
    # CUSTOMER PAYLOAD (Stripe tax + FR country)
    # ----------------------------
    customer_payload = {
        "email": email,
        "metadata": metadata,
        "address": {
          "country": "FR",
          "postal_code": "75001"
},
    }

    auto_tax_enabled = True  # 🚨 Désactivé car Stripe Tax + adresse FR sans postal = bloque PaymentIntent

    try:
        customer, subscription, _, client_secret = await _create_subscription_intent_with_httpx(
            customer_payload,
            subscription_items,
            metadata,
            auto_tax_enabled,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=f"Erreur Stripe lors de la création de l'abonnement: {exc}") from exc

    customer_id = customer.get("id") if isinstance(customer, dict) else None
    subscription_id = subscription.get("id") if isinstance(subscription, dict) else None

    if not client_secret:
        raise HTTPException(
            status_code=500,
            detail="Stripe n'a pas fourni de client secret pour l'abonnement créé"
        )

    if not customer_id or not subscription_id:
        raise HTTPException(status_code=500, detail="Stripe n'a pas renvoyé les identifiants attendus")

    return {
        "clientSecret": client_secret,
        "subscriptionId": subscription_id,
        "customerId": customer_id,
    }


async def _retrieve_checkout_session(session_id: str) -> dict | None:
    if not session_id:
        return None
    try:
        if stripe:
            session = stripe.checkout.Session.retrieve(
                session_id,
                expand=["subscription", "payment_intent", "line_items", "total_details"],
            )
            if hasattr(session, "to_dict_recursive"):
                return session.to_dict_recursive()
            return dict(session)
        return await _stripe_api_request(
            "GET",
            f"/v1/checkout/sessions/{session_id}",
            {"expand": ["subscription", "payment_intent", "line_items", "total_details"]},
        )
    except Exception as exc:
        logger.warning("Impossible de récupérer la session Checkout %s: %s", session_id, exc)
        return None


async def _retrieve_payment_intent(payment_intent_id: str) -> dict | None:
    if not payment_intent_id:
        return None
    try:
        if stripe:
            return stripe.PaymentIntent.retrieve(
                payment_intent_id,
                expand=["invoice"],
            )
        return await _stripe_api_request(
            "GET",
            f"/v1/payment_intents/{payment_intent_id}",
            {"expand": ["invoice"]},
        )
    except Exception as exc:
        logger.warning("Impossible de récupérer le PaymentIntent %s: %s", payment_intent_id, exc)
        return None


async def _retrieve_invoice(invoice_obj) -> dict | None:
    if isinstance(invoice_obj, dict):
        return invoice_obj
    invoice_id = invoice_obj if isinstance(invoice_obj, str) else None
    if not invoice_id:
        return None
    try:
        if stripe:
            return stripe.Invoice.retrieve(invoice_id)
        return await _stripe_api_request("GET", f"/v1/invoices/{invoice_id}")
    except Exception as exc:
        logger.warning("Impossible de récupérer la facture Stripe %s: %s", invoice_id, exc)
        return None


async def _sync_plan_from_invoice(invoice: dict):
    if not invoice:
        raise HTTPException(status_code=400, detail="Facture Stripe introuvable pour la synchronisation")
    await _handle_invoice_payment_succeeded(invoice, send_email=False)


@app.post("/stripe/sync-subscription")
async def sync_subscription(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe n'est pas configuré sur le serveur")

    is_service_call = _validate_backend_key(request)
    session_user: Optional[dict] = None

    if not is_service_call:
        _enforce_request_origin(request)
        _require_csrf_token(request)
        session_user = await _require_user_session(request)

    body = await request.json()
    payment_intent_id = str(body.get("paymentIntentId") or "").strip()
    plan_id = str(body.get("planId") or "").lower().strip()
    user_id = str(body.get("userId") or "").strip()

    if session_user:
        authenticated_user_id = session_user.get("id")
        if not authenticated_user_id:
            raise HTTPException(status_code=401, detail="Session utilisateur invalide")
        if user_id and user_id != authenticated_user_id:
            raise HTTPException(status_code=403, detail="userId ne correspond pas à la session authentifiée")
        user_id = authenticated_user_id

    if not payment_intent_id:
        raise HTTPException(status_code=400, detail="paymentIntentId manquant")

    intent = await _retrieve_payment_intent(payment_intent_id)
    if not intent:
        raise HTTPException(status_code=400, detail="PaymentIntent introuvable")

    status = intent.get("status")
    if status not in {"succeeded", "processing"}:
        raise HTTPException(status_code=400, detail="PaymentIntent non confirmé")

    invoice = await _retrieve_invoice(intent.get("invoice"))
    invoice_data = invoice or {}
    metadata = invoice_data.get("metadata") or {}
    pi_metadata = intent.get("metadata") or {}
    merged_metadata = {**metadata, **pi_metadata}
    if plan_id:
        merged_metadata.setdefault("planId", plan_id)
    if user_id:
        merged_metadata.setdefault("userId", user_id)
    if invoice:
        invoice["metadata"] = merged_metadata
        await _sync_plan_from_invoice(invoice)
    else:
        plan_from_request = merged_metadata.get("planId")
        user_from_request = merged_metadata.get("userId")
        if not plan_from_request or not user_from_request:
            raise HTTPException(status_code=400, detail="Impossible de récupérer la facture Stripe associée")

        fallback_invoice = {
            "id": intent.get("id"),
            "metadata": merged_metadata,
            "customer": intent.get("customer"),
            "customer_email": intent.get("receipt_email") or intent.get("customer_email"),
            "payment_intent": intent.get("id"),
            "paid": True,
            "status": intent.get("status"),
            "amount_paid": intent.get("amount_received") or intent.get("amount"),
            "amount_due": intent.get("amount"),
            "currency": intent.get("currency"),
            "subscription": merged_metadata.get("subscriptionId") or intent.get("metadata", {}).get("subscriptionId"),
        }
        await _sync_plan_from_invoice(fallback_invoice)
    return {"status": "synced"}

async def send_refund_email(invoice: dict, refund: dict):
    """
    Envoie un email de confirmation de remboursement au client.
    """

    customer_email = invoice.get("customer_email") or invoice.get("receipt_email")
    if not customer_email:
        logger.warning(
            "Impossible d'envoyer l'email de remboursement : aucune adresse email trouvée (invoice=%s)",
            invoice.get("id"),
        )
        return False

    refund_id = refund.get("id")
    refund_amount = (refund.get("amount") or 0) / 100
    refund_currency = (refund.get("currency") or "eur").upper()
    invoice_number = invoice.get("number") or invoice.get("id")
    refund_date = datetime.utcnow().strftime("%d/%m/%Y")

    subject = f"Refund confirmation — Invoice {invoice_number}"

    html_body = f"""
        <p>Hello,</p>
        <p>Your refund for invoice <strong>{invoice_number}</strong> has been processed.</p>

        <ul>
            <li><strong>Amount refunded:</strong> {refund_amount:.2f} {refund_currency}</li>
            <li><strong>Refund date:</strong> {refund_date}</li>
            <li><strong>Stripe refund ID:</strong> {refund_id}</li>
        </ul>

        <p>
            Depending on your bank, the funds should reappear on your account within 5–10 business days.
        </p>

        <p>— The CyberScan team</p>
    """

    text_body = (
        f"Hello,\n\n"
        f"Your refund for invoice {invoice_number} has been processed.\n"
        f"Amount refunded: {refund_amount:.2f} {refund_currency}\n"
        f"Refund ID: {refund_id}\n"
        f"Date: {refund_date}\n\n"
        "The credit should appear on your account within a few days.\n\n"
        "— CyberScan\n"
    )

    try:
        await asyncio.to_thread(
            _send_smtp_email,
            subject,
            customer_email,
            html_body.strip(),
            text_body.strip(),
        )
        logger.info(
            "Email de remboursement envoyé à %s (refund_id=%s)",
            customer_email,
            refund_id
        )
        return True

    except Exception as exc:
        logger.warning("Erreur lors de l'envoi email refund: %s", exc)
        return False


async def _perform_stripe_refund(
    invoice: dict,
    user_id: str,
    *,
    checkout_session_id: str | None = None,
    reason: str | None = None,
) -> dict:
    payment_intent_id = invoice.get("stripe_payment_intent_id")
    charge_id = invoice.get("stripe_charge_id")
    stripe_invoice_id = invoice.get("invoice_id")

    if checkout_session_id is None:
        checkout_session_id = invoice.get("stripe_checkout_session_id")

    def _extract_stripe_id(value):
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            return value.get("id")
        return None

    if checkout_session_id and (not stripe_invoice_id or not payment_intent_id or not charge_id):
        try:
            session = stripe.checkout.Session.retrieve(
                checkout_session_id,
                expand=["invoice.payment_intent", "payment_intent.latest_charge"],
            )
            invoice_from_session = session.get("invoice")
            session_payment_intent = session.get("payment_intent")

            invoice_from_session_id = _extract_stripe_id(invoice_from_session)
            if invoice_from_session_id:
                stripe_invoice_id = stripe_invoice_id or invoice_from_session_id

            if session_payment_intent:
                pi_from_invoice = (
                    _extract_stripe_id(invoice_from_session.get("payment_intent"))
                    if isinstance(invoice_from_session, dict)
                    else None
                )
                payment_intent_id = payment_intent_id or pi_from_invoice or _extract_stripe_id(session_payment_intent)
                charge_id = charge_id or _extract_stripe_id(session_payment_intent.get("latest_charge"))

            if isinstance(invoice_from_session, dict) and not charge_id:
                charge_id = _extract_stripe_id(invoice_from_session.get("charge"))

            logger.info(
                "Stripe session enriched refund payload (invoice=%s, pi=%s, charge=%s)",
                stripe_invoice_id,
                payment_intent_id,
                charge_id,
            )
        except Exception as exc:
            logger.warning("Impossible de rafraîchir la session Stripe %s: %s", checkout_session_id, exc)

    if stripe_invoice_id and (not charge_id and not payment_intent_id):
        try:
            stripe_invoice = stripe.Invoice.retrieve(stripe_invoice_id)
            invoice_payment_intent = stripe_invoice.get("payment_intent")
            payment_intent_id = payment_intent_id or _extract_stripe_id(invoice_payment_intent)
            charge_id = charge_id or _extract_stripe_id(stripe_invoice.get("charge"))
            if payment_intent_id and not charge_id:
                pi = stripe.PaymentIntent.retrieve(payment_intent_id)
                charge_id = charge_id or (pi.get("charges", {}).get("data") or [{}])[0].get("id")
        except Exception as exc:
            logger.warning("Impossible de récupérer Stripe invoice %s: %s", stripe_invoice_id, exc)

    if charge_id and not payment_intent_id:
        try:
            charge_obj = stripe.Charge.retrieve(charge_id)
            payment_intent_id = payment_intent_id or charge_obj.get("payment_intent")
        except Exception as exc:
            logger.warning("Impossible de récupérer Charge %s: %s", charge_id, exc)

    if not payment_intent_id and checkout_session_id:
        logger.warning("Refund: aucun payment_intent détecté pour la session %s", checkout_session_id)

    if not charge_id and not payment_intent_id:
        raise HTTPException(400, "Impossible de déterminer le paiement Stripe associé")

    refund_payload = (
        {
            "charge": charge_id,
            "reason": "requested_by_customer",
            "metadata": {
                "invoice_id": invoice.get("invoice_id") or invoice.get("id"),
                "invoice_uuid": invoice.get("id"),
                "user_id": user_id,
            },
        }
        if charge_id
        else {
            "payment_intent": payment_intent_id,
            "reason": "requested_by_customer",
            "metadata": {
                "invoice_id": invoice.get("invoice_id") or invoice.get("id"),
                "invoice_uuid": invoice.get("id"),
                "user_id": user_id,
            },
        }
    )

    logger.info(
        "Stripe refund payload=%s invoice_id=%s",
        refund_payload,
        invoice.get("invoice_id") or invoice.get("id"),
    )

    try:
        refund = stripe.Refund.create(**refund_payload)
    except Exception as exc:
        logger.error("Stripe refund failed payload=%s error=%s", refund_payload, exc)
        message = getattr(exc, "user_message", None) or getattr(exc, "error", {}).get("message")
        raise HTTPException(400, f"Stripe refund error: {message or exc}")

    refund_id = refund.get("id")
    refund_status = refund.get("status")
    refund_amount = refund.get("amount")
    refund_currency = refund.get("currency")

    logger.info(
        "Stripe refund succeeded refund_id=%s status=%s amount=%s currency=%s",
        refund_id,
        refund_status,
        refund_amount,
        refund_currency,
    )

    update_payload = {
        "refund_id": refund_id,
        "refund_status": refund_status,
        "refund_amount_cents": refund_amount,
        "refund_currency": refund_currency.upper() if refund_currency else None,
        "refunded_at": datetime.utcnow().isoformat() + "Z",
        "status": "refunded",
    }
    await _update_invoice_record(invoice["id"], update_payload)

    alert_payload = {
        "user_id": user_id,
        "title": "Refund in progress" if refund_status == "pending" else "Refund completed",
        "message": "Your refund has been initiated." if refund_status == "pending" else "Your refund has been processed.",
        "type": "system",
        "severity": "info",
        "is_read": False,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    await _supabase_request("POST", "rest/v1/alerts", json_payload=alert_payload)

    try:
        await send_refund_email(invoice, refund)
    except Exception as exc:
        logger.warning("Email refund non envoyé: %s", exc)

    try:
        await _reset_subscription_after_refund(user_id)
    except Exception as exc:
        logger.warning("Impossible de réinitialiser l'abonnement/credits après refund pour user %s: %s", user_id, exc)

    return {
        "refundId": refund_id,
        "status": refund_status,
        "amount": refund_amount,
        "currency": refund_currency,
    }
@app.post("/stripe/request-refund")
async def request_refund(request: Request, payload: RefundRequest):
    """
    Création d'une demande de remboursement.
    Corrigé + enrichissement Stripe + compatibilité invoices fallback.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(500, "Stripe n'est pas configuré sur le serveur")

    # ============================================
    # 🟦 Vérification utilisateur
    # ============================================
    is_service_call = _validate_backend_key(request)
    if not is_service_call:
        _enforce_request_origin(request)
        _require_csrf_token(request)
        session_user = await _require_user_session(request)
        user_id = session_user.get("id")
    else:
        user_id = (payload.userId or "").strip()

    if not user_id:
        raise HTTPException(400, "userId manquant")

    logger.info(
        "Refund requested user=%s invoiceId=%s raw_payload=%s",
        user_id,
        payload.invoiceId,
        payload.dict()
    )

    # ===============================================================
    # 🟦 1. Récupération de la facture (via invoiceId, paymentIntentId ou last paid)
    # ===============================================================
    invoice = None

    # a) via invoiceId
    if payload.invoiceId:
        invoice = await _fetch_invoice_record(invoice_id=payload.invoiceId, user_id=user_id)

    # b) via paymentIntentId
    if not invoice and payload.paymentIntentId:
        invoice = await _fetch_invoice_record(payment_intent_id=payload.paymentIntentId, user_id=user_id)

    # c) via dernière facture payée
    if not invoice:
        invoice = await _fetch_invoice_record(user_id=user_id, status="paid")

    if not invoice:
        invoice = await _fetch_invoice_record(user_id=user_id)

    if not invoice:
        raise HTTPException(404, "Aucune facture trouvée")

    # Vérification ownership
    invoice_owner_id = str(invoice.get("user_id") or "").strip()
    if not invoice_owner_id:
        raise HTTPException(400, "Facture invalide : aucun utilisateur associé.")
    if invoice_owner_id != str(user_id):
        raise HTTPException(403, "Cette facture ne vous appartient pas")
    user_id = invoice_owner_id  # normalisation

    # ============================================
    # 🟦 2. Vérification profil Supabase
    # ============================================
    profile_ready = await _ensure_profile_exists(
        user_id,
        email=invoice.get("customer_email"),
        full_name=invoice.get("customer_name") or invoice.get("full_name"),
    )
    if not profile_ready:
        logger.error("Impossible de garantir l'existence du profil user=%s avant le refund", user_id)
        raise HTTPException(500, "Profil utilisateur introuvable. Contactez le support.")

    # ============================================
    # 🟦 3. Préparation refund
    # ============================================
    amount_cents = invoice.get("amount_total_cents")
    if amount_cents is None:
        amount_cents = invoice.get("amount_paid")
    if amount_cents is None:
        amount_cents = invoice.get("amount_due")
    if amount_cents is None:
        amount_cents = invoice.get("total")
    if amount_cents is None:
        amount_cents = 0
    currency = (invoice.get("currency") or STRIPE_CURRENCY or "eur").upper()

    # ============================================
    # 🟦 4. Vérification qu’on n’a pas déjà une demande en attente
    # ============================================
    params = {
        "select": "id",
        "user_id": f"eq.{user_id}",
        "status": "eq.pending",
    }
    if invoice.get("id"):
        params["invoice_id"] = f"eq.{invoice.get('id')}"

    pi_for_refund = invoice.get("stripe_payment_intent_id") or payload.paymentIntentId
    if pi_for_refund:
        params["stripe_payment_intent_id"] = f"eq.{pi_for_refund}"

    existing = await _supabase_request("GET", "rest/v1/refund_requests", params=params)
    if existing:
        raise HTTPException(400, "Une demande de remboursement est déjà en attente pour cette facture.")

    # ===============================================================
    # 🟦 5. ENRICHISSEMENT STRIPE (CRITIQUE POUR REFUND)
    # ===============================================================
    if not pi_for_refund:
        raise HTTPException(400, "PaymentIntent introuvable pour cette facture")

    charge_id = invoice.get("stripe_charge_id")

    # --------------------------------
    # → PATCH CRITIQUE : récupérer latest_charge
    # --------------------------------
    if pi_for_refund and not charge_id:
        logger.info("Refund: récupération Stripe latest_charge pour PI %s", pi_for_refund)
        try:
            pi_obj = stripe.PaymentIntent.retrieve(
                pi_for_refund,
                expand=["latest_charge"]
            )
            latest_charge = pi_obj.get("latest_charge")

            if isinstance(latest_charge, dict):
                charge_id = latest_charge.get("id")
            elif latest_charge:
                charge_id = latest_charge

            if charge_id:
                logger.info("Refund: charge récupérée → %s", charge_id)
                invoice["stripe_charge_id"] = charge_id  # patch local
            else:
                logger.warning("Refund: latest_charge non trouvée pour %s", pi_for_refund)

        except Exception as exc:
            logger.warning("Refund: impossible de récupérer la charge pour PI %s: %s", pi_for_refund, exc)

    # --------------------------------
    # REFUND IMPOSSIBLE SANS charge
    # --------------------------------
    if not charge_id:
        raise HTTPException(404, "Impossible de traiter le remboursement : charge Stripe introuvable")

    # ===============================================================
    # 🟦 6. Créer la demande de remboursement Supabase
    # ===============================================================
    record = {
        "user_id": user_id,
        "invoice_id": invoice.get("id"),
        "invoice_number": invoice.get("invoice_number") or invoice.get("invoice_id"),
        "stripe_invoice_id": invoice.get("invoice_id"),
        "stripe_payment_intent_id": pi_for_refund,
        "stripe_charge_id": charge_id,
        "stripe_checkout_session_id": invoice.get("stripe_checkout_session_id"),
        "amount_cents": int(amount_cents) if amount_cents else 0,
        "currency": currency,
        "reason": payload.reason,
        "status": "pending",
    }

    created = await _supabase_request("POST", "rest/v1/refund_requests", json_payload=record)
    if not created:
        raise HTTPException(500, "Erreur lors de la création de la demande de remboursement")

    request_id = created[0].get("id") if isinstance(created, list) else created.get("id")
    logger.info("Refund request créée avec succès: %s", request_id)

    return {
        "status": "pending",
        "requestId": request_id,
    }




@app.get("/refund-requests")
async def list_refund_requests(request: Request):
    await _require_admin_user(request)
    params = {
        "select": "*,profiles:profiles(full_name,email)",
        "order": "created_at.desc",
    }
    data = await _supabase_request("GET", "rest/v1/refund_requests", params=params)
    requests = data or []
    missing_invoice_ids = {
        str(req.get("invoice_id"))
        for req in requests
        if req.get("invoice_id")
        and (req.get("amount_cents") in (None, 0) or not req.get("currency"))
    }
    if missing_invoice_ids:
        invoice_ids = ",".join(missing_invoice_ids)
        invoices = await _supabase_request(
            "GET",
            "rest/v1/invoices",
            params={
                "select": "id,amount_total_cents,currency",
                "id": f"in.({invoice_ids})",
            },
        )
        invoice_map = {str(row.get("id")): row for row in (invoices or [])}
        for req in requests:
            invoice_id = str(req.get("invoice_id")) if req.get("invoice_id") else None
            if not invoice_id:
                continue
            invoice = invoice_map.get(invoice_id)
            if not invoice:
                continue
            if req.get("amount_cents") in (None, 0):
                amount_total_cents = invoice.get("amount_total_cents")
                if amount_total_cents is not None:
                    req["amount_cents"] = amount_total_cents
            if not req.get("currency"):
                currency = invoice.get("currency")
                if currency:
                    req["currency"] = str(currency).upper()
    return {"requests": requests}

@app.post("/refund-requests/{request_id}/decision")
async def decide_refund(request_id: str, request: Request):
    _enforce_request_origin(request)
    _require_csrf_token(request)
    admin_user = await _require_admin_user(request)

    try:
        payload = RefundDecisionPayload(**(await request.json()))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Payload invalide: {exc}")

    row = await _fetch_refund_request(request_id)
    if not row:
        raise HTTPException(404, "Demande introuvable")
    if row.get("status") != "pending":
        raise HTTPException(400, "Cette demande a déjà été traitée")

    user_id = row.get("user_id")
    if not user_id:
        raise HTTPException(400, "Demande invalide (user_id manquant)")

    decided_at = datetime.utcnow().isoformat() + "Z"

    if payload.decision == 'reject':
        update = {
            "status": "rejected",
            "admin_id": admin_user.get("id"),
            "decision_reason": payload.note,
            "decided_at": decided_at,
        }
        await _supabase_request(
            "PATCH",
            "rest/v1/refund_requests",
            params={"id": f"eq.{request_id}"},
            json_payload=update,
        )
        logger.info("Refund request %s rejected by admin %s", request_id, admin_user.get("id"))

        message = "Your refund request was rejected."
        if payload.note:
            message += f" Reason: {payload.note}"
        await _supabase_request(
            "POST",
            "rest/v1/alerts",
            json_payload={
                "user_id": user_id,
                "title": "Refund request update",
                "message": message,
                "type": "system",
                "severity": "info",
                "is_read": False,
                "created_at": decided_at,
            },
        )
        return {"status": "rejected"}

    invoice = await _fetch_invoice_record(invoice_id=row.get("invoice_id"), user_id=user_id)
    if not invoice:
        raise HTTPException(404, "Facture introuvable pour ce remboursement")

    result = await _perform_stripe_refund(
        invoice,
        user_id,
        checkout_session_id=row.get("stripe_checkout_session_id"), 
        reason=row.get("reason"),
    )

    refund_status = str(result.get("status") or "").lower()
    request_status = "accepted" if refund_status == "succeeded" else "approved"

    update_payload = {
        "status": request_status,
        "admin_id": admin_user.get("id"),
        "stripe_refund_id": result.get("refundId"),
        "decision_reason": payload.note,
        "decided_at": decided_at,
    }

    await _supabase_request(
        "PATCH",
        "rest/v1/refund_requests",
        params={"id": f"eq.{request_id}"},
        json_payload=update_payload,
    )

    logger.info(
        "Refund request %s %s (refund_id=%s status=%s)",
        request_id,
        request_status,
        result.get("refundId"),
        refund_status or "unknown",
    )

    return {"status": request_status, **result}


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("stripe-signature") or ""

    try:
        event = _construct_stripe_event(payload, signature)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Stripe webhook rejeté: %s", exc)
        raise HTTPException(status_code=400, detail="Signature Stripe invalide")

    event_type = event.get("type")
    data_object = (event.get("data") or {}).get("object") or {}
    metadata = data_object.get("metadata") or {}

    logger.info(
        "Webhook Stripe reçu type=%s id=%s metadata=%s",
        event_type,
        data_object.get("id"),
        metadata,
    )
    logger.debug("Stripe webhook payload: %s", data_object)

    if not metadata:
        logger.warning(
            "Stripe webhook type=%s id=%s sans metadata",
            event_type,
            data_object.get("id"),
        )

    if event_type == "checkout.session.completed":
        await _handle_checkout_session_completed(data_object)
    elif event_type in {"invoice.payment_succeeded", "invoice_payment.paid"}:
        await _handle_invoice_payment_succeeded(data_object)
    else:
        logger.debug("Webhook Stripe type=%s ignoré", event_type)

    return {"status": "ok"}


def _reserve_free_scan_email_usage(
    email: str,
    payload: FreeScanReportRequest,
    scan_identifier: str | None,
    site_label: str | None,
) -> None:
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        raise HTTPException(status_code=400, detail="Email requis")

    metadata = {
        "email": email.strip(),
        "email_normalized": normalized_email,
        "scan_identifier": scan_identifier,
        "scan_id": payload.scan_id,
        "mongo_report_id": payload.mongo_report_id,
        "site_url": site_label,
        "created_at": datetime.utcnow(),
    }
    metadata = {key: value for key, value in metadata.items() if value is not None}

    try:
        result = free_scan_emails_collection.update_one(
            {"email_normalized": normalized_email},
            {"$setOnInsert": metadata},
            upsert=True,
        )
    except PyMongoError as exc:
        logger.error("Free scan email lookup failed for %s: %s", normalized_email, exc)
        raise HTTPException(
            status_code=500,
            detail="Impossible de vérifier cet email pour le scan gratuit. Réessayez plus tard.",
        )

    if result.upserted_id is None:
        raise HTTPException(
            status_code=403,
            detail="This email already used the free scan. Please sign in or sign up to continue.",
        )


@app.get("/generate-report/{scan_id}")
async def generate_report(
    scan_id: str,
    request: Request,
    report_format: str = Query("pdf", pattern="^(pdf|json|xlsx)$")
):
    try:
        scan = get_scan_from_mongo(scan_id)
        scan = convert_objectid(scan) if scan else None
        if not scan:
            raise HTTPException(status_code=404, detail="Scan non trouvé.")

        file_io, media_type, filename = await _generate_report_file(scan, request, report_format)

        return StreamingResponse(
            file_io,
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur génération rapport : {e}")


@app.get("/generate-report-zap/{scan_id}")
async def generate_report_zap(
    scan_id: str,
    request: Request,
):
    try:
        scan = get_scan_from_mongo(scan_id)
        scan = convert_objectid(scan) if scan else None
        if not scan:
            raise HTTPException(status_code=404, detail="Scan non trouvé.")

        cms = (scan.get("cms_type") or "").lower()
        if cms not in {"drupal", "prestashop"}:
            raise HTTPException(status_code=400, detail="Rapport ZAP réservé à Drupal/PrestaShop.")

        zap_data = scan.get("zap_scan") or {}
        context = {
            "request": request,
            "scan": scan,
            "zap_scan": zap_data if isinstance(zap_data, dict) else {},
        }
        html = templates.get_template("rapport_drupal_zap_only.html").render(context)
        pdf_io = BytesIO()
        HTML(string=html, base_url=str(request.base_url)).write_pdf(pdf_io)
        pdf_io.seek(0)
        filename = f"rapport_zap_{cms}_{scan.get('scan_id') or scan_id}.pdf"

        return StreamingResponse(
            pdf_io,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur génération rapport ZAP : {e}")


@app.post("/free-scan/send-report")
async def send_free_scan_report(request: Request, payload: FreeScanReportRequest):
    if not payload.email:
        raise HTTPException(status_code=400, detail="Email requis")
    report_format = (payload.report_format or "pdf").lower()
    if report_format != "pdf":
        raise HTTPException(status_code=400, detail="Seul le format PDF est supporté pour l'envoi automatique.")

    identifier = payload.mongo_report_id or payload.scan_id
    if not identifier:
        raise HTTPException(status_code=400, detail="scan_id ou mongo_report_id requis pour envoyer le rapport.")

    scan = get_scan_from_mongo(identifier, include_preview=True)
    scan = convert_objectid(scan) if scan else None
    if not scan:
        raise HTTPException(status_code=404, detail="Scan gratuit introuvable.")

    site_label = (
        payload.site_url
        or scan.get("target_url")
        or scan.get("site_url")
        or scan.get("url")
        or "votre site"
    )
    _reserve_free_scan_email_usage(payload.email, payload, identifier, site_label)

    try:
        pdf_io, media_type, filename = await _generate_report_file(scan, request, report_format)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Impossible de générer le rapport: {exc}") from exc

    pdf_bytes = pdf_io.getvalue()
    severity_counts, highest_risk = compute_vulnerability_summary(scan)
    cms_value = payload.display_cms or scan.get("cms_type") or ""
    cms_label = cms_value.capitalize() if cms_value and cms_value.lower() not in CMS_UNKNOWN_VALUES else "Inconnu"
    risk_label = payload.display_risk or (highest_risk.capitalize() if highest_risk else "Non déterminé")

    severity_lines = "".join(
        f"<li>{sev.capitalize()} : <strong>{severity_counts.get(sev, 0)}</strong></li>" for sev in SEVERITY_ORDER
    )

    risk_class_map = {
        "critical": "risk-critical",
        "high": "risk-high",
        "medium": "risk-medium",
        "low": "risk-low",
    }
    risk_class = risk_class_map.get((highest_risk or "").lower(), "risk-low")
    app_url = (
        os.environ.get("NEXT_PUBLIC_SITE_URL")
        or os.environ.get("NEXT_PUBLIC_APP_URL")
        or "https://cyberscan.fr"
    )
    report_scan_id = scan.get("scan_id") or payload.scan_id
    base_url = str(request.base_url).rstrip("/")
    download_url = (
        f"{base_url}/generate-report/{report_scan_id}?report_format=pdf"
        if report_scan_id
        else None
    )
    html_body = f"""
        <html>
        <head>
        <style>
          body {{
            font-family: sans-serif;
            line-height: 1.6;
            color: #333;
          }}
          .container {{
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
          }}
          .header {{
            text-align: center;
            margin-bottom: 20px;
          }}
          .header h1 {{
            color: #333;
          }}
          .risk-level {{
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            font-weight: bold;
            color: #fff;
            font-size: 1.1em;
          }}
          .risk-critical {{ background-color: #b91c1c; }}
          .risk-high {{ background-color: #dc2626; }}
          .risk-medium {{ background-color: #f97316; }}
          .risk-low {{ background-color: #16a34a; }}
          .summary-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
          }}
          .summary-table th, .summary-table td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
          }}
          .icon {{
            font-size: 1.2em;
            vertical-align: middle;
            margin-right: 8px;
          }}
          .button-container {{
              text-align: center;
              margin-top: 30px;
          }}
          .button {{
              background-color: #007bff;
              color: #ffffff !important;
              padding: 12px 24px;
              text-decoration: none;
              border-radius: 5px;
              font-weight: bold;
              display: inline-block;
              margin: 5px;
          }}
          .button-secondary {{
              background-color: #16a34a;
              color: #ffffff !important;
          }}
          .footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 0.9em;
            color: #777;
          }}
        </style>
        </head>
        <body>
        <div class="container">
          <div class="header">
            <h1>Cybersecurity Analysis Report</h1>
          </div>
          <p>Hello,</p>
          <p>Here are the results of the cybersecurity analysis you requested for the website <strong>{site_label}</strong>.</p>

          <h2>Overall Risk Level</h2>
          <div class="risk-level {risk_class}">{risk_label}</div>

          <h2>Site Information</h2>
          <p><strong>URL:</strong> {site_label}<br>
          <strong>Detected CMS:</strong> {cms_label}</p>

          <h2>Vulnerability Summary</h2>
          <table class="summary-table">
            <tr>
              <th>Risk Level</th>
              <th>Number of Vulnerabilities</th>
            </tr>
            <tr>
              <td><span class="icon">🟢</span>Low</td>
              <td>{severity_counts.get("low", 0)}</td>
            </tr>
            <tr>
              <td><span class="icon">🟠</span>Medium</td>
              <td>{severity_counts.get("medium", 0)}</td>
            </tr>
            <tr>
              <td><span class="icon">🔴</span>High</td>
              <td>{severity_counts.get("high", 0)}</td>
            </tr>
            <tr>
              <td><span class="icon">⚫</span>Critical</td>
              <td>{severity_counts.get("critical", 0)}</td>
            </tr>
          </table>

          <p>The detailed PDF report is attached. Download it for the full remediation recommendations.</p>

          <div class="button-container">
              {
                  f'<a href="{download_url}" class="button" style="color:#ffffff !important;">Download report</a>'
                  if download_url
                  else ""
              }
              <a href="https://app.cybershield.cloud/fr/auth/signup" class="button button-secondary" style="color:#ffffff !important;">Protect Your Website with CyberShield</a>
          </div>

          <div class="footer">
            <p>The CyberScan Team</p>
          </div>
        </div>
        </body>
        </html>
    """
    text_body = (
        f"CyberScan report for {site_label}\n"
        f"Risk: {risk_label}\n"
        f"CMS: {cms_label}\n"
        + " / ".join(f"{sev}:{severity_counts.get(sev, 0)}" for sev in SEVERITY_ORDER)
    )

    try:
        await asyncio.to_thread(
            _send_smtp_email,
            f"CyberScan — Free scan report for {site_label}",
            payload.email,
            html_body.strip(),
            text_body,
            [
                {
                    "filename": filename,
                    "content": pdf_bytes,
                    "content_type": media_type,
                }
            ],
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"message": "Rapport envoyé par email."}


def clean_url(url):
    url = str(url).strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme in ["http", "https"] and bool(parsed.netloc)
    except Exception:
        return False
    
# === ROUTE MULTI RAPPORT PDF new ===
@app.post("/generate-multi-report")
async def generate_multi_report(request: Request, data: MultiReportRequest = Body(...)):
    scan_ids = data.scan_ids
    if not scan_ids:
        raise HTTPException(status_code=400, detail="Liste de scan_id vide.")

    zip_io = io.BytesIO()
    with zipfile.ZipFile(zip_io, mode="w") as zf:
        for scan_id in scan_ids:
            # Recherche scan
            scan = (
                scan_drupal_collection.find_one({"scan_id": scan_id}) or
                scan_wp_collection.find_one({"scan_id": scan_id}) or
                scan_presta_collection.find_one({"scan_id": scan_id}) or
                scan_generic_collection.find_one({"scan_id": scan_id})
            )
            if not scan:
                continue
            scan = convert_objectid(scan)

            cms = scan.get("cms_type", "").lower()
            mode = scan.get("mode", "light")
            zap_data = scan.get("zap_scan", {})

            # === Cas PrestaShop + Drupal (CVEs internes) ===
            if cms in ["drupal", "prestashop"]:
                template_name = "rapport_drupal.html"
                cves = scan.get("cms_scan", {}).get("cves", [])
                severity_counts = {
                    "CRITICAL": len([c for c in cves if c.get("severity") == "CRITICAL"]),
                    "HIGH": len([c for c in cves if c.get("severity") == "HIGH"]),
                    "MEDIUM": len([c for c in cves if c.get("severity") == "MEDIUM"]),
                    "LOW": len([c for c in cves if c.get("severity") == "LOW"]),
                    "INFO": len([c for c in cves if c.get("severity") == "INFO"]),
                }
                total = sum(severity_counts.values()) or 1

                context = {
                    "request": request,
                    "scan": scan,
                    "cms_scan": scan.get("cms_scan"),
                    "nuclei_scan": scan.get("nuclei_scan"),
                    "zap_scan": zap_data,
                    "critical_count": severity_counts["CRITICAL"],
                    "high_count": severity_counts["HIGH"],
                    "medium_count": severity_counts["MEDIUM"],
                    "low_count": severity_counts["LOW"],
                    "info_count": severity_counts["INFO"],
                    "critical_width": severity_counts["CRITICAL"] / total * 100,
                    "high_width": severity_counts["HIGH"] / total * 100,
                    "medium_width": severity_counts["MEDIUM"] / total * 100,
                    "low_width": severity_counts["LOW"] / total * 100,
                    "info_width": severity_counts["INFO"] / total * 100,
                }

            # === Cas WordPress + Inconnu ===
            elif cms in ["wordpress", "inconnu"]:
                template_name = "report_template.html"
                context = {
                    "request": request,
                    "scan": scan,
                    "cms_scan": scan.get("cms_scan"),
                    "nuclei_scan": scan.get("nuclei_scan"),
                    "zap_scan": zap_data,
                }

            else:
                continue  # CMS non supporté

            # Rendu HTML + PDF en mémoire
            html = templates.get_template(template_name).render(context)
            pdf_io = io.BytesIO()
            HTML(string=html, base_url=str(request.base_url)).write_pdf(pdf_io)
            pdf_io.seek(0)

            # Nom fichier PDF (inclut cms + mode + scan_id)
            pdf_filename = f"rapport_{cms}_{mode}_{scan_id}.pdf"

            # Ajout au ZIP
            zf.writestr(pdf_filename, pdf_io.read())

    zip_io.seek(0)
    return StreamingResponse(
        zip_io,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": 'attachment; filename="multi_report.zip"'}
    )


@app.get("/scan-history")
async def get_scan_history(limit: int = Query(20, ge=1, le=100)):
    try:
        collections = ["scan_wordpress", "scan_prestashop", "scan_drupal", "scan_generic"]
        all_scans = []

        for col in collections:
            scans = list(
                db[col].find(
                    {},
                    {
                        "_id": 1,
                        "scan_id": 1,
                        "target_url": 1,
                        "cms_type": 1,
                        "mode": 1,
                        "scan_time": 1,
                        "created_at": 1,
                    }
                )
            )
            all_scans.extend(scans)

        # Tri global par date décroissante
        all_scans.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        return {"count": len(all_scans[:limit]), "history": convert_objectid(all_scans[:limit])}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur récupération historique: {e}")


@app.get("/scan-report/{scan_id}")
async def get_scan_report(scan_id: str):
    """
    Retourne le rapport complet d'un scan.
    """
    scan = get_scan_from_mongo(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    return convert_objectid(scan)

@app.get("/test-stream")
async def test_stream():
    async def event_stream():
        for i in range(5):
            yield f"data: message {i}\n\n"  # format SSE
            await asyncio.sleep(1)
        yield "data: [DONE]\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")

# === ROUTES SCAN ===
app.include_router(scan_router)
app.include_router(medianet_router)
app.include_router(zap_router)  

# === ROUTES SANDBOX ===
if sandbox_router:
    app.include_router(sandbox_router, prefix="/sandbox", tags=["sandbox"])
else:
    logger.info("Sandbox API routes not registered (dependency missing).")

# Handle the domain analyzer Flask app
flask_analyzer_wsgi_app = None
try:
    from domainAnalyzer.app import app as flask_analyzer_app
    from flask.app import Flask
    from werkzeug.middleware.proxy_fix import ProxyFix

    if not isinstance(flask_analyzer_app, Flask):
        raise TypeError("Expected Flask application instance")

    flask_analyzer_app.wsgi_app = ProxyFix(
        flask_analyzer_app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_prefix=1
    )

    flask_analyzer_wsgi_app = WSGIMiddleware(flask_analyzer_app)

except Exception as e:
    print(f"[ERROR] Could not prepare domain analyzer app: {e}")
    raise

# Initialize Socket.IO server separately
try:
    import socketio

    sio = socketio.AsyncServer(
        async_mode='asgi',
        cors_allowed_origins='*',
        logger=True,
        engineio_logger=True
    )

    def build_socket_app(other_app=None):
        return socketio.ASGIApp(
            sio,
            socketio_path="socket.io",
            other_asgi_app=other_app
        )

    async def analyzer_fallback(scope, receive, send):
        # Domain analyzer only knows HTTP; reject other protocols explicitly
        if scope["type"] != "http":
            await PlainTextResponse("Not found", status_code=404)(scope, receive, send)
            return
        await flask_analyzer_wsgi_app(scope, receive, send)

    # Ensure the main Socket.IO endpoints are available
    for path in ["/socket.io", "/api/socket.io"]:
        app.mount(path, build_socket_app())

    # Mount analyzer paths with the Flask app as fallback for non-Socket.IO routes
    if flask_analyzer_wsgi_app:
        analyzer_socket_app = build_socket_app(analyzer_fallback)
        for path in ["/analyzer", "/api/analyzer"]:
            app.mount(path, analyzer_socket_app)
        print("[INFO] Successfully mounted analyzer with integrated Socket.IO support")
    else:
        print("[WARN] Flask analyzer app unavailable; Socket.IO analyzer routes not mounted")

    @sio.event
    async def connect(sid, environ):
        print(f"[Socket.IO] Client connected: {sid}")

    @sio.event
    async def disconnect(sid):
        print(f"[Socket.IO] Client disconnected: {sid}")

except Exception as e:
    print(f"[WARN] Could not initialize Socket.IO server: {e}")
    if flask_analyzer_wsgi_app:
        for path in ["/analyzer", "/api/analyzer"]:
            app.mount(path, analyzer_fallback)
        print("[INFO] Analyzer mounted without Socket.IO support")

# === ADMIN: SUPPRESSION COMPLÈTE UTILISATEUR ===

async def _delete_supabase_auth_user(user_id: str):
    """
    Supprime l'utilisateur dans Supabase Auth via l'API Admin.
    """
    SUPABASE_URL = os.environ.get("SUPABASE_URL")
    SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

    if not SUPABASE_URL or not SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase non configuré sur le serveur")

    admin_url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/admin/users/{user_id}"
    headers = {
        "apikey": SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SERVICE_ROLE_KEY}",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.delete(admin_url, headers=headers)

    if response.status_code not in (200, 204):
        raise HTTPException(status_code=response.status_code, detail=f"Erreur Supabase Auth: {response.text}")

    return True


async def _verify_admin_request(request: Request):
    """
    Vérifie que la requête provient d'un admin (JWT Supabase ou clé BACKEND_API_KEY).
    """
    if _validate_backend_key(request):
        return True

    token = _extract_bearer_token(request.headers.get("authorization"))
    if not token:
        token = request.cookies.get("sb-access-token")
    if not token:
        raise HTTPException(status_code=401, detail="Token d'authentification manquant")

    user = await _fetch_supabase_user(token)
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur non trouvé")

    role = user.get("app_metadata", {}).get("role") or user.get("user_metadata", {}).get("role")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Accès refusé : rôle admin requis")

    return True


@app.post("/admin/delete-user")
async def delete_user(request: Request, body: dict = Body(...)):
    """
    Supprime complètement un utilisateur :
    - Auth Supabase
    - Données liées (profiles, subscriptions, credits, alerts)
    """
    await _verify_admin_request(request)

    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id manquant")

    logger.info(f"🧹 Suppression complète demandée pour user_id={user_id}")

    # Étape 1 : supprimer les données liées
    tables = ["subscriptions", "credits", "alerts", "profiles"]
    for table in tables:
        try:
            await _supabase_request("DELETE", f"rest/v1/{table}", params={"user_id": f"eq.{user_id}"})
            logger.info(f"✅ {table} supprimé pour user {user_id}")
        except Exception as e:
            logger.warning(f"⚠️ Erreur suppression {table}: {e}")

    # Étape 2 : supprimer dans Auth
    try:
        await _delete_supabase_auth_user(user_id)
        logger.info(f"✅ Utilisateur Auth {user_id} supprimé")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur Supabase Auth: {e}")


@app.get("/admin/medianet-usage")
async def get_admin_medianet_usage(
    request: Request,
    days: int = Query(30, ge=1, le=365),
):
    """
    Retourne la consommation quotidienne de l'API Medianet (scans MongoDB).
    """
    await _verify_admin_request(request)

    daily_limit: int | None = None
    raw_limit = os.environ.get("MEDIANET_DAILY_LIMIT")
    if raw_limit:
        try:
            daily_limit = int(raw_limit)
            if daily_limit < 0:
                daily_limit = None
        except ValueError:
            daily_limit = None

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days - 1)
    start_day = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_day = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)

    try:
        collection = db["scan_medianet"]
        pipeline = [
            {"$match": {"created_at": {"$gte": start_day, "$lte": end_day}}},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$created_at",
                            "timezone": "UTC",
                        }
                    },
                    "count": {"$sum": 1},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        aggregated = list(collection.aggregate(pipeline))
    except PyMongoError as exc:
        logger.error("Erreur chargement consommation Medianet: %s", exc)
        raise HTTPException(status_code=500, detail="Erreur MongoDB lors du chargement Medianet")

    counts_by_day = {
        entry.get("_id"): int(entry.get("count", 0))
        for entry in aggregated
        if isinstance(entry, dict) and entry.get("_id")
    }

    series = []
    total = 0
    for i in range(days):
        day = start_day + timedelta(days=i)
        key = day.strftime("%Y-%m-%d")
        count = counts_by_day.get(key, 0)
        total += count
        if daily_limit is None:
            in_plan = count
            over_limit = 0
        else:
            in_plan = min(count, daily_limit)
            over_limit = max(count - daily_limit, 0)
        series.append(
            {
                "date": key,
                "count": count,
                "in_plan": in_plan,
                "over_limit": over_limit,
            }
        )

    return {
        "range_days": days,
        "limit": daily_limit,
        "total": total,
        "series": series,
    }


@app.get("/admin/medianet-dehashed-usage")
async def get_admin_medianet_dehashed_usage(
    request: Request,
    days: int = Query(30, ge=1, le=365),
):
    """
    Retourne la consommation quotidienne de l'API DeHashed (Medianet).
    """
    await _verify_admin_request(request)

    daily_limit: int | None = None
    raw_limit = os.environ.get("MEDIANET_DEHASHED_DAILY_LIMIT")
    if raw_limit:
        try:
            daily_limit = int(raw_limit)
            if daily_limit < 0:
                daily_limit = None
        except ValueError:
            daily_limit = None

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days - 1)
    start_day = start_date.replace(hour=0, minute=0, second=0, microsecond=0)

    day_keys: list[str] = []
    for i in range(days):
        day = start_day + timedelta(days=i)
        day_keys.append(day.strftime("%Y-%m-%d"))

    try:
        collection = db["medianet_dehashed_usage"]
        docs = list(collection.find({"_id": {"$in": day_keys}}, {"count": 1}))
    except PyMongoError as exc:
        logger.error("Erreur chargement consommation DeHashed Medianet: %s", exc)
        raise HTTPException(status_code=500, detail="Erreur MongoDB lors du chargement DeHashed")

    counts_by_day = {
        doc.get("_id"): int(doc.get("count", 0))
        for doc in docs
        if isinstance(doc, dict) and doc.get("_id")
    }

    series = []
    total = 0
    for key in day_keys:
        count = counts_by_day.get(key, 0)
        total += count
        if daily_limit is None:
            in_plan = count
            over_limit = 0
        else:
            in_plan = min(count, daily_limit)
            over_limit = max(count - daily_limit, 0)
        series.append(
            {
                "date": key,
                "count": count,
                "in_plan": in_plan,
                "over_limit": over_limit,
            }
        )

    return {
        "range_days": days,
        "limit": daily_limit,
        "total": total,
        "series": series,
    }


@app.get("/admin/medianet-sites")
async def get_admin_medianet_sites(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(25, ge=1, le=200),
):
    """
    Retourne les sites scannés par Medianet sur la période.
    """
    await _verify_admin_request(request)

    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days - 1)
    start_day = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_day = end_date.replace(hour=23, minute=59, second=59, microsecond=999999)

    try:
        collection = db["scan_medianet"]
        cursor = (
            collection.find(
                {"created_at": {"$gte": start_day, "$lte": end_day}},
                {"target_url": 1, "site_url": 1, "url": 1, "created_at": 1, "mode": 1, "risk_level": 1},
            )
            .sort("created_at", -1)
            .limit(limit)
        )

        sites: list[dict[str, str | None]] = []
        for entry in cursor:
            if not isinstance(entry, dict):
                continue
            url = entry.get("target_url") or entry.get("site_url") or entry.get("url")
            if not url:
                continue
            created_at = entry.get("created_at")
            scanned_at = None
            if isinstance(created_at, datetime):
                scanned_at = created_at.replace(microsecond=0).isoformat() + "Z"
            mode = entry.get("mode")
            risk_level = entry.get("risk_level")
            sites.append({"url": url, "scanned_at": scanned_at, "mode": mode, "risk_level": risk_level})
    except PyMongoError as exc:
        logger.error("Erreur chargement sites Medianet: %s", exc)
        raise HTTPException(status_code=500, detail="Erreur MongoDB lors du chargement Medianet")

    return {
        "range_days": days,
        "limit": limit,
        "sites": sites,
    }


@app.get("/admin/scan-logs")
async def get_admin_scan_logs(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    user_id: str | None = Query(None),
    search: str | None = Query(None, description="Filtrer par URL"),
):
    """
    Retourne les logs de scans (visible uniquement par un admin).
    """
    await _verify_admin_request(request)

    params: dict[str, str] = {
        "select": "*",
        "order": "triggered_at.desc",
        "limit": str(limit),
    }
    if user_id:
        params["user_id"] = f"eq.{user_id}"
    if search:
        params["target_url"] = f"ilike.%{search}%"

    logs = await _supabase_request("GET", "rest/v1/scan_logs", params=params)
    logs = logs or []

    try:
        scan_ids = []
        for log in logs:
            if isinstance(log, dict):
                scan_id = log.get("scan_id")
                if scan_id:
                    scan_ids.append(str(scan_id))

        if scan_ids:
            unique_scan_ids = list(dict.fromkeys(scan_ids))
            risk_by_scan_id: dict[str, str | None] = {}

            try:
                scans = await _supabase_request(
                    "GET",
                    "rest/v1/scans",
                    params={
                        "select": "id,backend_scan_id,risk_level",
                        "backend_scan_id": f"in.({','.join(unique_scan_ids)})",
                    },
                )
            except Exception as exc:
                scans = []
                logger.warning("Scan log risk lookup failed (backend_scan_id): %s", exc)

            for scan in scans or []:
                if not isinstance(scan, dict):
                    continue
                risk = scan.get("risk_level")
                backend_scan_id = scan.get("backend_scan_id")
                if backend_scan_id:
                    risk_by_scan_id[str(backend_scan_id)] = risk
                scan_id = scan.get("id")
                if scan_id:
                    risk_by_scan_id[str(scan_id)] = risk

            missing = [scan_id for scan_id in unique_scan_ids if scan_id not in risk_by_scan_id]
            if missing:
                uuid_re = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
                uuid_ids = [scan_id for scan_id in missing if uuid_re.match(scan_id)]
                if uuid_ids:
                    try:
                        scans = await _supabase_request(
                            "GET",
                            "rest/v1/scans",
                            params={
                                "select": "id,risk_level",
                                "id": f"in.({','.join(uuid_ids)})",
                            },
                        )
                    except Exception as exc:
                        scans = []
                        logger.warning("Scan log risk lookup failed (id): %s", exc)
                    for scan in scans or []:
                        if not isinstance(scan, dict):
                            continue
                        scan_id = scan.get("id")
                        if scan_id:
                            risk_by_scan_id[str(scan_id)] = scan.get("risk_level")

            if risk_by_scan_id:
                for log in logs:
                    if not isinstance(log, dict):
                        continue
                    scan_id = log.get("scan_id")
                    if scan_id and log.get("risk_level") is None:
                        log["risk_level"] = risk_by_scan_id.get(str(scan_id))

            missing_risk = [
                log.get("scan_id")
                for log in logs
                if isinstance(log, dict) and log.get("scan_id") and not log.get("risk_level")
            ]
            if missing_risk:
                for scan_id in dict.fromkeys(missing_risk):
                    try:
                        scan = get_scan_from_mongo(str(scan_id))
                    except Exception:
                        scan = None
                    if not isinstance(scan, dict):
                        continue
                    risk = scan.get("risk_level")
                    if not risk:
                        counts = scan.get("severity_counts")
                        if isinstance(counts, dict):
                            for level in ("critical", "high", "medium", "low"):
                                if counts.get(level):
                                    risk = level
                                    break
                    if risk:
                        risk_by_scan_id[str(scan_id)] = risk

                if risk_by_scan_id:
                    for log in logs:
                        if not isinstance(log, dict):
                            continue
                        scan_id = log.get("scan_id")
                        if scan_id and log.get("risk_level") is None:
                            log["risk_level"] = risk_by_scan_id.get(str(scan_id))
    except Exception as exc:
        logger.warning("Scan log risk enrichment skipped: %s", exc)

    return {"count": len(logs), "logs": logs}

    # Étape 3 : confirmation
    return {"status": "success", "message": f"Utilisateur {user_id} supprimé avec succès."}



# === LANCEMENT LOCAL UVICORN ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
