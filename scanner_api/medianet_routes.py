import os
import uuid
import json
import logging
from datetime import datetime
from io import BytesIO
from typing import Any, Awaitable, Callable, List, Sequence, Type

import httpx
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Body
from fastapi.responses import StreamingResponse
from openpyxl import Workbook
from pydantic import BaseModel
from pymongo import ReturnDocument
from pymongo.errors import PyMongoError
from weasyprint import HTML
from dotenv import load_dotenv

from DB.database import db
from scanner_api.utils import convert_objectid, validate_scan_target

# =========================================================
# 🔐 LOAD ENV (IMPORTANT)
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ⚠️ Ajuste si ce fichier est dans scanner_api/
load_dotenv(os.path.join(BASE_DIR, "..", ".env"))

logger = logging.getLogger(__name__)

MEDIANET_DEHASHED_USAGE_COLLECTION = "medianet_dehashed_usage"

def _read_env_int(name: str, default: int, min_value: int | None = None) -> int:
    raw_value = os.environ.get(name)
    try:
        value = int(raw_value) if raw_value is not None else default
    except (TypeError, ValueError):
        value = default
    if min_value is not None and value < min_value:
        return min_value
    return value

MEDIANET_REDIS_URL = os.environ.get("MEDIANET_REDIS_URL", "redis://localhost:6379/0")
MEDIANET_QUEUE_NAME = os.environ.get("MEDIANET_QUEUE_NAME", "medianet:scan_jobs")
MEDIANET_MAX_COMPLETE_SCANS = _read_env_int("MEDIANET_MAX_COMPLETE_SCANS", 5, min_value=1)
MEDIANET_MAX_LIGHT_SCANS = _read_env_int("MEDIANET_MAX_LIGHT_SCANS", 200, min_value=1)

# =========================================================
# 🔐 AUTH MEDIANET
# =========================================================

def verify_medianet_api_key(
    x_medianet_api_key: str | None = Header(None, alias="X-Medianet-Api-Key"),
    authorization: str | None = Header(None),
) -> bool:
    """
    Authenticate requests using MEDIANET_API_KEY
    Accepts:
      - X-Medianet-Api-Key
      - Authorization: Bearer <key>
    """

    expected = os.environ.get("MEDIANET_API_KEY")

    if not expected:
        logger.error("❌ MEDIANET_API_KEY not configured")
        raise HTTPException(status_code=500, detail="Medianet API key is not configured")

    if x_medianet_api_key == expected:
        return True

    if authorization:
        try:
            _, token = authorization.split(" ", 1)
        except ValueError:
            token = authorization

        if token == expected:
            return True

    raise HTTPException(status_code=403, detail="Invalid or missing Medianet API key")

# =========================================================
# 🚀 ROUTER
# =========================================================

medianet_router = APIRouter(
    prefix="/Medianet",
    tags=["Medianet"],
    dependencies=[Depends(verify_medianet_api_key)],
)

# =========================================================
# 🔎 DEHASHED (MEDIANET)
# =========================================================

class DehashedQueryPayload(BaseModel):
    query: str | None = None


def _medianet_dehashed_daily_limit() -> int | None:
    raw_limit = os.environ.get("MEDIANET_DEHASHED_DAILY_LIMIT")
    if not raw_limit:
        return None
    try:
        limit = int(raw_limit)
    except ValueError:
        return None
    if limit < 0:
        return None
    return limit


def _consume_medianet_dehashed_quota(limit: int | None) -> tuple[int | None, int | None]:
    if limit is None:
        return None, None

    day_key = datetime.utcnow().strftime("%Y-%m-%d")
    collection = db[MEDIANET_DEHASHED_USAGE_COLLECTION]

    try:
        doc = collection.find_one_and_update(
            {"_id": day_key, "count": {"$lt": limit}},
            {
                "$inc": {"count": 1},
                "$setOnInsert": {"created_at": datetime.utcnow()},
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
    except PyMongoError as exc:
        logger.error("Medianet DeHashed quota check failed: %s", exc)
        raise HTTPException(status_code=500, detail="Medianet usage tracking unavailable")

    if not doc:
        try:
            current = collection.find_one({"_id": day_key}, {"count": 1})
            current_count = int(current.get("count", limit)) if current else limit
        except PyMongoError:
            current_count = limit
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Medianet daily limit reached",
                "limit": limit,
                "count": current_count,
            },
        )

    return limit, int(doc.get("count", 0))


from urllib.parse import urlparse
import re

def normalize_dehashed_query(raw: str) -> str:
    """
    Normalise l'entrée utilisateur vers une query DeHashed valide
    """
    raw = raw.strip()

    # Email explicite
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", raw):
        return f"email:{raw.lower()}"

    # URL complète
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        domain = parsed.hostname or ""
        domain = domain.lower().replace("www.", "")
        if not domain:
            raise HTTPException(status_code=400, detail="Invalid URL provided")
        return f"domain:{domain}"

    # Domaine simple (medianet.tn)
    if "." in raw and "/" not in raw:
        return f"domain:{raw.lower().replace('www.', '')}"

    # Fallback (recherche libre – autorisée mais contrôlée)
    return raw


@medianet_router.api_route("/check-domain", methods=["GET", "POST"])
async def medianet_dehashed_search(
    query: str | None = Query(None),
    payload: DehashedQueryPayload | None = Body(None),
):
    raw_query = query or (payload.query if payload else None)

    if not raw_query:
        raise HTTPException(status_code=400, detail="Missing query parameter")

    # 🔹 Normalisation SAFE
    try:
        normalized_query = normalize_dehashed_query(raw_query)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Query normalization failed: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid query format")

    api_key = os.environ.get("DEHASHED_API_KEY") or os.environ.get("DEHASHED_APIKEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="DeHashed API key not configured")

    # 🔹 Quota journalier
    limit = _medianet_dehashed_daily_limit()
    limit_value, current_count = _consume_medianet_dehashed_quota(limit)

    headers = {
        "Content-Type": "application/json",
        "Dehashed-Api-Key": api_key,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                "https://api.dehashed.com/v2/search",
                json={"query": normalized_query},
                headers=headers,
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="DeHashed API timeout")
    except httpx.RequestError as exc:
        logger.error("DeHashed request error: %s", exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "DeHashed API request failed", "message": str(exc)},
        )

    if response.status_code >= 400:
        try:
            details = response.json()
        except ValueError:
            details = response.text
        logger.error("DeHashed API error %s: %s", response.status_code, details)
        raise HTTPException(
            status_code=response.status_code,
            detail={"error": "DeHashed API failed", "details": details},
        )

    try:
        data = response.json()
    except ValueError:
        raise HTTPException(status_code=502, detail="Invalid JSON from DeHashed")

    result = {
        "success": True,
        "query": normalized_query,
        "data": data,
    }

    if limit_value is not None:
        result["usage"] = {
            "count": current_count,
            "limit": limit_value,
        }

    return result


# =========================================================
# 🚀 SCAN AUTO
# =========================================================

def register_medianet_scan_route(
    *,
    router: APIRouter | None = None,
    site_detect_model: Type[BaseModel],
    fetch_html_fn: Callable[[str], Awaitable[tuple[Any, str | None, Any, Any]]],
    detect_cms_with_model_fn: Callable[[str, str | None, Any, Any], str | None],
    detect_cms_from_html_fn: Callable[[str | None, Any | None], str | None],
    scan_sites_fn: Callable[..., Awaitable[List[dict[str, Any]]]],
    extract_request_ip_fn: Callable[[Request | None], str | None],
) -> None:

    router = router or medianet_router
    class MedianetSiteDetect(site_detect_model):  # type: ignore[misc]
        callback_url: str | None = None
        network_scan: bool | str | None = None


    def _normalize_medianet_mode(mode_value: str | None) -> str:
        normalized = (mode_value or "light").strip().lower()
        if normalized in {"full", "complete"}:
            return "complete"
        return "light"

    def _count_running(mode: str) -> int:
        return db["scan_medianet"].count_documents({
            "status": "running",
            "mode": mode,
        })

    async def _enqueue_jobs(jobs: list[dict[str, Any]]) -> None:
        try:
            import redis.asyncio as redis  # type: ignore
        except Exception as exc:
            logger.exception("Redis client not available for Medianet queue")
            raise HTTPException(status_code=500, detail="Redis client is not configured") from exc

        client = redis.from_url(MEDIANET_REDIS_URL, decode_responses=True)
        try:
            for job in jobs:
                await client.rpush(MEDIANET_QUEUE_NAME, json.dumps(job))
        finally:
            await client.close()

    def _collect_vulnerabilities(payload: dict[str, Any]) -> list[dict[str, Any]]:
        collected: list[dict[str, Any]] = []

        cms_scan = payload.get("cms_scan") or {}
        if isinstance(cms_scan, dict):
            for cve in cms_scan.get("cves", []) or []:
                if not isinstance(cve, dict):
                    continue
                references = cve.get("references") or {}
                identifier = (
                    cve.get("cve_id")
                    or references.get("cve")
                    or (references.get("cve_id") if isinstance(references, dict) else None)
                )
                collected.append(
                    {
                        "severity": (cve.get("severity") or "").lower(),
                        "title": cve.get("title") or cve.get("name"),
                        "identifier": identifier,
                        "details": cve.get("description"),
                    }
                )

        nuclei_scan = payload.get("nuclei_scan") or {}
        parsed_results = nuclei_scan.get("parsed_results") if isinstance(nuclei_scan, dict) else None
        for entry in parsed_results or []:
            if not isinstance(entry, dict):
                continue
            collected.append(
                {
                    "severity": (entry.get("severity") or "").lower(),
                    "title": entry.get("name"),
                    "identifier": entry.get("id") or entry.get("template_id"),
                    "details": entry.get("description") or entry.get("info"),
                }
            )

        zap_scan = payload.get("zap_scan") or {}
        for alert in zap_scan.get("alerts", []) or []:
            if not isinstance(alert, dict):
                continue
            collected.append(
                {
                    "severity": (alert.get("risk") or alert.get("severity") or "").lower(),
                    "title": alert.get("name"),
                    "identifier": alert.get("cweid") or alert.get("pluginid"),
                    "details": alert.get("description"),
                    "remediation": alert.get("solution"),
                }
            )

        return collected

    @router.post("/scan-auto")
    async def medianet_scan_auto(
       request: Request,
       sites: List[MedianetSiteDetect],
    ):
       if not sites:
         raise HTTPException(status_code=400, detail="Liste des sites vide")

       callback_header = request.headers.get("x-callback-url")
       client_ip = extract_request_ip_fn(request)
       report_base_url = os.environ.get("MEDIANET_REPORT_BASE_URL") or str(request.base_url).rstrip("/")

       scan_ids: list[str] = []
       jobs: list[dict[str, Any]] = []
       normalized_modes: list[str] = []

       for entry in sites:
          url_str = str(entry.url)
          allowed, reason = validate_scan_target(url_str)
          if not allowed:
             raise HTTPException(status_code=400, detail=f"URL '{url_str}' refusée: {reason}")

          scan_id = str(uuid.uuid4())
          mode_value = _normalize_medianet_mode(getattr(entry, "mode", None))
          normalized_modes.append(mode_value)

          callback_url = getattr(entry, "callback_url", None) or callback_header

          jobs.append({
             "scan_id": scan_id,
             "url": url_str,
             "mode": mode_value,
             "user_id": getattr(entry, "user_id", None),
             "frontend_scan_id": getattr(entry, "frontend_scan_id", None),
             "preview_only": bool(getattr(entry, "preview_only", False)),
             "network_scan": getattr(entry, "network_scan", None),
             "callback_url": callback_url,
             "report_base_url": report_base_url,
             "request_ip": client_ip,
          })

          scan_ids.append(scan_id)

       new_complete = sum(1 for mode in normalized_modes if mode == "complete")
       new_light = len(normalized_modes) - new_complete
       running_complete = _count_running("complete")
       running_light = _count_running("light")

       if running_complete + new_complete > MEDIANET_MAX_COMPLETE_SCANS:
          raise HTTPException(status_code=429, detail="Trop de scans complets en cours")
       if running_light + new_light > MEDIANET_MAX_LIGHT_SCANS:
          raise HTTPException(status_code=429, detail="Trop de scans légers en cours")

       now = datetime.utcnow()
       for job in jobs:
          db["scan_medianet"].update_one(
             {"scan_id": job["scan_id"]},
             {
                "$set": {
                   "scan_id": job["scan_id"],
                   "status": "queued",
                   "progress": 0,
                   "mode": job["mode"],
                   "callback_url": job.get("callback_url"),
                   "target_url": job.get("url"),
                   "updated_at": now,
                },
                "$setOnInsert": {"created_at": now},
             },
             upsert=True,
          )

       # Push jobs to the external queue; worker will process them asynchronously.
       try:
          await _enqueue_jobs(jobs)
       except HTTPException:
          db["scan_medianet"].update_many(
             {"scan_id": {"$in": scan_ids}},
             {"$set": {"status": "failed", "error": "Queue unavailable", "updated_at": datetime.utcnow()}},
          )
          raise

       return {
          "status": "accepted",
          "scan_ids": scan_ids,
       }

    @router.get("/scan-status/{scan_id}")
    async def medianet_scan_status(scan_id: str):
        doc = db["scan_medianet"].find_one(
            {"scan_id": scan_id},
            {"_id": 0, "scan_id": 1, "status": 1, "progress": 1},
            sort=[("updated_at", -1), ("created_at", -1)],
        )

        if not doc:
            raise HTTPException(status_code=404, detail="Scan not found")

        return {
            "scan_id": doc.get("scan_id", scan_id),
            "status": doc.get("status", "unknown"),
            "progress": int(doc.get("progress") or 0),
        }


# =========================================================
# 📄 REPORT GENERATION
# =========================================================

def register_report_generation_routes(
    app_router: APIRouter | FastAPI | None = None,
    *,
    get_scan_from_mongo_fn: Callable[[str], dict[str, Any] | None],
    convert_objectid_fn: Callable[[Any], Any],
    compute_summary_fn: Callable[[dict], tuple[dict[str, int], str | None]],
    build_wpprobe_table_fn: Callable[[Sequence[dict[str, Any]]], list[dict[str, Any]]],
    parse_nuclei_output_fn: Callable[[str], list[dict[str, Any]]],
    templates,
    severity_order: Sequence[str],
):
    blocked_json_terms = ("nuclei", "zap")

    def _is_empty_json_value(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return value.strip() == ""
        if isinstance(value, (dict, list, tuple, set)):
            return len(value) == 0
        return False

    def _sanitize_report_json(value: Any) -> Any:
        if isinstance(value, dict):
            cleaned: dict[str, Any] = {}
            for key, raw_value in value.items():
                key_text = str(key)
                key_lower = key_text.lower()
                if any(term in key_lower for term in blocked_json_terms):
                    continue

                cleaned_value = _sanitize_report_json(raw_value)
                if _is_empty_json_value(cleaned_value):
                    continue

                cleaned[key] = cleaned_value
            return cleaned

        if isinstance(value, list):
            cleaned_items: list[Any] = []
            for item in value:
                cleaned_item = _sanitize_report_json(item)
                if _is_empty_json_value(cleaned_item):
                    continue
                cleaned_items.append(cleaned_item)
            return cleaned_items

        if isinstance(value, str):
            if any(term in value.lower() for term in blocked_json_terms):
                return ""
            return value

        return value

    def _build_recon_payload(scan_payload: dict[str, Any]) -> dict[str, Any] | None:
        recon_data = scan_payload.get("recon")
        if not isinstance(recon_data, dict):
            return None

        collected: list[dict[str, Any]] = []

        webanalyze_data = recon_data.get("webanalyze")
        if isinstance(webanalyze_data, dict):
            webanalyze_techs = webanalyze_data.get("technologies")
            if isinstance(webanalyze_techs, list):
                for tech in webanalyze_techs:
                    if isinstance(tech, dict):
                        name = (tech.get("name") or "").strip()
                        if not name:
                            continue
                        entry: dict[str, Any] = {"name": name}
                        version = tech.get("version")
                        if isinstance(version, str) and version.strip():
                            entry["version"] = version.strip()
                        collected.append(entry)
                    elif isinstance(tech, str) and tech.strip():
                        collected.append({"name": tech.strip()})

        httpx_data = recon_data.get("httpx")
        if isinstance(httpx_data, dict):
            httpx_techs = httpx_data.get("tech")
            if isinstance(httpx_techs, list):
                for tech in httpx_techs:
                    if isinstance(tech, str) and tech.strip():
                        collected.append({"name": tech.strip()})
                    elif isinstance(tech, dict):
                        name = (tech.get("name") or "").strip()
                        if name:
                            collected.append({"name": name})

        if not collected:
            return None

        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for item in collected:
            name = str(item.get("name") or "").strip()
            version = str(item.get("version") or "").strip()
            if not name:
                continue
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            normalized_item: dict[str, Any] = {"name": name}
            if version:
                normalized_item["version"] = version
            deduped.append(normalized_item)

        return {"technologies": deduped} if deduped else None

    def _build_active_findings_payload(zap_payload: dict[str, Any]) -> dict[str, Any] | None:
        alerts = zap_payload.get("alerts")
        if not isinstance(alerts, list):
            return None

        reduced_alerts: list[dict[str, str]] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            reduced: dict[str, str] = {}
            for field in ("name", "risk", "description", "solution"):
                raw_value = alert.get(field)
                if raw_value is None:
                    continue
                text = raw_value if isinstance(raw_value, str) else str(raw_value)
                text = text.strip()
                if text:
                    reduced[field] = text

            if reduced:
                reduced_alerts.append(reduced)

        if not reduced_alerts:
            return None

        return {"alerts": reduced_alerts}

    async def _generate_report_file(scan: dict, request: Request, report_format: str):
        if isinstance(scan, list):
            scan = scan[0] if scan else {}
        if not isinstance(scan, dict):
            raise HTTPException(status_code=400, detail="Invalid scan payload")

        cms = (scan.get("cms_type") or "").lower()
        mode = scan.get("mode", "light")
        zap_data = scan.get("zap_scan") if isinstance(scan.get("zap_scan"), dict) else {}
        cms_scan = scan.get("cms_scan") if isinstance(scan.get("cms_scan"), dict) else {}
        if not isinstance(cms_scan.get("cves"), list):
            cms_scan["cves"] = []
        if "scanned_at" not in cms_scan:
            cms_scan["scanned_at"] = None
        if "wpprobe_report" not in cms_scan:
            cms_scan["wpprobe_report"] = None
        scan["cms_scan"] = cms_scan
        nuclei_scan = scan.get("nuclei_scan") if isinstance(scan.get("nuclei_scan"), dict) else {}

        plugin_rows: list[dict[str, Any]] = []
        if cms == "wordpress":
            plugin_rows = cms_scan.get("wpprobe_table") or []
            if not plugin_rows and cms_scan.get("cves"):
                try:
                    plugin_rows = build_wpprobe_table_fn(cms_scan.get("cves") or [])
                except Exception:
                    plugin_rows = []

        severity_counts, highest_risk = compute_summary_fn(scan)
        severity_counts_upper = {k.upper(): v for k, v in severity_counts.items()}
        total_vulnerabilities = sum(severity_counts.values())
        severity_metrics = {
            "critical_count": severity_counts_upper.get("CRITICAL", 0),
            "high_count": severity_counts_upper.get("HIGH", 0),
            "medium_count": severity_counts_upper.get("MEDIUM", 0),
            "low_count": severity_counts_upper.get("LOW", 0),
            "info_count": severity_counts_upper.get("INFO", 0),
            "critical_width": (severity_counts_upper.get("CRITICAL", 0) / (total_vulnerabilities or 1)) * 100,
            "high_width": (severity_counts_upper.get("HIGH", 0) / (total_vulnerabilities or 1)) * 100,
            "medium_width": (severity_counts_upper.get("MEDIUM", 0) / (total_vulnerabilities or 1)) * 100,
            "low_width": (severity_counts_upper.get("LOW", 0) / (total_vulnerabilities or 1)) * 100,
            "info_width": (severity_counts_upper.get("INFO", 0) / (total_vulnerabilities or 1)) * 100,
        }

        if cms in ["drupal", "prestashop"]:
            template_name = "rapport_drupal.html"
            context = {
                "request": request,
                "scan": scan,
                "cms_scan": cms_scan,
                "nuclei_scan": nuclei_scan,
                "zap_scan": zap_data if isinstance(zap_data, dict) else {},
                "has_zap": bool(zap_data and zap_data.get("alerts")),
                **severity_metrics,
                "plugin_rows": [],
            }
        elif cms in ["wordpress", "inconnu"]:
            if mode == "complete" and zap_data:
                template_name = "report_wp_inconnu_complete.html"
            else:
                template_name = "report_template.html"
            context = {
                "request": request,
                "scan": scan,
                "nuclei_scan": nuclei_scan,
                "zap_scan": zap_data,
                "severity_counts": severity_counts,
                "risk_level": highest_risk,
                "total_vulnerabilities": total_vulnerabilities,
                "plugin_rows": plugin_rows,
                **severity_metrics,
            }
        else:
            raise HTTPException(status_code=400, detail=f"CMS non supporté : {cms}")

        cms_label = cms or "inconnu"
        report_format = (report_format or "pdf").lower()

        if report_format == "json":
            payload = {
                "scan_id": scan.get("scan_id"),
                "cms": cms_label,
                "mode": mode,
                "risk_level": highest_risk,
                "severity_counts": severity_counts,
                "total_vulnerabilities": total_vulnerabilities,
                "scan": {
                    "scan_id": scan.get("scan_id"),
                    "status": scan.get("status"),
                    "site_url": scan.get("target_url") or scan.get("site_url") or scan.get("url"),
                    "created_at": scan.get("created_at"),
                    "started_at": scan.get("started_at"),
                    "completed_at": scan.get("completed_at"),
                    "scan_time": scan.get("scan_time"),
                },
                "cms_scan": cms_scan,
                "network_scan": scan.get("network_scan") or scan.get("network_results"),
                "recon": _build_recon_payload(scan),
                "web_findings": nuclei_scan,
                "active_findings": _build_active_findings_payload(zap_data) if isinstance(zap_data, dict) else None,
            }
            payload = _sanitize_report_json(payload)
            json_io = BytesIO()
            json_io.write(json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8"))
            json_io.seek(0)
            return json_io, "application/json", f"rapport_{cms_label}_{mode}.json"

        if report_format == "xlsx":
            wb = Workbook()
            ws_summary = wb.active
            ws_summary.title = "Résumé"
            ws_summary.append(["Champ", "Valeur"])
            ws_summary.append(["Site", scan.get("target_url") or scan.get("site_url") or scan.get("url") or ""])
            ws_summary.append(["CMS", cms_label])
            ws_summary.append(["Mode", mode])
            ws_summary.append(["Niveau de risque", highest_risk or "N/A"])
            ws_summary.append(["Total vulnérabilités", total_vulnerabilities])
            ws_summary.append([])
            ws_summary.append(["Niveau", "Détections"])
            for sev in severity_order:
                ws_summary.append([sev.capitalize(), severity_counts.get(sev, 0)])

            def add_sheet_from_rows(title: str, entries):
                rows = [row for row in (entries or []) if isinstance(row, dict)]
                if not rows:
                    return
                headers: list[str] = []
                for row in rows:
                    for key in row.keys():
                        if key not in headers:
                            headers.append(key)
                if not headers:
                    return
                sheet = wb.create_sheet(title)
                sheet.append([header.upper() for header in headers])
                for row in rows:
                    values = []
                    for header in headers:
                        value = row.get(header, "")
                        if isinstance(value, (dict, list)):
                            value = json.dumps(value, ensure_ascii=False)
                        values.append(value)
                    sheet.append(values)

            if isinstance(cms_scan, dict) and isinstance(cms_scan.get("cves"), list):
                add_sheet_from_rows("CMS_VULNERABILITES", cms_scan.get("cves", []))

            nuclei_results = nuclei_scan.get("parsed_results")
            if not nuclei_results and nuclei_scan.get("nuclei_stdout"):
                nuclei_results = parse_nuclei_output_fn(nuclei_scan.get("nuclei_stdout", ""))
            if isinstance(nuclei_results, list):
                add_sheet_from_rows("NUCLEI", nuclei_results)

            if isinstance(zap_data, dict) and isinstance(zap_data.get("alerts"), list):
                add_sheet_from_rows("ZAP_ALERTES", zap_data.get("alerts", []))

            xlsx_io = BytesIO()
            wb.save(xlsx_io)
            xlsx_io.seek(0)
            return (
                xlsx_io,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                f"rapport_{cms_label}_{mode}.xlsx",
            )

        html = templates.get_template(template_name).render(context)
        pdf_io = BytesIO()
        HTML(string=html, base_url=str(request.base_url)).write_pdf(pdf_io)
        pdf_io.seek(0)
        return pdf_io, "application/pdf", f"rapport_{cms_label}_{mode}.pdf"

    if app_router is not None:

        @app_router.get("/generate-report/{scan_id}")
        async def generate_report(
            scan_id: str,
            request: Request,
            report_format: str = Query("pdf", pattern="^(pdf|json|xlsx)$"),
        ):
            scan_raw = db["scan_medianet"].find_one({"scan_id": scan_id})
            if not scan_raw:
                raise HTTPException(status_code=404, detail="Scan non trouvé")

# préserver ZAP tel quel
            zap_backup = scan_raw.get("zap_scan")

# convertir le reste
            scan_safe = convert_objectid_fn(scan_raw)

# réinjecter ZAP
            scan_safe["zap_scan"] = zap_backup

            file_io, media_type, filename = await _generate_report_file(
               scan_safe, request, report_format
            )


            return StreamingResponse(
                file_io,
                media_type=media_type,
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

        @app_router.get("/generate-rapport/{scan_id}")
        async def generate_report_medianet(
            scan_id: str,
            request: Request,
            report_format: str = Query("pdf", pattern="^(pdf|json|xlsx)$"),
        ):
            scan = db["scan_medianet"].find_one({"scan_id": scan_id})
            if not scan:
                raise HTTPException(status_code=404, detail="Scan non trouvé")

            file_io, media_type, filename = await _generate_report_file(
                convert_objectid_fn(scan), request, report_format
            )

            return StreamingResponse(
                file_io,
                media_type=media_type,
                headers={"Content-Disposition": f"attachment; filename={filename}"},
            )

    return _generate_report_file
