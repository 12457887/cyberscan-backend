from __future__ import annotations
import os, requests, logging
from typing import Any, Dict, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

SUPABASE_URL              = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
_ENABLED = bool(
    SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
    and SUPABASE_URL != "disabled"
    and SUPABASE_SERVICE_ROLE_KEY != "disabled"
)

def _headers() -> Dict[str, str]:
    if not _ENABLED:
        return {}
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def create_scan_row(scan_id, user_id, mongo_scan_id=None,
                    status="pending", site_name=None, site_url=None):
    if not _ENABLED: return {}
    try:
        r = requests.post(f"{SUPABASE_URL}/rest/v1/scans",
            headers={**_headers(), "Prefer": "return=representation"},
            json={"id": scan_id, "user_id": user_id,
                  "mongo_scan_id": mongo_scan_id or "",
                  "status": status, "site_name": site_name or "",
                  "site_url": site_url or ""}, timeout=10)
        data = r.json()
        return (data[0] if isinstance(data, list) and data else data) if r.ok else {}
    except Exception as e:
        logger.warning(f"create_scan_row: {e}"); return {}

def update_scan_row(scan_id, updates, allow_retry=True):
    if not _ENABLED: return {}
    try:
        r = requests.patch(f"{SUPABASE_URL}/rest/v1/scans",
            headers={**_headers(), "Prefer": "return=representation"},
            params={"id": f"eq.{scan_id}"}, json=updates, timeout=10)
        data = r.json()
        return (data[0] if isinstance(data, list) and data else data) if r.ok else {}
    except Exception as e:
        logger.warning(f"update_scan_row: {e}"); return {}

def get_scan_row(scan_id):
    if not _ENABLED: return {}
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/scans",
            headers=_headers(),
            params={"id": f"eq.{scan_id}", "select": "*"}, timeout=10)
        rows = r.json() if r.ok else []
        return rows[0] if rows else {}
    except Exception as e:
        logger.warning(f"get_scan_row: {e}"); return {}

def insert_vulnerabilities(scan_id, vuln_counts):
    if not _ENABLED: return []
    try:
        rows = [{"scan_id": scan_id, "severity": s, "count": c}
                for s, c in vuln_counts.items()]
        r = requests.post(f"{SUPABASE_URL}/rest/v1/vulnerabilities",
            headers={**_headers(), "Prefer": "return=minimal"}, json=rows, timeout=10)
        return rows if r.ok else []
    except Exception as e:
        logger.warning(f"insert_vulnerabilities: {e}"); return []

def insert_alert(scan_id, alert_type, message, **kw):
    if not _ENABLED: return {}
    try:
        r = requests.post(f"{SUPABASE_URL}/rest/v1/alerts",
            headers=_headers(),
            json={"scan_id": scan_id, "type": alert_type,
                  "message": message, **kw}, timeout=10)
        return r.json() if r.ok else {}
    except Exception as e:
        logger.warning(f"insert_alert: {e}"); return {}

def get_scan_id_by_zap_scan_id(zap_scan_id):
    if not _ENABLED: return None
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/scans",
            headers=_headers(),
            params={"zap_scan_id": f"eq.{zap_scan_id}", "select": "id"}, timeout=10)
        rows = r.json() if r.ok else []
        return rows[0]["id"] if rows else None
    except Exception: return None

def _get_profile(user_id):
    if not _ENABLED: return None
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/profiles",
            headers=_headers(),
            params={"id": f"eq.{user_id}", "select": "*"}, timeout=10)
        rows = r.json() if r.ok else []
        return rows[0] if rows else None
    except Exception: return None

def _fetch_auth_user(user_id):
    if not _ENABLED: return None
    try:
        r = requests.get(f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
            headers=_headers(), timeout=10)
        return r.json() if r.ok else None
    except Exception: return None

def ensure_profile_row(user_id):
    if not _ENABLED: return None
    profile = _get_profile(user_id)
    if profile: return profile
    try:
        r = requests.post(f"{SUPABASE_URL}/rest/v1/profiles",
            headers=_headers(), json={"id": user_id}, timeout=10)
        return r.json() if r.ok else None
    except Exception: return None

def record_scan_activity(scan_id, user_id, action, **kw):
    if not _ENABLED: return {}
    try:
        r = requests.post(f"{SUPABASE_URL}/rest/v1/scan_logs",
            headers=_headers(),
            json={"scan_id": scan_id, "user_id": user_id,
                  "action": action,
                  "created_at": datetime.utcnow().isoformat(), **kw}, timeout=10)
        return r.json() if r.ok else {}
    except Exception as e:
        logger.warning(f"record_scan_activity: {e}"); return {}

def _cms_type_supported(force_check=False): return True
