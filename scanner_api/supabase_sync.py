"""Helpers to sync lightweight scan metadata to Supabase (Postgres) via REST API.

This module provides two helpers:
- create_scan_row: inserts a new row into the `scans` table using the provided id
- update_scan_row: updates fields for an existing scan row

Uses these environment variables (must be set in your backend runtime):
- SUPABASE_URL (example: https://abcdxyz.supabase.co)
- SUPABASE_SERVICE_ROLE_KEY (service role key, keep secret)

Important: the service role key bypasses RLS and should be kept secret. If you
prefer not to use the service role key, call Supabase functions from a secure
environment or implement a server-side Postgres connection.
"""
from __future__ import annotations

import os
import requests
from typing import Any, Dict, Optional, List
from datetime import datetime

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    # Do not raise at import time to keep testability; functions will raise on use.
    pass


def _headers() -> Dict[str, str]:
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is not set in environment")
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def create_scan_row(
    scan_id: str,
    user_id: str,
    mongo_scan_id: Optional[str] = None,
    status: str = "pending",
    site_name: Optional[str] = None,
    site_url: Optional[str] = None,
    ) -> Dict[str, Any]:
    """Insert a scan row into Supabase `scans` table.

    Returns the inserted row as dict (representation). Raises on HTTP error.
    Note: requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment vars.
    """
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set in environment")

    payload: Dict[str, Any] = {
        "id": scan_id,
        "user_id": user_id,
        "mongo_scan_id": mongo_scan_id or "",
        "status": status,
    }
    if site_name is not None:
        payload["site_name"] = site_name
    if site_url is not None:
        payload["site_url"] = site_url

    url = SUPABASE_URL.rstrip("/") + "/rest/v1/scans"
    headers = _headers()
    # Ask Supabase to return the newly created row via Prefer header
    headers["Prefer"] = "return=representation"
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    if not r.ok:
        raise RuntimeError(f"Supabase insert failed: {r.status_code} {r.text}")
    # Response is a JSON array of inserted rows
    data = r.json()
    return data[0] if isinstance(data, list) and data else data


CMS_TYPE_SUPPORT_STATE = "unknown"  # "unknown" | "supported" | "unsupported"


def _cms_type_supported(force_check: bool = False) -> bool:
    global CMS_TYPE_SUPPORT_STATE

    if CMS_TYPE_SUPPORT_STATE == "supported":
        return True
    if CMS_TYPE_SUPPORT_STATE == "unsupported" and not force_check:
        return False

    if not SUPABASE_URL:
        CMS_TYPE_SUPPORT_STATE = "unsupported"
        return False

    try:
        headers = _headers()
        url = SUPABASE_URL.rstrip("/") + "/rest/v1/scans?select=cms_type&limit=1"
        r = requests.get(url, headers=headers, timeout=10)
        if r.ok:
            CMS_TYPE_SUPPORT_STATE = "supported"
            return True
        if r.status_code == 400 and "cms_type" in r.text:
            CMS_TYPE_SUPPORT_STATE = "unsupported"
            return False
    except Exception:
        pass

    CMS_TYPE_SUPPORT_STATE = "unsupported"
    return False


def update_scan_row(scan_id: str, updates: Dict[str, Any], allow_retry: bool = True) -> Dict[str, Any]:
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set in environment")

    url = SUPABASE_URL.rstrip("/") + f"/rest/v1/scans?id=eq.{scan_id}"
    headers = _headers()
    headers["Prefer"] = "return=representation"

    payload = dict(updates)
    wants_cms = "cms_type" in payload
    cms_supported = _cms_type_supported(force_check=wants_cms)
    if not cms_supported and "cms_type" in payload:
        payload.pop("cms_type")

    print(f"🔄 [Supabase] Updating scan {scan_id} with {payload}")
    r = requests.patch(url, json=payload, headers=headers, timeout=15)
    print(f"🟡 [Supabase] Primary update response: {r.status_code} {r.text}")

    if (
        not r.ok
        and allow_retry
        and r.status_code == 400
        and "Could not find the 'cms_type' column of 'scans'" in r.text
        and "cms_type" in payload
    ):
        CMS_TYPE_SUPPORT_STATE = "unsupported"
        trimmed_updates = {k: v for k, v in payload.items() if k != "cms_type"}
        if trimmed_updates != payload:
            print("🔁 [Supabase] Retrying update without cms_type column")
            return update_scan_row(scan_id, trimmed_updates, allow_retry=False)

    if not r.ok:
        raise RuntimeError(f"Supabase update failed: {r.status_code} {r.text}")

    data = r.json()

    # 🔁 Met aussi à jour les lignes liées à backend_scan_id
    try:
        url2 = SUPABASE_URL.rstrip('/') + f"/rest/v1/scans?backend_scan_id=eq.{scan_id}"
        r2 = requests.patch(url2, json=payload, headers=headers, timeout=15)
        print(f"🟢 [Supabase] Secondary update (backend_scan_id) response: {r2.status_code} {r2.text}")
    except Exception as e:
        print(f"⚠️ [Supabase] Secondary update exception: {e}")

    return data[0] if isinstance(data, list) and data else data


def get_scan_row(scan_id: str) -> Dict[str, Any]:
    """Fetch a scan row from Supabase `scans` table by id."""
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set in environment")

    url = SUPABASE_URL.rstrip("/") + f"/rest/v1/scans?id=eq.{scan_id}&select=*&limit=1"
    headers = _headers()
    r = requests.get(url, headers=headers, timeout=10)
    if not r.ok:
        raise RuntimeError(f"Supabase fetch failed: {r.status_code} {r.text}")

    data = r.json()
    if isinstance(data, list):
        if not data:
            raise RuntimeError(f"Supabase scan row not found for id {scan_id}")
        return data[0]
    if isinstance(data, dict):
        return data
    raise RuntimeError("Supabase returned unexpected response format")

def insert_vulnerabilities(scan_id: str, vuln_counts: Dict[str, int]) -> List[Dict[str, Any]]:
    """Insert aggregated vulnerability rows for a scan into `vulnerabilities` table.

    vuln_counts should be a mapping like {'critical': 1, 'high': 2, ...}
    Returns the inserted rows as a list of dicts. Raises on HTTP error.
    """
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set in environment")

    url = SUPABASE_URL.rstrip('/') + '/rest/v1/vulnerabilities'
    headers = _headers()

    rows = []
    for severity, count in vuln_counts.items():
        try:
            count_int = int(count)
        except Exception:
            continue
        if count_int <= 0:
            continue
        rows.append({'scan_id': scan_id, 'severity': severity, 'count': count_int})

    if not rows:
        return []

    headers['Prefer'] = 'return=representation'
    r = requests.post(url, json=rows, headers=headers, timeout=15)
    if not r.ok:
        raise RuntimeError(f"Supabase insert vulnerabilities failed: {r.status_code} {r.text}")
    data = r.json()
    return data if isinstance(data, list) else [data]

def get_scan_id_by_zap_scan_id(zap_scan_id: str) -> Optional[str]:
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set in environment")

    url = (
        SUPABASE_URL.rstrip("/")
        + f"/rest/v1/scans?zap_scan_id=eq.{zap_scan_id}&select=id&limit=1"
    )
    headers = _headers()
    r = requests.get(url, headers=headers, timeout=10)

    if not r.ok:
        raise RuntimeError(
            f"Supabase lookup failed: {r.status_code} {r.text}"
        )

    data = r.json()
    if isinstance(data, list) and data:
        return data[0]["id"]

    return None


def _get_profile(user_id: str) -> Optional[Dict[str, Any]]:
    if not SUPABASE_URL:
        return None
    url = SUPABASE_URL.rstrip('/') + f"/rest/v1/profiles?id=eq.{user_id}&select=*&limit=1"
    headers = _headers()
    r = requests.get(url, headers=headers, timeout=10)
    if not r.ok:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    if isinstance(data, list) and data:
        return data[0]
    if isinstance(data, dict):
        return data
    return None


def _fetch_auth_user(user_id: str) -> Optional[Dict[str, Any]]:
    if not SUPABASE_URL:
        return None
    url = SUPABASE_URL.rstrip('/') + f"/auth/v1/admin/users/{user_id}"
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
    }
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code == 200:
        try:
            return r.json()
        except ValueError:
            return None
    return None


def ensure_profile_row(user_id: str) -> Optional[Dict[str, Any]]:
    """
    Ensure a profile row exists for user_id; create and return minimal entry if missing.
    """
    if not SUPABASE_URL:
        return None
    profile = _get_profile(user_id)
    if profile:
        return profile

    auth_user = _fetch_auth_user(user_id)
    if not auth_user:
        return None

    metadata = auth_user.get("user_metadata") or {}
    app_metadata = auth_user.get("app_metadata") or {}
    payload: Dict[str, Any] = {
        "id": user_id,
        "email": auth_user.get("email"),
        "full_name": metadata.get("full_name") or metadata.get("name") or auth_user.get("email"),
        "role": metadata.get("role") or app_metadata.get("role") or "client",
        "created_at": auth_user.get("created_at") or datetime.utcnow().isoformat() + "Z",
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    payload = {k: v for k, v in payload.items() if v is not None}
    url = SUPABASE_URL.rstrip('/') + "/rest/v1/profiles"
    headers = _headers()
    headers["Prefer"] = "return=minimal"
    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if not r.ok:
        return None
    return payload


def record_scan_activity(
    *,
    user_id: str,
    target_url: str,
    scan_mode: str,
    ip_address: Optional[str] = None,
    scan_id: Optional[str] = None,
    triggered_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enregistre un log de scan dans la table `scan_logs` de Supabase pour audit admin.
    """
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set in environment")

    payload: Dict[str, Any] = {
        "user_id": user_id,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "triggered_at": triggered_at or datetime.utcnow().isoformat() + "Z",
    }
    if ip_address:
        payload["ip_address"] = ip_address
    if scan_id:
        payload["scan_id"] = scan_id

    url = SUPABASE_URL.rstrip('/') + '/rest/v1/scan_logs'
    headers = _headers()
    headers["Prefer"] = "return=representation"
    profile_data: Optional[Dict[str, Any]] = None
    if user_id:
        profile_data = ensure_profile_row(user_id)
        if not profile_data:
            raise RuntimeError(f"Profil Supabase introuvable pour user_id={user_id}")
        full_name = profile_data.get("full_name")
        if full_name:
            payload["user_name"] = full_name
        elif profile_data.get("email"):
            payload["user_name"] = profile_data["email"]

    r = requests.post(url, json=payload, headers=headers, timeout=10)
    if not r.ok:
        raise RuntimeError(f"Supabase scan_log insert failed: {r.status_code} {r.text}")
    data = r.json()
    return data[0] if isinstance(data, list) and data else data
