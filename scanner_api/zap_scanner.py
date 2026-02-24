import os
import time
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse, urlencode

import requests
import urllib3
from fastapi import APIRouter, Request

from scanner_api.supabase_sync import (
    get_scan_id_by_zap_scan_id,
    update_scan_row,
)

# -------------------------------------------------
# 🔧 Router
# -------------------------------------------------
router = APIRouter(prefix="/scans")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCAN_PROGRESS: Dict[str, Dict[str, Any]] = {}

# -------------------------------------------------
# 🔧 ENV CONFIG
# -------------------------------------------------
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_PORT = os.getenv("ZAP_PORT", "8090")
ZAP_HOST = os.getenv("ZAP_HOST", f"http://127.0.0.1:{ZAP_PORT}")
ZAP_TIMEOUT = int(os.getenv("ZAP_TIMEOUT", "20"))

ZAP_FULL_WORKER_URL = os.getenv(
    "ZAP_FULL_WORKER_URL",
    "http://108.181.1.247:5001",
)

ZAP_FULL_TOKEN = os.getenv(
    "ZAP_FULL_TOKEN",
    "JY##jeaoU2KowBsZE54P0sJDcNSlb2o2ONyS8bpVjrn",
)

# -------------------------------------------------
# 🔧 Logging
# -------------------------------------------------
logger = logging.getLogger("zap_light_scanner")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
    )
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# -------------------------------------------------
# 🔧 HTTP Session
# -------------------------------------------------
session = requests.Session()
session.verify = False


def zap_get(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    host: Optional[str] = None,
) -> Dict[str, Any]:

    host = host or ZAP_HOST
    params = params or {}

    if ZAP_API_KEY:
        params.setdefault("apikey", ZAP_API_KEY)

    url = f"{host.rstrip('/')}/{path.lstrip('/')}"
    resp = session.get(url, params=params, timeout=ZAP_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


# =================================================
# 🚀 ZAP LIGHT SCAN (PASSIVE ONLY)
# =================================================
def run_zap_light_scan(target: str, zap_port: int) -> Dict[str, Any]:
    logger.info(f"🟦 ZAP Light Scan → {target} (port {zap_port})")

    host = f"http://127.0.0.1:{zap_port}"

    try:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        session_name = f"light_{parsed.netloc}_{int(time.time() * 1000)}"

        zap_get(
            "/JSON/core/action/newSession/",
            {"name": session_name, "overwrite": True},
            host=host,
        )

        zap_get(
            "/JSON/core/action/accessUrl/",
            {"url": target, "followRedirects": True},
            host=host,
        )

        for _ in range(30):
            records = zap_get(
                "/JSON/pscan/view/recordsToScan/",
                host=host,
            ).get("recordsToScan", 0)

            if int(records) == 0:
                break

            time.sleep(1)

        raw_alerts = zap_get(
            "/JSON/core/view/alerts/",
            {"baseurl": base},
            host=host,
        ).get("alerts", [])

        alerts = [
            {
                "name": a.get("alert"),
                "risk": a.get("risk"),
                "confidence": a.get("confidence"),
                "url": a.get("url"),
                "description": a.get("description"),
                "solution": a.get("solution"),
                "source": "zap-light",
            }
            for a in raw_alerts
            if a.get("risk") not in {"Informational"}
        ]

        logger.info(f"🟢 ZAP terminé ({zap_port}) : {len(alerts)} alertes")

        # clean session
        zap_get(
            "/JSON/core/action/newSession/",
            {"name": "clean_session", "overwrite": True},
            host=host,
        )

        return {
            "target_url": target,
            "alerts": alerts,
            "total_alerts": len(alerts),
            "zap_port": zap_port,
        }

    except Exception as e:
        logger.error(f"❌ Erreur ZAP Light Scan (port {zap_port}): {e}")
        return {
            "error": str(e),
            "target_url": target,
        }



# =================================================
# 🟥 ZAP FULL REMOTE
# =================================================
def run_zap_full_remote_scan(target: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
    logger.info(f"🟥 ZAP FULL (remote) → {target}")

    try:
        callback_url = "https://scanner.securas.cloud/api/scans/zap/callback"
        if scan_id:
            callback_url = f"{callback_url}?{urlencode({'scan_id': scan_id})}"

        resp = requests.post(
            f"{ZAP_FULL_WORKER_URL}/scan/full",
            headers={
                "Authorization": f"Bearer {ZAP_FULL_TOKEN}",
                "Content-Type": "application/json",
            },
            json={
                "target": target,
                "callback_url": (
                    callback_url
                ),
            },
            timeout=20,
        )

        if resp.status_code != 202:
            raise Exception(f"{resp.status_code}: {resp.text}")

        data = resp.json()

        return {
            "status": "accepted",
            "scanId": data.get("scanId"),
            "target_url": target,
            "source": "zap-full",
        }

    except Exception as e:
        logger.error(f"❌ Erreur ZAP FULL remote : {e}")
        return {
            "status": "ERROR",
            "error": str(e),
            "target_url": target,
            "source": "zap-full",
        }


# =================================================
# 🔄 CALLBACK ZAP FULL
# =================================================
@router.post("/zap/callback")
async def zap_callback(payload: dict, request: Request):
    scan_id_param = request.query_params.get("scan_id")
    zap_scan_id = payload.get("scanId")
    if not zap_scan_id:
        return {"status": "ignored"}

    internal_scan_id = get_scan_id_by_zap_scan_id(zap_scan_id)
    if not internal_scan_id:
        try:
            from scanner_api import routes as scan_routes
            internal_scan_id = scan_routes._resolve_scan_id_by_zap_scan_id(zap_scan_id)
        except Exception:
            internal_scan_id = None

    if not internal_scan_id and scan_id_param:
        internal_scan_id = scan_id_param

    if not internal_scan_id:
        logger.warning(f"⚠️ ZAP callback orphan: {zap_scan_id}")
        return {"status": "orphan"}

    if payload.get("progress", 0) < 100:
        return {"status": "progress"}

    alerts: list[dict[str, Any]] = []

    if isinstance(payload.get("alerts"), list):
      for a in payload["alerts"]:
        alerts.append({
            "name": a.get("alert"),
            "risk": a.get("risk"),
            "confidence": a.get("confidence"),
            "url": a.get("url"),
            "description": a.get("description"),
            "solution": a.get("solution"),
            "source": "zap",
        })

    else:
        for name, items in payload.get("findings", {}).items():
            for it in items:
                alerts.append(
                    {
                        "name": name,
                        "risk": it.get("risk"),
                        "confidence": it.get("confidence"),
                        "url": it.get("url"),
                    }
                )

    try:
        update_scan_row(
            internal_scan_id,
            {
                "zap_status": "completed",
                "zap_results": alerts,
            },
        )
    except Exception as exc:
        logger.warning("Supabase update failed for %s: %s", internal_scan_id, exc)
    logger.info(
        f"✅ ZAP FULL saved [{internal_scan_id}] ({len(alerts)} alerts)"
    )

    try:
        from scanner_api import routes as scan_routes
        try:
            scan_routes._update_complete_cache(
                internal_scan_id,
                zap_status="completed",
                zap_results=alerts,
            )
        except Exception:
            pass
        scan_routes.try_finalize_complete_scan(internal_scan_id)
    except Exception as exc:
        logger.warning("Finalize complete scan failed for %s: %s", internal_scan_id, exc)

    return {"status": "ok"}


# =================================================
# 🧪 CLI
# =================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser("ZAP Scanner")
    parser.add_argument("target", help="URL à scanner")
    parser.add_argument(
        "--type", choices=["light", "full"], default="light"
    )

    args = parser.parse_args()

    if args.type == "light":
      print(run_zap_light_scan(args.target, zap_port=int(ZAP_PORT)))

    else:
        print(run_zap_full_remote_scan(args.target))
