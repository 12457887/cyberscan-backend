import os, logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class SupabaseClient:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL", "")
        self.key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
        self._enabled = bool(
            self.url and self.key
            and self.url != "disabled"
            and self.key != "disabled"
        )
        if not self._enabled:
            logger.warning("Supabase désactivé — mode local.")
            return
        self.headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }

    async def query(self, table, method="GET", params=None, data=None):
        if not self._enabled:
            return None
        async with httpx.AsyncClient(timeout=10) as client:
            url = f"{self.url}/rest/v1/{table}"
            p = (params or {}).copy()
            if method == "GET":
                p.setdefault("select", "*")
                r = await client.get(url, headers=self.headers, params=p)
            elif method == "POST":
                r = await client.post(url, headers=self.headers, json=data)
            elif method == "PATCH":
                r = await client.patch(url, headers=self.headers, params=p, json=data)
            else:
                return None
            r.raise_for_status()
            return r.json() if r.text else None

    async def fetch_due_schedules(self) -> List[Dict]:
        if not self._enabled:
            return []
        params = {
            "is_active": "eq.true",
            "is_running": "eq.false",
            "next_scan_date": f"lte.{datetime.now(timezone.utc).isoformat()}",
            "order": "next_scan_date.asc",
        }
        return (await self.query("scheduled_scans", params=params)) or []

    async def update_scan_status(self, scan_id, status, **kw):
        if not self._enabled:
            return None
        return await self.query("scans", "PATCH",
                                params={"id": f"eq.{scan_id}"},
                                data={"status": status, **kw})

    async def create_scan(self, data):
        if not self._enabled:
            return None
        return await self.query("scans", "POST", data=data)

    async def update_scheduled_scan(self, scan_id, data):
        if not self._enabled:
            return None
        return await self.query("scheduled_scans", "PATCH",
                                params={"id": f"eq.{scan_id}"}, data=data)

    async def mark_schedule_running(self, sid, is_running):
        return await self.update_scheduled_scan(sid, {"is_running": is_running})

    async def get_user_email(self, user_id) -> Optional[str]:
        if not self._enabled:
            return None
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    f"{self.url}/rest/v1/profiles",
                    params={"id": f"eq.{user_id}", "select": "email", "limit": "1"},
                    headers=self.headers)
                if r.is_success:
                    d = r.json()
                    if d and d[0].get("email"):
                        return d[0]["email"]
        except Exception:
            pass
        return None
