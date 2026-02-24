import os
from datetime import datetime, timezone
from dotenv import load_dotenv
import httpx
from typing import Optional, Dict, Any, List

# Load environment variables
load_dotenv()

class SupabaseClient:
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        if not self.url or not self.key:
            raise ValueError("Missing Supabase environment variables")
        
        self.headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"
        }

    async def query(
        self,
        table: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Execute a query against Supabase REST API
        """
        async with httpx.AsyncClient() as client:
            url = f"{self.url}/rest/v1/{table}"

            # Ensure we request a representation unless explicitly overridden
            headers = dict(self.headers)
            if method.upper() in {"POST", "PATCH"} and "Prefer" not in headers:
                headers["Prefer"] = "return=representation"

            request_params = params.copy() if params else {}
            if method.upper() == "GET":
                request_params.setdefault("select", "*")

            if method.upper() == "GET":
                response = await client.get(url, headers=headers, params=request_params)
            elif method.upper() == "POST":
                response = await client.post(url, headers=headers, json=data)
            elif method.upper() == "PATCH":
                response = await client.patch(url, headers=headers, params=request_params, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            if not response.text:
                return None
            try:
                return response.json()
            except ValueError:
                return response.text

    async def fetch_due_schedules(self) -> List[Dict[str, Any]]:
        """Return every active scheduled scan that should run now."""
        params = {
            "is_active": "eq.true",
            "is_running": "eq.false",
            "next_scan_date": f"lte.{datetime.now(timezone.utc).isoformat()}",
            "order": "next_scan_date.asc",
        }
        result = await self.query("scheduled_scans", params=params)
        return result or []

    async def update_scan_status(self, scan_id: str, status: str, **kwargs) -> Dict[str, Any]:
        """Update a scan's status and other fields"""
        data = {"status": status, **kwargs}
        return await self.query("scans", method="PATCH", params={"id": f"eq.{scan_id}"}, data=data)

    async def create_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new scan"""
        return await self.query("scans", method="POST", data=scan_data)

    async def update_scheduled_scan(self, scan_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a scheduled scan"""
        return await self.query(
            "scheduled_scans",
            method="PATCH",
            params={"id": f"eq.{scan_id}"},
            data=data,
        )

    async def mark_schedule_running(self, schedule_id: str, is_running: bool) -> Dict[str, Any]:
        return await self.update_scheduled_scan(schedule_id, {"is_running": is_running})
