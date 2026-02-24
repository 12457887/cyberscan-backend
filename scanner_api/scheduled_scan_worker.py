import os
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict

import httpx
from dotenv import load_dotenv

from .supabase_client import SupabaseClient

load_dotenv()

BACKEND_BASE_URL = os.getenv("BACKEND_BASE_URL") or os.getenv("SCHEDULER_BACKEND_URL") or "http://localhost:8000"
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY")

supabase = SupabaseClient()


async def _trigger_backend_scan(scheduled_scan: Dict[str, str], scan_id: str) -> None:
    payload = [
        {
            "url": scheduled_scan["site_url"],
            "mode": scheduled_scan.get("scan_type", "light"),
            "scan_id": scan_id,
            "frontend_scan_id": scan_id,
            "user_id": scheduled_scan["user_id"],
        }
    ]

    headers = {"Content-Type": "application/json"}
    if BACKEND_API_KEY:
        headers["x-backend-api-key"] = BACKEND_API_KEY

    async with httpx.AsyncClient(timeout=600) as client:
        response = await client.post(
            f"{BACKEND_BASE_URL.rstrip('/')}/scan-auto-detect",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()


def _compute_next_date(current_next: str, frequency: str) -> datetime:
    base = datetime.fromisoformat(current_next.replace("Z", "+00:00"))
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    if frequency == "weekly":
        delta = timedelta(days=7)
    elif frequency == "monthly":
        delta = timedelta(days=30)
    else:
        delta = timedelta(days=7)
    candidate = base + delta
    now = datetime.now(timezone.utc)
    if candidate < now:
        return now + delta
    return candidate


async def process_scheduled_scans() -> None:
    try:
        due_schedules = await supabase.fetch_due_schedules()
        if not due_schedules:
            return

        for schedule in due_schedules:
            schedule_id = schedule["id"]
            try:
                await supabase.mark_schedule_running(schedule_id, True)

                now_iso = datetime.now(timezone.utc).isoformat()
                site_url = schedule["site_url"]
                site_name = schedule.get("site_name") or site_url
                scan_payload = {
                    "user_id": schedule["user_id"],
                    "site_url": site_url,
                    "site_name": site_name,
                    "scan_type": schedule.get("scan_type", "light"),
                    "status": "pending",
                    "scheduled_scan_id": schedule_id,
                    "created_at": now_iso,
                }

                scan_response = await supabase.create_scan(scan_payload)
                if not scan_response:
                    raise RuntimeError("Supabase did not return the created scan")
                scan_row = scan_response[0]
                scan_id = scan_row["id"]

                await _trigger_backend_scan(schedule, scan_id)

                next_date = _compute_next_date(schedule["next_scan_date"], schedule.get("frequency", "weekly"))
                await supabase.update_scheduled_scan(
                    schedule_id,
                    {
                        "is_running": False,
                        "last_scan_date": now_iso,
                        "next_scan_date": next_date.isoformat(),
                    },
                )

            except Exception as exc:
                await supabase.mark_schedule_running(schedule_id, False)
                print(f"[SCHEDULER] Error processing scheduled scan {schedule_id}: {exc}")
                continue

    except Exception as exc:
        print(f"[SCHEDULER] Unexpected error: {exc}")


async def run_scheduler() -> None:
    while True:
        await process_scheduled_scans()
        await asyncio.sleep(60)


if __name__ == "__main__":
    asyncio.run(run_scheduler())
