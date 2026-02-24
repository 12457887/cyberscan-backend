import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime
from typing import Any

import httpx
import redis.asyncio as redis

from DB.database import db
from scanner_api.routes import (
    detect_cms_from_html,
    detect_cms_with_model,
    fetch_html,
    scan_sites,
)

logger = logging.getLogger("medianet_scan_worker")

# ==============================
# CONFIG
# ==============================

REDIS_URL = os.environ.get("MEDIANET_REDIS_URL", "redis://localhost:6379/0")
QUEUE_NAME = os.environ.get("MEDIANET_QUEUE_NAME", "medianet:scan_jobs")

MAX_COMPLETE = int(os.environ.get("MEDIANET_MAX_COMPLETE_SCANS", "5")
MAX_LIGHT = int(os.environ.get("MEDIANET_MAX_LIGHT_SCANS", "200"))


CALLBACK_SECRET = os.environ.get("MEDIANET_CALLBACK_SECRET", "")

POLL_INTERVAL_SECONDS = 5
REPORT_TIMEOUT_SECONDS = 3600

# ==============================
# ZAP POOL CONFIG
# ==============================

ZAP_PORTS = [8090, 8091, 8092, 8093, 8094]
ZAP_PORT_PREFIX = "medianet:zap_port_lock"

# ==============================
# REDIS SEMAPHORE (GLOBAL MODE LIMIT)
# ==============================

SEMAPHORE_PREFIX = "medianet:semaphore"
SEMAPHORE_TTL_SECONDS = REPORT_TIMEOUT_SECONDS + 300

_SEMAPHORE_ACQUIRE_LUA = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local token = ARGV[4]

redis.call("ZREMRANGEBYSCORE", key, "-inf", now - ttl)
local count = redis.call("ZCARD", key)

if count >= limit then
  return 0
end

redis.call("ZADD", key, now, token)
redis.call("PEXPIRE", key, ttl)
return 1
"""

def _status_collection():
    return db["scan_medianet"]

def _update_status(scan_id: str, fields: dict[str, Any]) -> None:
    now = datetime.utcnow()
    fields["updated_at"] = now
    fields.setdefault("scan_id", scan_id)

    _status_collection().update_one(
        {"scan_id": scan_id},
        {"$set": fields, "$setOnInsert": {"created_at": now}},
        upsert=True,
    )

def _semaphore_key(mode: str) -> str:
    return f"{SEMAPHORE_PREFIX}:{mode}"

async def _acquire_semaphore(client, mode: str, token: str, limit: int) -> bool:
    now_ms = int(time.time() * 1000)
    ttl_ms = int(SEMAPHORE_TTL_SECONDS * 1000)

    result = await client.eval(
        _SEMAPHORE_ACQUIRE_LUA,
        1,
        _semaphore_key(mode),
        limit,
        now_ms,
        ttl_ms,
        token,
    )

    return int(result) == 1

async def _release_semaphore(client, mode: str, token: str):
    await client.zrem(_semaphore_key(mode), token)

# ==============================
# ZAP PORT LOCKING
# ==============================

# ==============================
# ZAP PORT LOCKING
# ==============================

async def _acquire_zap_port(client, timeout: int = 60):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        for port in ZAP_PORTS:
            key = f"{ZAP_PORT_PREFIX}:{port}"
            acquired = await client.set(
                key,
                "1",
                nx=True,
                ex=REPORT_TIMEOUT_SECONDS
            )
            if acquired:
                return port

        await asyncio.sleep(1)

    raise RuntimeError("No ZAP instance available")


async def _release_zap_port(client, port):
    key = f"{ZAP_PORT_PREFIX}:{port}"
    try:
        await client.delete(key)
    except Exception:
        logger.warning("Failed to release ZAP port %s", port)


# ==============================
# CALLBACK
# ==============================

def _sign_payload(payload: bytes) -> str | None:
    if not CALLBACK_SECRET:
        return None
    return hmac.new(CALLBACK_SECRET.encode(), payload, hashlib.sha256).hexdigest()

async def _send_callback(callback_url: str, payload: dict[str, Any]):
    body = json.dumps(payload).encode()
    signature = _sign_payload(body)
    if not signature:
        return

    headers = {
        "Content-Type": "application/json",
        "X-Medianet-Signature": signature,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        await client.post(callback_url, content=body, headers=headers)

# ==============================
# PROCESS JOB
# ==============================

async def _process_job(job: dict[str, Any], client):
    scan_id = job.get("scan_id")
    url = job.get("url")
    mode = job.get("mode", "light")

    if not scan_id or not url:
        logger.error("Invalid job: %s", job)
        return

    limit = MAX_COMPLETE if mode == "complete" else MAX_LIGHT

    acquired = await _acquire_semaphore(client, mode, scan_id, limit)
    if not acquired:
        raise RuntimeError("Concurrency limit reached")

    zap_port = None

    try:
        # Acquire dedicated ZAP instance
        zap_port = await _acquire_zap_port(client)
        logger.info("Assigned ZAP port %s to scan %s", zap_port, scan_id)

        _update_status(scan_id, {
            "status": "running",
            "progress": 10,
            "mode": mode,
            "target_url": url,
        })

        # Detect CMS
        _, html, headers, robots = await fetch_html(str(url))

        detected_cms = (
            detect_cms_with_model(str(url), html, headers, robots)
            or detect_cms_from_html(html, headers)
            or "inconnu"
        )

        _update_status(scan_id, {
            "progress": 40,
            "cms_type": detected_cms,
        })

        network_scan_value = job.get("network_scan")
        if network_scan_value is None:
            network_scan_value = "quick" if mode == "light" else "full"

        # Run full scan with assigned port
        await scan_sites(
            detected_cms,
            [url],
            scan_id,
            mode=mode,
            user_id=job.get("user_id") or "",
            frontend_scan_id=job.get("frontend_scan_id"),
            preview_only=bool(job.get("preview_only")),
            request_ip=job.get("request_ip"),
            network_scan=network_scan_value,
            collection_override="scan_medianet",
            zap_port=zap_port,
        )

        _update_status(scan_id, {
            "status": "completed",
            "progress": 100,
            "completed_at": datetime.utcnow(),
        })

        logger.info("Scan completed: %s", scan_id)

        if job.get("callback_url"):
            await _send_callback(job["callback_url"], {
                "event": "scan.completed",
                "scan_id": scan_id,
                "status": "completed",
            })

    except Exception as exc:
        logger.exception("Scan failed: %s", scan_id)
        _update_status(scan_id, {
            "status": "failed",
            "progress": 100,
            "error": str(exc),
            "completed_at": datetime.utcnow(),
        })

    finally:
        if zap_port:
            await _release_zap_port(client, zap_port)
        await _release_semaphore(client, mode, scan_id)

# ==============================
# WORKER LOOP
# ==============================

async def worker_loop():
    client = redis.from_url(REDIS_URL, decode_responses=True)

    while True:
        item = await client.blpop(QUEUE_NAME, timeout=5)
        if not item:
            continue

        _, raw = item

        try:
            job = json.loads(raw)
            await _process_job(job, client)
        except RuntimeError:
            await client.rpush(QUEUE_NAME, raw)
            await asyncio.sleep(2)
        except Exception:
            logger.exception("Job processing failed")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(worker_loop())
