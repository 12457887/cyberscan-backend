# scanner_api/nuclei_scanner.py

import subprocess
import os
import logging
import json
import requests as _requests
from typing import Dict, Any, Optional

NUCLEI_SERVICE_URL = os.environ.get("NUCLEI_SERVICE_URL", "")

logger = logging.getLogger(__name__)

# =========================
# ENV HELPERS
# =========================

def _read_int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _read_str_env(name: str, default: str) -> str:
    return str(os.environ.get(name, default)).strip()


def _read_bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}


# =========================
# CONFIG (Optimisé 5 scans parallèles)
# =========================

NUCLEI_FULL_SEVERITY = _read_str_env(
    "NUCLEI_FULL_SEVERITY",
    "low,medium,high,critical"
)

NUCLEI_LIGHT_SEVERITY = _read_str_env(
    "NUCLEI_LIGHT_SEVERITY",
    "medium,high,critical"
)

NUCLEI_RATE_LIMIT = _read_int_env("NUCLEI_RATE_LIMIT", 50)
NUCLEI_CONCURRENCY = _read_int_env("NUCLEI_CONCURRENCY", 6)
NUCLEI_BULK_SIZE = _read_int_env("NUCLEI_BULK_SIZE", 5)

NUCLEI_FULL_TAGS = _read_str_env(
    "NUCLEI_FULL_TAGS",
    "cves,misconfig,ssl,headers"
)

NUCLEI_LIGHT_TAGS = _read_str_env(
    "NUCLEI_LIGHT_TAGS",
    "cves,misconfig,headers"
)

NUCLEI_REQUEST_TIMEOUT = _read_int_env("NUCLEI_REQUEST_TIMEOUT", 8)
NUCLEI_RETRIES = _read_int_env("NUCLEI_RETRIES", 1)
NUCLEI_MAX_HOST_ERROR = _read_int_env("NUCLEI_MAX_HOST_ERROR", 5)

NUCLEI_OUTPUT_JSONL = _read_bool_env("NUCLEI_OUTPUT_JSONL", True)


# =========================
# JSONL PARSER
# =========================

def parse_nuclei_jsonl(output: str):
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


# =========================
# COMMAND BUILDER
# =========================

def generate_nuclei_command(url: str, cms: str, profile: str = "full") -> list:
    use_light = profile.strip().lower() == "light"

    severity = NUCLEI_LIGHT_SEVERITY if use_light else NUCLEI_FULL_SEVERITY
    tags_common = NUCLEI_LIGHT_TAGS if use_light else NUCLEI_FULL_TAGS

    base_cmd = [
        "nuclei",
        "-u", url,
        "-severity", severity,
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-c", str(NUCLEI_CONCURRENCY),
        "-bulk-size", str(NUCLEI_BULK_SIZE),
        "-timeout", str(NUCLEI_REQUEST_TIMEOUT),
        "-retries", str(NUCLEI_RETRIES),
        "-max-host-error", str(NUCLEI_MAX_HOST_ERROR),
        "-no-color",
        "-silent",
        "-no-interactsh"  # recommandé SaaS
    ]

    if NUCLEI_OUTPUT_JSONL:
        base_cmd.append("-jsonl")

    # CMS tagging
    tags_by_cms = {
        "wordpress": "wordpress",
        "prestashop": "prestashop",
        "drupal": "drupal"
    }

    cms_tag = tags_by_cms.get(cms.lower())
    if cms_tag:
        tags_common = f"{tags_common},{cms_tag}"

    if tags_common:
        base_cmd += ["-tags", tags_common]

    logger.info("NUCLEI CMD: %s", " ".join(base_cmd))
    return base_cmd


# =========================
# RUN SCAN
# =========================

def run_nuclei_scan(
    url: str,
    cms: str,
    profile: str = "full",
    timeout: Optional[int] = 240
) -> Dict[str, Any]:

    logger.info(f"🔎 Starting Nuclei scan → {url} (CMS: {cms}, profile: {profile})")

    # Appel au pod Nuclei si configuré
    if NUCLEI_SERVICE_URL:
        try:
            resp = _requests.post(
                f"{NUCLEI_SERVICE_URL}/scan",
                json={"url": url, "cms": cms, "profile": profile, "timeout": timeout},
                timeout=(10, timeout + 30),
            )
            if resp.ok:
                return resp.json()
            logger.warning("Nuclei service returned %s, falling back to local", resp.status_code)
        except Exception as exc:
            logger.warning("Nuclei service unreachable (%s), falling back to local", exc)

    cmd = generate_nuclei_command(url, cms, profile)

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        parsed_results = []

        if NUCLEI_OUTPUT_JSONL and result.stdout:
            parsed_results = parse_nuclei_jsonl(result.stdout)

        logger.info("PARSED RESULTS COUNT: %s", len(parsed_results))

        real_error = None
        if result.returncode != 0:
            real_error = result.stderr.strip() or "Unknown Nuclei error"

        response = {
            "target_url": url,
            "cms": cms,
            "profile": profile,
            "matched": len(parsed_results),
            "parsed_results": parsed_results,
            "timed_out": False,
            "source": "nuclei"
        }

        if real_error:
            response["error"] = real_error

        return response

    except subprocess.TimeoutExpired:
        logger.warning(f"⏱ Nuclei timeout after {timeout}s → {url}")

        return {
            "target_url": url,
            "cms": cms,
            "profile": profile,
            "matched": 0,
            "parsed_results": [],
            "timed_out": True,
            "error": "Timeout",
            "source": "nuclei"
        }

    except Exception as e:
        logger.error(f"❌ Nuclei execution error → {e}")

        return {
            "target_url": url,
            "cms": cms,
            "profile": profile,
            "matched": 0,
            "parsed_results": [],
            "timed_out": False,
            "error": str(e),
            "source": "nuclei"
        }
