import os
import uuid
import logging
import tempfile
import contextlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

from .wpprobe_scan import run_wpprobe
from .wpscan_scan import run_wpscan

_LOGGER = logging.getLogger(__name__)
VALID_SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_PRIORITY = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _normalize_severity(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    normalized = str(value).strip().lower()
    aliases = {
        "info": "low",
        "informational": "low",
        "information": "low",
        "n/a": None,
        "na": None,
        "none": None,
        "": None,
    }
    if normalized in aliases:
        return aliases[normalized]
    if normalized in VALID_SEVERITIES:
        return normalized
    return None


def _resolve_wpscan_default_severity() -> Optional[str]:
    value = os.getenv("WPSCAN_DEFAULT_SEVERITY", "low")
    return _normalize_severity(value)


def _severity_from_cvss(score: Any) -> Optional[str]:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None

    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return None


def _extract_wpprobe_cves(report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not report:
        return []

    results: List[Dict[str, Any]] = []
    for plugin_name, plugin_entries in (report.get("plugins") or {}).items():
        for entry in plugin_entries or []:
            version = entry.get("version")
            severity_groups = entry.get("severities") or []
            for severity_block in severity_groups:
                if not isinstance(severity_block, dict):
                    continue
                for severity_label, details in severity_block.items():
                    normalized = _normalize_severity(severity_label) or None
                    for detail in details or []:
                        auth_type = detail.get("auth_type")
                        for vuln in detail.get("vulnerabilities") or []:
                            severity_value = normalized or _severity_from_cvss(vuln.get("cvss_score")) or "low"
                            results.append({
                                "source": "wpprobe",
                                "plugin": plugin_name,
                                "plugin_version": version,
                                "title": vuln.get("title"),
                                "cve": vuln.get("cve") if vuln.get("cve") not in {"N/A", "n/a"} else None,
                                "cve_link": vuln.get("cve_link"),
                                "severity": severity_value,
                                "cvss_score": vuln.get("cvss_score"),
                                "cvss_vector": vuln.get("cvss_vector"),
                                "auth_type": auth_type,
                            })

    return results


def _read_wpscan_version(entry: Any) -> Optional[str]:
    if isinstance(entry, dict) and "version" in entry:
        version_info = entry.get("version")
    else:
        version_info = entry

    if isinstance(version_info, dict):
        value = version_info.get("number") or version_info.get("version")
        return str(value) if value else None

    if isinstance(version_info, str):
        return version_info

    return None


def _extract_wpscan_vulnerabilities(report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not report:
        return []

    default_severity = _resolve_wpscan_default_severity()
    results: List[Dict[str, Any]] = []

    def add_entries(
        asset_type: str,
        name: str,
        version: Optional[str],
        vulnerabilities: Optional[List[Dict[str, Any]]],
    ) -> None:
        if not name:
            return
        for vuln in vulnerabilities or []:
            if not isinstance(vuln, dict):
                continue
            references = vuln.get("references") or {}

            cve_value = references.get("cve") or []
            if isinstance(cve_value, list):
                cve = cve_value[0] if cve_value else None
            elif isinstance(cve_value, str):
                cve = cve_value
            else:
                cve = None

            url_value = references.get("url") or []
            if isinstance(url_value, list):
                cve_link = url_value[0] if url_value else None
            elif isinstance(url_value, str):
                cve_link = url_value
            else:
                cve_link = None

            results.append({
                "source": "wpscan",
                "plugin": name,
                "plugin_version": version,
                "title": vuln.get("title"),
                "cve": cve,
                "cve_link": cve_link,
                "severity": default_severity,
                "fixed_in": vuln.get("fixed_in"),
                "asset_type": asset_type,
                "references": references or None,
            })

    core = report.get("version")
    if isinstance(core, dict):
        add_entries(
            "core",
            "wordpress-core",
            _read_wpscan_version(core),
            core.get("vulnerabilities"),
        )

    main_theme = report.get("main_theme")
    if isinstance(main_theme, dict):
        theme_slug = (main_theme.get("slug") or main_theme.get("style_name") or "theme").strip()
        theme_name = f"theme:{theme_slug}" if theme_slug else "theme"
        add_entries(
            "theme",
            theme_name,
            _read_wpscan_version(main_theme),
            main_theme.get("vulnerabilities"),
        )

    plugins = report.get("plugins") or {}
    if isinstance(plugins, dict):
        plugin_items = list(plugins.items())
    elif isinstance(plugins, list):
        plugin_items = [
            ((plugin or {}).get("slug") or (plugin or {}).get("name"), plugin)
            for plugin in plugins
            if isinstance(plugin, dict)
        ]
    else:
        plugin_items = []

    for slug, plugin in plugin_items:
        if not isinstance(plugin, dict):
            continue
        name = str(slug) if slug else (plugin.get("slug") or plugin.get("name") or "plugin")
        name = name.strip() if isinstance(name, str) else str(name)
        add_entries(
            "plugin",
            name,
            _read_wpscan_version(plugin),
            plugin.get("vulnerabilities"),
        )

    return results


def _deduplicate_cves(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for entry in entries:
        key = (
            (entry.get("cve") or entry.get("title") or "").lower(),
            (entry.get("plugin") or entry.get("source") or "").lower(),
        )
        if key in deduped:
            continue
        deduped[key] = entry
    return list(deduped.values())


def _count_wpscan_plugins(report: Optional[Dict[str, Any]]) -> int:
    plugins = (report or {}).get("plugins") or {}
    if isinstance(plugins, dict):
        return len(plugins)
    if isinstance(plugins, list):
        return len(plugins)
    return 0


def run_wordpress_wpscan_only(
    url: str,
    wpscan_timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute WPScan only and return the cms_scan object.
    """
    errors: List[str] = []
    wpscan_data: Optional[Dict[str, Any]] = None

    if wpscan_timeout is None:
        try:
            wpscan_timeout = int(os.getenv("WPSCAN_TIMEOUT", "120"))
        except ValueError:
            wpscan_timeout = 120

    wpscan_token = os.getenv("WPSCAN_API_TOKEN") or os.getenv("WPSCAN_TOKEN")
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="wpscan_", suffix=".json")
    os.close(tmp_fd)
    try:
        wpscan_data, _ = run_wpscan(
            url=url,
            output=tmp_path,
            timeout=wpscan_timeout,
            api_token=wpscan_token,
        )
        if wpscan_data is None:
            errors.append("WPScan returned no results.")
    except Exception as exc:  # pragma: no cover - depends on WPScan binary
        errors.append(f"WPScan error: {exc}")
        _LOGGER.warning("WPScan execution failed for %s: %s", url, exc)
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)

    wpscan_cves = _extract_wpscan_vulnerabilities(wpscan_data)
    cves = _deduplicate_cves(wpscan_cves)
    scanned_at = datetime.utcnow().isoformat() + "Z"

    return {
        "scanner": "wpscan",
        "target_url": url,
        "scanned_at": scanned_at,
        "cves": cves,
        "wpscan_report": wpscan_data,
        "source": "wordpress_scanner",
        "errors": errors or None,
        "stats": {
            "total_vulnerabilities": len(cves),
            "wpscan_plugins_scanned": _count_wpscan_plugins(wpscan_data),
        },
        "wpscan_timeout": wpscan_timeout,
        "wpscan_api_token_present": bool(wpscan_token),
        "wpprobe_table": build_wpprobe_table(cves),
    }


def run_wordpress_scan(
    url: str,
    wpprobe_mode: str = "stealthy",
    wpprobe_timeout: int = 60,
    wpscan_timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Execute WPProbe and WPScan then return the combined cms_scan object.
    """
    errors: List[str] = []
    wpprobe_data: Optional[Dict[str, Any]] = None
    wpscan_data: Optional[Dict[str, Any]] = None

    tmp_fd, tmp_path = tempfile.mkstemp(prefix="wpprobe_", suffix=".json")
    os.close(tmp_fd)
    try:
        wpprobe_data, _ = run_wpprobe(
            url=url,
            mode=wpprobe_mode,
            output=tmp_path,
            timeout=wpprobe_timeout,
        )
        if wpprobe_data is None:
            errors.append("WPProbe n'a retourne aucun resultat.")
    except Exception as exc:  # pragma: no cover - depend du binaire WPProbe
        errors.append(f"WPProbe erreur: {exc}")
        _LOGGER.warning("WPProbe execution failed for %s: %s", url, exc)
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)

    if wpscan_timeout is None:
        try:
            wpscan_timeout = int(os.getenv("WPSCAN_TIMEOUT", "120"))
        except ValueError:
            wpscan_timeout = 120

    wpscan_token = os.getenv("WPSCAN_API_TOKEN") or os.getenv("WPSCAN_TOKEN")
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="wpscan_", suffix=".json")
    os.close(tmp_fd)
    try:
        wpscan_data, _ = run_wpscan(
            url=url,
            output=tmp_path,
            timeout=wpscan_timeout,
            api_token=wpscan_token,
        )
        if wpscan_data is None:
            errors.append("WPScan n'a retourne aucun resultat.")
    except Exception as exc:  # pragma: no cover - depend du binaire WPScan
        errors.append(f"WPScan erreur: {exc}")
        _LOGGER.warning("WPScan execution failed for %s: %s", url, exc)
    finally:
        with contextlib.suppress(OSError):
            os.remove(tmp_path)

    wpprobe_cves = _extract_wpprobe_cves(wpprobe_data)
    wpscan_cves = _extract_wpscan_vulnerabilities(wpscan_data)
    cves = _deduplicate_cves(wpprobe_cves + wpscan_cves)
    scanned_at = datetime.utcnow().isoformat() + "Z"

    return {
        "scanner": "wpprobe+wpscan" if wpscan_data else "wpprobe",
        "target_url": url,
        "scanned_at": scanned_at,
        "cves": cves,
        "wpprobe_report": wpprobe_data,
        "wpscan_report": wpscan_data,
        "source": "wordpress_scanner",
        "errors": errors or None,
        "stats": {
            "total_vulnerabilities": len(cves),
            "wpprobe_plugins_scanned": len((wpprobe_data or {}).get("plugins") or {}),
            "wpscan_plugins_scanned": _count_wpscan_plugins(wpscan_data),
        },
        "wpprobe_mode": wpprobe_mode,
        "wpscan_timeout": wpscan_timeout,
        "wpscan_api_token_present": bool(wpscan_token),
        "wpprobe_table": build_wpprobe_table(cves),
    }


def build_wpprobe_table(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for entry in entries or []:
        plugin_name = (entry.get("plugin") or "").strip()
        version = (entry.get("plugin_version") or "unknown").strip() or "unknown"
        if not plugin_name:
            continue
        cve = (entry.get("cve") or "").strip()
        if not cve or cve.lower() in {"n/a", "unknown", ""}:
            if version.lower() == "unknown":
                continue
            cve = None

        severity_raw = (entry.get("severity") or "info").lower()
        severity_key = severity_raw if severity_raw in VALID_SEVERITIES else "info"
        severity_rank = SEVERITY_PRIORITY.get(severity_key, 0)
        key = (plugin_name, version)

        row = rows.get(key)
        if not row:
            row = {
                "plugin": plugin_name,
                "version": version,
                "severity": severity_key.capitalize(),
                "severity_key": severity_key,
                "severity_rank": severity_rank,
                "auth_map": {},
            }
            rows[key] = row
        elif severity_rank > row.get("severity_rank", 0):
            row["severity_rank"] = severity_rank
            row["severity"] = severity_key.capitalize()
            row["severity_key"] = severity_key

        auth_label = (entry.get("auth_type") or "").strip()
        normalized_auth = auth_label.title() if auth_label else "Unknown"
        auth_map = row["auth_map"]
        if normalized_auth not in auth_map:
            auth_map[normalized_auth] = []
        if cve:
            auth_map[normalized_auth].append(cve)

    return sorted(
        rows.values(),
        key=lambda r: (-r.get("severity_rank", 0), r.get("plugin", "").lower(), r.get("version", "")),
    )
