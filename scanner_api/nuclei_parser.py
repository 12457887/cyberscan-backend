import json
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def parse_nuclei_output(stdout: str) -> List[Dict[str, Any]]:
    """
    Parse Nuclei JSONL output (v3+).
    Handles polluted lines and mixed output safely.
    """

    parsed_results: List[Dict[str, Any]] = []

    if not stdout:
        return parsed_results

    for line in stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        # ✅ Ignore non-JSON lines safely
        if not line.startswith("{"):
            continue

        try:
            data = json.loads(line)
            info = data.get("info") or {}

            result = {
                "template_id": data.get("template-id") or data.get("template_id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "description": info.get("description"),
                "reference": info.get("reference", []),
                "tags": info.get("tags", []),
                "host": data.get("host"),
                "matched_at": data.get("matched-at"),
                "ip": data.get("ip"),
                "protocol": data.get("type"),
                "extracted_results": (
                    data.get("extracted-results")
                    or data.get("extracted_results")
                ),
                "matcher_name": data.get("matcher-name"),
                "timestamp": data.get("timestamp"),
            }

            parsed_results.append(result)

        except Exception as e:
            logger.debug("Skipping invalid nuclei JSON line: %s | Error: %s", line, e)
            continue

    return parsed_results
