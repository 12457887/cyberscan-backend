#!/usr/bin/env python3
import subprocess
import json
import os
import sys
from typing import Tuple, Optional, Sequence

WPSCAN_PATH = os.getenv("WPSCAN_PATH", "wpscan")


def run_wpscan(
    url: str,
    output: str,
    timeout: int,
    api_token: Optional[str] = None,
    extra_args: Optional[Sequence[str]] = None,
) -> Tuple[Optional[dict], Optional[str]]:
    token = api_token or os.getenv("WPSCAN_API_TOKEN") or os.getenv("WPSCAN_TOKEN")
    command = [
        WPSCAN_PATH,
        "--url", url,
        "--format", "json",
        "--output", output,
        "--random-user-agent",
    ]

    if token:
        command.extend(["--api-token", token])

    if extra_args:
        command.extend(list(extra_args))

    print(f"[+] Target      : {url}")
    print(f"[+] Output file : {output}")
    print(f"[+] Timeout     : {timeout}s\n")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        if result.stdout:
            print(result.stdout)

        if result.returncode != 0:
            print("[!] WPScan error:")
            print(result.stderr)
            return None, None

        if os.path.exists(output):
            try:
                with open(output, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (json.JSONDecodeError, OSError) as parse_error:
                print(f"[!] Impossible de lire le JSON WPScan ({parse_error})")
                return None, None

            print(f"[OK] Scan termine - resultats enregistres dans {output}")
            return data, output

        print("[!] Fichier de sortie introuvable")
        return None, None

    except FileNotFoundError:
        print(f"[!] WPScan binaire introuvable: {WPSCAN_PATH}")
        return None, None
    except subprocess.TimeoutExpired:
        print("[!] Timeout depasse - scan interrompu")
        return None, None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: wpscan_scan.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    tmp_output = "wpscan_output.json"
    data, _ = run_wpscan(target_url, tmp_output, timeout=120)
    sys.exit(0 if data is not None else 1)
