#!/usr/bin/env python3
import subprocess
import argparse
import json
import os
import sys
from typing import Tuple, Optional

WPPROBE_PATH = os.getenv(
    "WPPROBE_PATH",
    "/home/ubuntu/go/bin/wpprobe"
)

def run_wpprobe(url: str, mode: str, output: str, timeout: int) -> Tuple[Optional[dict], Optional[str]]:
    command = [
        WPPROBE_PATH,
        "scan",
        "-u", url,
        "--mode", mode,
        "-o", output
    ]

    print(f"[+] Target      : {url}")
    print(f"[+] Mode        : {mode}")
    print(f"[+] Output file : {output}")
    print(f"[+] Timeout     : {timeout}s\n")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        print(result.stdout)

        if result.returncode != 0:
            print("[!] WPProbe error:")
            print(result.stderr)
            return None, None

        if os.path.exists(output):
            try:
                with open(output, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
            except (json.JSONDecodeError, OSError) as parse_error:
                print(f"[!] Impossible de lire le JSON WPProbe ({parse_error})")
                return None, None

            print(f"[✓] Scan terminé – résultats enregistrés dans {output}")
            return data, output
        else:
            print("[!] Fichier de sortie introuvable")
            return None, None

    except subprocess.TimeoutExpired:
        print("[!] Timeout dépassé – scan interrompu")
        return None, None


def main():
    parser = argparse.ArgumentParser(
        description="Fast & stealthy WordPress plugin + CVE scanner (WPProbe wrapper)"
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="URL du site WordPress (ex: https://example.com)"
    )

    parser.add_argument(
        "-m", "--mode",
        default="stealthy",
        choices=["stealthy", "bruteforce", "hybrid"],
        help="Mode de scan (default: stealthy)"
    )

    parser.add_argument(
        "-o", "--output",
        default="plugins_cve.json",
        help="Fichier de sortie JSON"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=40,
        help="Timeout en secondes (default: 40)"
    )

    args = parser.parse_args()

    data, _ = run_wpprobe(
        url=args.url,
        mode=args.mode,
        output=args.output,
        timeout=args.timeout
    )

    sys.exit(0 if data is not None else 1)


if __name__ == "__main__":
    main()
