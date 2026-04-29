import json
import os
import subprocess
from typing import Dict, List


def run_nuclei_scan(target: str) -> Dict:
    """
    runs nuclei against a single target and returns scan metadata plus findings

    why this exists:
    - dnscope should not run nuclei directly inside routes
    - this keeps scanner execution isolated in a service layer
    - routes can decide how to store successful or failed scan runs
    """
    nuclei_path = os.getenv("NUCLEI_PATH", "nuclei")
    timeout_seconds = int(os.getenv("NUCLEI_TIMEOUT_SECONDS", "120"))

    command = [
        nuclei_path,
        "-target", target,
        "-j",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )

        findings: List[Dict] = []

        for line in result.stdout.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return {
            "findings": findings,
            "returncode": result.returncode,
            "stderr": result.stderr,
            "timed_out": False,
            "command": command,
        }

    except subprocess.TimeoutExpired:
        return {
            "findings": [],
            "returncode": None,
            "stderr": f"nuclei timed out after {timeout_seconds} seconds",
            "timed_out": True,
            "command": command,
        }

    except Exception as e:
        return {
            "findings": [],
            "returncode": None,
            "stderr": str(e),
            "timed_out": False,
            "command": command,
        }
