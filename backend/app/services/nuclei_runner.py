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
    template_dir = os.getenv("DNSCOPE_TEMPLATE_DIR")

    command = [
        nuclei_path,
        "-target", target,
    ]

    # when a template directory is configured, use dnscope's focused template set
    if template_dir:
        command.extend(["-t", template_dir])

    # return one json object per finding so dnscope can parse results reliably
    command.append("-j")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )

        findings: List[Dict] = []

        # nuclei should return json lines on stdout, but stdout can be empty or none on failure
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        for line in stdout.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return {
            "findings": findings,
            "returncode": result.returncode,
            "stdout_preview": stdout[:1000],
            "stderr": stderr,
            "stderr_preview": stderr[:1000],
            "timed_out": False,
            "command": command,
        }

    except subprocess.TimeoutExpired as e:
        return {
            "findings": [],
            "returncode": None,
            "stdout_preview": "",
            "stderr": e.stderr or f"nuclei timed out after {timeout_seconds} seconds",
            "stderr_preview": e.stderr or f"nuclei timed out after {timeout_seconds} seconds",
            "timed_out": True,
            "command": command,
        }

    except Exception as e:
        return {
            "findings": [],
            "returncode": None,
            "stdout_preview": "",
            "stderr": str(e),
            "stderr_preview": str(e),
            "timed_out": False,
            "command": command,
        }
