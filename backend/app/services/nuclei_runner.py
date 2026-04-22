import subprocess
import json
from typing import List, Dict


def run_nuclei_scan(target: str) -> List[Dict]:
    """
    runs nuclei against a single target and returns any findings as
    a list of python dictionaries.

    example target:
        app.example.com

    why this exists:
    - dnscope should not run nuclei directly inside routes
    - this keeps scanning logic isolated in a service layer
    - routes can call this function and just work with the returned data
    """

    # build the terminal command that will run nuclei
    # -target tells nuclei what hostname to scan
    # -json tells nuclei to return machine-readable output
    command = [
        "nuclei",
        "-target", target,
        "-j"
    ]

    try:
        # run the command in the operating system shell
        # capture_output=True captures stdout/stderr so python can read it
        # text=True returns output as strings instead of bytes
        # check=False means python will not crash automatically if nuclei returns a non-zero code
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        # this list will hold all parsed nuclei findings
        findings = []

        # nuclei prints one json object per line when -json is used,
        # so we split the output into lines and parse each one
        for line in result.stdout.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                # if a line is not valid json, skip it rather than crashing
                continue

        return findings

    except Exception as e:
        # if something goes wrong when trying to run nuclei itself,
        # print an error and return an empty list so the app does not crash
        print(f"error running nuclei for target {target}: {e}")
        return []