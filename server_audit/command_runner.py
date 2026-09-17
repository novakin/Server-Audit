"""Bounded, shell-free host command execution."""

import os
import shutil
import subprocess


def run(argv, input_text=None):
    executable = shutil.which(argv[0])
    if not executable:
        return {"status": "unavailable", "detail": "Command not installed: " + argv[0]}
    try:
        result = subprocess.run(
            [executable, *argv[1:]], capture_output=True, text=True,
            input=input_text,
            errors="replace", timeout=30, env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "error", "detail": str(error)}
    return {
        "status": "ok" if result.returncode == 0 else "error",
        "exit_code": result.returncode,
        "output": result.stdout.strip(),
        "detail": result.stderr.strip(),
    }
