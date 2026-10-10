"""Runner Builder for Gatekeeper Extractor Engine (Block 3).

Compiles inline lifecycle commands and scripts into standalone executable bash wrappers (.sysdrift_<hook>.sh).
Ensures safe environment defaults, POSIX executable permissions, and container filesystem mapping.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Optional

from core.schema.extraction import LifecycleHookType


class RunnerBuilder:
    """Builds hermetic wrapper execution scripts for sandbox telemetry tracing."""

    @classmethod
    def build_runner_script(
        cls,
        package_dir: str | Path,
        hook_type: Optional[LifecycleHookType],
        command: str,
        output_dir: Optional[str | Path] = None,
    ) -> Path:
        """Generates an executable wrapper script for a given lifecycle hook.

        Args:
            package_dir: Root directory of the package being evaluated.
            hook_type: Lifecycle hook enum (e.g., PREINSTALL, INSTALL, POSTINSTALL).
            command: Shell command or script execution command declared in manifest.
            output_dir: Optional directory where wrapper script should be placed. Defaults to package_dir.

        Returns:
            Path object pointing to the created runner script.
        """
        pkg_path = Path(package_dir).resolve()
        target_dir = Path(output_dir).resolve() if output_dir else pkg_path
        target_dir.mkdir(parents=True, exist_ok=True)

        hook_name = hook_type.value if hook_type else "run"
        # Sanitize filename (e.g. setup.py -> setup_py)
        safe_hook_name = hook_name.replace(".", "_")
        script_filename = f".sysdrift_{safe_hook_name}.sh"
        script_path = target_dir / script_filename

        # Construct hermetic bash wrapper script
        # Header includes strict error exit (set -e), working dir anchor, and command
        script_content = f"""#!/usr/bin/env bash
# Gatekeeper Autonomous Trace Wrapper
# Hook: {hook_name}
# Target: {pkg_path.name}

set -e
# Anchor working directory to script location (compatible with container mounts)
cd "$(dirname "$0")" || true

# Execute declared lifecycle command
{command}
"""

        # Write script to disk (LF newline for Linux container / bwrap compatibility)
        with open(script_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(script_content)

        # Apply executable permission (mode 0755: rwxr-xr-x)
        try:
            current_mode = os.stat(script_path).st_mode
            os.chmod(script_path, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except OSError:
            pass  # On Windows host OS, chmod is limited; container will mount with execution

        return script_path

    @classmethod
    def cleanup_runner_script(cls, script_path: str | Path) -> bool:
        """Removes the generated runner script after execution completes."""
        try:
            p = Path(script_path)
            if p.is_file():
                p.unlink()
                return True
        except OSError:
            pass
        return False
