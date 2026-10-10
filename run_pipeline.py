"""Run the complete Gatekeeper analysis pipeline."""

import sys

from core.cli.main import run_cli


DEFAULT_ARGS = ["--monitor", "fixtures/malicious-telemetry"]


def main() -> None:
    """Run Gatekeeper with forwarded CLI arguments."""
    args = sys.argv[1:] or DEFAULT_ARGS
    raise SystemExit(run_cli(args))


if __name__ == "__main__":
    main()
