"""
Report Generator Module for Gatekeeper CLI.
Formats scan results into JSON and OASIS SARIF v2.1.0 schemas for CI/CD pipeline integration.
"""

import json
from typing import Dict, Any, Optional
from core.schema.contract import ExpectedBehaviorContract
from core.schema.telemetry import ObservedKernelTrace
from core.schema.arbitrator_models import DriftResult
from core.schema.forensics import ThreatAttributionReport


def generate_json_report(
    package_dir: str,
    contract: ExpectedBehaviorContract,
    trace: ObservedKernelTrace,
    result: DriftResult,
    forensic_report: Optional[ThreatAttributionReport] = None,
) -> str:
    """Generates structured JSON report string."""
    payload: Dict[str, Any] = {
        "gatekeeper_version": "0.1.0",
        "target_package": package_dir,
        "verdict": "QUARANTINE" if result.is_quarantined else "ALLOW",
        "exit_code": 1 if result.is_quarantined else 0,
        "composite_drift_score": result.composite_drift_score,
        "sub_scores": {
            "network_drift": result.network_drift,
            "filesystem_drift": result.filesystem_drift,
            "process_drift": result.process_drift,
        },
        "contract": contract.model_dump(),
        "observed_trace": {
            "files_read": sorted(list(trace.files_read)),
            "files_written": sorted(list(trace.files_written)),
            "network_endpoints": sorted(list(trace.network_endpoints)),
            "spawned_binaries": sorted(list(trace.spawned_binaries)),
            "timed_out": trace.timed_out,
            "execution_duration_ms": trace.execution_duration_ms,
        },
        "violations": [v.model_dump() for v in result.violations],
    }

    if forensic_report:
        payload["forensic_attribution"] = forensic_report.model_dump()

    return json.dumps(payload, indent=2)


def generate_sarif_report(
    package_dir: str,
    result: DriftResult,
    forensic_report: Optional[ThreatAttributionReport] = None,
) -> str:
    """
    Generates OASIS SARIF (Static Analysis Results Format) v2.1.0 JSON format
    for GitHub Security Code Scanning tab integration.
    """
    rules = [
        {
            "id": "GK-DRIFT-001",
            "name": "SemanticToKernelDrift",
            "shortDescription": {"text": "Semantic-to-Kernel Behavioral Drift Detected"},
            "fullDescription": {
                "text": "The package executed operations at the kernel level that diverge from its declared intent."
            },
            "defaultConfiguration": {"level": "error" if result.is_quarantined else "note"},
            "helpUri": "https://github.com/Omsupe15/gatekeeper",
        }
    ]

    sarif_results = []
    if result.is_quarantined:
        for violation in result.violations:
            rule_id = "GK-DRIFT-001"
            message_text = f"[{violation.dimension.value}] {violation.description} (Offending artifact: {violation.offending_artifact})"
            if forensic_report and forensic_report.executive_summary:
                message_text += f"\n\nForensic Detail: {forensic_report.executive_summary}"

            sarif_results.append({
                "ruleId": rule_id,
                "ruleIndex": 0,
                "level": "error",
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": package_dir.replace("\\", "/")},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Gatekeeper",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/Omsupe15/gatekeeper",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)


def write_report_to_file(content: str, output_path: str) -> None:
    """Writes string content to output file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
