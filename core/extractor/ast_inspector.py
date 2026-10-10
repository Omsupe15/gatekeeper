"""AST Inspector & Obfuscation Analyzer for Gatekeeper Extractor Engine (Block 3).

Performs passive static analysis of lifecycle code across JavaScript, Python, and Shell scripts.
Identifies dangerous call-chains, sensitive asset references, and high-entropy obfuscated strings.
"""

from __future__ import annotations

import ast
import collections
import math
import re
from typing import List, Optional

from core.schema.extraction import ASTSuspiciousToken


# High-entropy threshold for base64 / encrypted string payloads (Shannon entropy >= 4.5)
HIGH_ENTROPY_THRESHOLD = 4.5
MIN_STRING_LENGTH_FOR_ENTROPY = 20

# Dangerous indicators across JavaScript and Python
DANGEROUS_PATTERNS = [
    # Process execution
    (r"\b(child_process|exec|execSync|spawn|spawnSync|fork)\b", "ProcessExecution", "child_process execution"),
    (r"\b(subprocess|os\.system|os\.popen|os\.spawn|posix_spawn)\b", "ProcessExecution", "subprocess execution"),
    # Code injection & Dynamic evaluation
    (r"\b(eval|Function|vm\.runInThisContext|vm\.runInNewContext)\b", "DynamicEvaluation", "dynamic code execution"),
    (r"\b(exec\(|eval\()", "DynamicEvaluation", "Python dynamic evaluation"),
    # Network sockets & egress
    (r"\b(net\.connect|net\.createConnection|dgram\.createSocket)\b", "NetworkEgress", "raw network socket connection"),
    (r"\b(http\.request|https\.request|fetch|axios|needle)\b", "NetworkEgress", "HTTP egress request"),
    (r"\b(socket\.socket|socket\.connect|urllib\.request|requests\.(get|post|put))\b", "NetworkEgress", "Python socket or HTTP request"),
    # Sensitive credential targets
    (r"(\.aws/credentials|\.ssh/id_|\.env|\.kube/config|/etc/shadow|/etc/passwd)", "CredentialAccess", "sensitive filesystem target accessed"),
    # Obfuscation & Buffer operations
    (r"\b(Buffer\.from\(.+['\"]base64['\"]\)|atob\(|btoa\()", "Obfuscation", "base64 encoding or decoding"),
    (r"\b(base64\.b64decode|binascii\.unhexlify)\b", "Obfuscation", "base64/hex decoding"),
    # Shell exfiltration utilities
    (r"\b(curl|wget|nc|netcat|ncat|bash\s+-i|sh\s+-i)\b", "ShellUtility", "suspicious shell exfiltration utility"),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string to detect high-entropy obfuscated blobs.

    H(X) = -sum(P(x) * log2(P(x)))
    """
    if not data:
        return 0.0

    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


class ASTInspector:
    """Passively inspects script code for security-critical tokens without execution."""

    @classmethod
    def inspect_code(cls, source_code: str, filename: str = "<inline>") -> List[ASTSuspiciousToken]:
        """Analyzes source code and returns a list of detected suspicious AST tokens.

        Args:
            source_code: The raw script or command string.
            filename: The source filename or label.

        Returns:
            List of ASTSuspiciousToken instances.
        """
        if not source_code or not source_code.strip():
            return []

        tokens: List[ASTSuspiciousToken] = []
        lines = source_code.splitlines()

        # 1. Regex-based pattern matching (works across polyglot scripts & inline commands)
        for line_num, line in enumerate(lines, start=1):
            stripped_line = line.strip()
            if not stripped_line or stripped_line.startswith("#") or stripped_line.startswith("//"):
                continue

            for pattern, token_type, identifier in DANGEROUS_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    matched_str = match.group(0)
                    tokens.append(
                        ASTSuspiciousToken(
                            token_type=token_type,
                            identifier=matched_str,
                            line_number=line_num,
                            snippet=line.strip()[:160],
                            entropy_score=None,
                        )
                    )

            # 2. String literal entropy analysis for obfuscated payloads
            # Extract quoted strings: '...', "...", `...`
            string_literals = re.findall(r"['\"`]{1}([^'\"`]{20,})['\"`]{1}", line)
            for lit in string_literals:
                entropy = calculate_shannon_entropy(lit)
                if entropy >= HIGH_ENTROPY_THRESHOLD:
                    tokens.append(
                        ASTSuspiciousToken(
                            token_type="HighEntropyString",
                            identifier=f"entropy={entropy:.2f}",
                            line_number=line_num,
                            snippet=lit[:80] + "..." if len(lit) > 80 else lit,
                            entropy_score=entropy,
                        )
                    )

        # 3. Python-specific AST deep inspection if valid Python syntax
        try:
            py_tree = ast.parse(source_code, filename=filename)
            py_tokens = cls._inspect_python_ast(py_tree, lines)
            # Avoid duplicate line+identifier entries
            existing_signatures = {(t.line_number, t.identifier) for t in tokens}
            for pt in py_tokens:
                if (pt.line_number, pt.identifier) not in existing_signatures:
                    tokens.append(pt)
        except (SyntaxError, ValueError):
            pass

        return tokens

    @classmethod
    def _inspect_python_ast(cls, tree: ast.AST, lines: List[str]) -> List[ASTSuspiciousToken]:
        """Deep AST inspection for Python lifecycle code."""
        py_tokens: List[ASTSuspiciousToken] = []

        for node in ast.walk(tree):
            line_no = getattr(node, "lineno", 1)
            line_snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""

            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ("subprocess", "socket", "urllib", "requests", "shutil", "base64"):
                        py_tokens.append(
                            ASTSuspiciousToken(
                                token_type="Import",
                                identifier=alias.name,
                                line_number=line_no,
                                snippet=line_snippet[:160],
                                entropy_score=None,
                            )
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module in ("subprocess", "socket", "os", "urllib", "requests", "base64"):
                    py_tokens.append(
                        ASTSuspiciousToken(
                            token_type="ImportFrom",
                            identifier=node.module,
                            line_number=line_no,
                            snippet=line_snippet[:160],
                            entropy_score=None,
                        )
                    )

            # Check function calls
            elif isinstance(node, ast.Call):
                func_id = None
                if isinstance(node.func, ast.Name):
                    func_id = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_id = node.func.attr

                if func_id in ("eval", "exec", "system", "popen", "connect", "b64decode"):
                    py_tokens.append(
                        ASTSuspiciousToken(
                            token_type="CallExpression",
                            identifier=func_id,
                            line_number=line_no,
                            snippet=line_snippet[:160],
                            entropy_score=None,
                        )
                    )

        return py_tokens
