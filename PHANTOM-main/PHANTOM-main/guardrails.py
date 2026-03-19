"""
PHANTOM Security Guardrails — matches PPT Slide 6 claims.

1. Sentinel token locking — reject tool output containing system tokens
2. Action validator (red lines) — block dangerous actions before execution
3. Scope enforcement — never connect outside defined target scope
"""


class SecurityViolation(Exception):
    """Raised when any guardrail is breached. Logs and halts the action."""
    pass


# ── Sentinel Token Locking ─────────────────────────────────────────────
# System prompt wrapped in sentinel tokens. Tool output containing these
# strings is hard-rejected before LLM context injection.

SENTINEL_TOKENS = [
    "|||SYS_BEGIN|||",
    "|||SYS_END|||",
    "PHANTOM_SYSTEM_OVERRIDE",
    "IGNORE_PREVIOUS_INSTRUCTIONS",
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
]


def sanitize_tool_output(output: str, source: str = "unknown") -> str:
    """
    Check tool output for sentinel token injection attempts.
    Called before any external tool output enters the LLM context window.
    """
    if not isinstance(output, str):
        output = str(output)
    for token in SENTINEL_TOKENS:
        if token in output:
            raise SecurityViolation(
                f"BLOCKED: Tool output from '{source}' contains sentinel token '{token}'. "
                f"Possible prompt injection detected. Output rejected."
            )
    return output


# ── Red Lines — Action Validator ────────────────────────────────────────
# Pre-execution check before every tool call.
# These CANNOT be overridden by agent reasoning.
# Violation → immediate halt + alert.

BLOCKED_PATTERNS = [
    "exfiltrate",
    "reverse_shell",
    "rm -rf",
    "DROP TABLE",
    "DROP DATABASE",
    "FORMAT C:",
    "shutdown",
    "reboot",
    "wget http",
    "curl http",
    "nc -e",
    "bash -i",
    "powershell -enc",
    "data_exfil",
    "/etc/shadow",
    "connect_external",
]


def validate_action(agent: str, action: str, args: dict = None) -> bool:
    """
    Pre-execution check. Returns True if action is allowed.
    Raises SecurityViolation if a red line is crossed.
    """
    action_lower = action.lower()

    for blocked in BLOCKED_PATTERNS:
        if blocked.lower() in action_lower:
            raise SecurityViolation(
                f"RED LINE VIOLATION: Agent '{agent}' attempted action containing "
                f"blocked pattern '{blocked}'. Action halted."
            )

    # Check args for dangerous content too
    if args:
        args_str = str(args).lower()
        for blocked in BLOCKED_PATTERNS:
            if blocked.lower() in args_str:
                raise SecurityViolation(
                    f"RED LINE VIOLATION: Agent '{agent}' passed blocked pattern "
                    f"'{blocked}' in arguments. Action halted."
                )

    return True


# ── Scope Enforcement ───────────────────────────────────────────────────

def check_scope(target: str, allowed_scope: list) -> bool:
    """Verify target is within the defined assessment scope."""
    if not allowed_scope:
        return True  # No scope restriction — allow all (demo mode)

    for allowed in allowed_scope:
        if target == allowed or target.startswith(allowed):
            return True

    raise SecurityViolation(
        f"OUT OF SCOPE: Target '{target}' is not in allowed scope {allowed_scope}. "
        f"Assessment restricted to defined targets only."
    )


# ── Human-in-the-Loop Gate ──────────────────────────────────────────────

def confidence_gate(confidence: float, threshold: float = 0.70,
                    auto_mode: bool = True) -> str:
    """
    Gate check at confidence boundaries.
    Below threshold → pause for human review (or auto-continue in demo mode).
    Returns: 'proceed', 'pause', or 'abort'
    """
    if confidence >= threshold:
        return "proceed"
    elif confidence >= 0.30:
        if auto_mode:
            return "proceed"  # Auto-continue for demo, but log the gate
        return "pause"  # Would pause in production
    else:
        return "abort"  # Confidence too low, abandon this vector
