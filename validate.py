"""
validate.py - Three-layer prompt-injection defence (capstone version of Project 2).

Control layers 2 and 3:
  * validate_input()  - Layer 1 (length limit) and Layer 2 (regex blocklist)
  * scan_output()     - Layer 3 (canary / credential / unsolicited-URL scanner)

Changes from the Project 2 module:
  1. scan_output() no longer contains hardcoded secrets. Prompt leakage is
     detected with a random canary tag plus verbatim-excerpt matching against the
     protected instruction block, so this file stays clean for Gitleaks.
  2. check_external_url() no longer allows any domain that merely CONTAINS the
     word "techcorp" (that let evil-techcorp.attacker.com through). A domain must
     now equal an allowed domain or be a subdomain of one.
"""
import re
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Layer 1: maximum input length
# ---------------------------------------------------------------------------
MAX_LENGTH: int = 500

# ---------------------------------------------------------------------------
# Layer 2: regex injection / role-play blocklist
# ---------------------------------------------------------------------------
INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(prior|previous)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+instruction\s+override", re.IGNORECASE),
    # Persona and role-play hijack patterns
    re.compile(r"you\s+are\s+now", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+are", re.IGNORECASE),
    re.compile(r"act\s+as\s+if\s+you\s+have\s+no", re.IGNORECASE),
    re.compile(r"\bDAN\b.*no\s+restrictions", re.IGNORECASE),
    re.compile(r"developer\s+mode\s+(enabled|active)", re.IGNORECASE),
    # Base64-encoded payload (40+ continuous base64 characters)
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
]

# ---------------------------------------------------------------------------
# Layer 3: output scanner patterns
# ---------------------------------------------------------------------------
CREDENTIAL_PATTERNS = [
    re.compile(r"password\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"api_key\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"token\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9_-]{20,}", re.IGNORECASE),
    re.compile(r"postgresql://\S+:\S+@\S+", re.IGNORECASE),
]

ALLOWED_DOMAINS = [
    "localhost",
    "127.0.0.1",
    "techcorp.local",
    "techcorp.com",
    "internal.techcorp.local",
]


def check_external_url(text: str) -> Optional[str]:
    """Return the first URL in `text` whose host is not on the allow-list."""
    urls = re.findall(r"https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s]*)?", text, re.IGNORECASE)
    for url in urls:
        host = url.split("://", 1)[1].split("/", 1)[0].split(":")[0].lower()
        allowed = any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)
        if not allowed:
            return url
    return None


def validate_input(user_input) -> Tuple[bool, Optional[str]]:
    """Layer 1 + Layer 2. Returns (True, None) if clean, else (False, message)."""
    if not user_input or not isinstance(user_input, str):
        return False, "Input cannot be empty and must be a text string."

    # Layer 1: length
    if len(user_input) > MAX_LENGTH:
        return False, (
            f"Input rejected by Layer 1 (Length Validator): Length ({len(user_input)} chars) "
            f"exceeds maximum limit of {MAX_LENGTH} characters."
        )

    # Layer 2: regex blocklist
    for pattern in INJECTION_PATTERNS:
        match = pattern.search(user_input)
        if match:
            text = match.group(0)
            shown = text if len(text) <= 50 else text[:47] + "..."
            return False, (
                "Input rejected by Layer 2 (Regex Blocklist): "
                f"Detected disallowed injection pattern '{shown}'."
            )

    return True, None


def _words(text: str):
    """Lower-case word list with punctuation stripped, for excerpt matching."""
    return re.findall(r"[a-z0-9']+", text.lower())


def contains_excerpt(response_text: str, protected_text: str, window: int = 8) -> bool:
    """True if the response repeats `window` or more consecutive words of the
    protected text (a verbatim excerpt, even if only part of it is leaked)."""
    protected = _words(protected_text)
    if len(protected) < window:
        return False
    shingles = {tuple(protected[i:i + window]) for i in range(len(protected) - window + 1)}
    reply = _words(response_text)
    return any(tuple(reply[i:i + window]) in shingles for i in range(len(reply) - window + 1))


def scan_output(
    response_text: str,
    canary: Optional[str] = None,
    protected_text: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """Layer 3. Returns (True, None) if the model output is safe to release,
    else (False, message). The message is for logs and the caller; the raw
    model text is never returned to the client when this check fails.

    protected_text is the internal instruction block of the system prompt. Any
    verbatim excerpt of it (8+ consecutive words) or the canary tag blocks the
    response. Shareable company notes are deliberately NOT protected, so normal
    answers that quote them are not blocked."""
    if not response_text:
        return True, None

    # 1. System-prompt leakage: canary tag, or a verbatim excerpt of the instructions
    leaked = bool(canary and canary in response_text) or bool(
        protected_text and contains_excerpt(response_text, protected_text)
    )
    if leaked:
        return False, "Response blocked by Layer 3 (Output Scanner): output contains system prompt content."

    # 2. Credential patterns
    for pattern in CREDENTIAL_PATTERNS:
        if pattern.search(response_text):
            return False, (
                "Response blocked by Layer 3 (Output Scanner): output contains credential "
                "patterns (password, api_key, token or database URI)."
            )

    # 3. Unsolicited external URLs
    bad_url = check_external_url(response_text)
    if bad_url:
        return False, f"Response blocked by Layer 3 (Output Scanner): output contains unapproved external URL '{bad_url}'."

    return True, None
