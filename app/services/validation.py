"""
PhishGuard AI - Input Validation Module
Validates and sanitizes all user-provided email fields before
they are passed to the detection engine or stored in the database.
"""
import re
from typing import Tuple

# -------------------------------------------------------------------
# Limits
# -------------------------------------------------------------------
MAX_SENDER_LENGTH = 254       # RFC 5321 maximum email address length
MAX_SUBJECT_LENGTH = 998      # RFC 5322 recommended subject limit
MAX_BODY_LENGTH = 50_000      # ~50 KB – reasonable cap for analysis
MIN_BODY_LENGTH = 5           # Must have at least some content


def validate_email_input(
    sender: str,
    subject: str,
    body: str
) -> Tuple[bool, list[str]]:
    """
    Validate all three fields of an email submission.

    Args:
        sender:  The sender's email address (or display name + address).
        subject: The email subject line.
        body:    The full email body text.

    Returns:
        A tuple of (is_valid: bool, errors: list[str]).
        If is_valid is True, errors will be an empty list.
    """
    errors = []

    # --- Sender validation ---
    sender = sender.strip()
    if not sender:
        errors.append("Sender email address is required.")
    elif len(sender) > MAX_SENDER_LENGTH:
        errors.append(
            f"Sender address is too long (max {MAX_SENDER_LENGTH} characters)."
        )
    elif not _looks_like_email(sender):
        errors.append(
            "Sender does not appear to be a valid email address."
        )

    # --- Subject validation ---
    subject = subject.strip()
    if not subject:
        errors.append("Email subject is required.")
    elif len(subject) > MAX_SUBJECT_LENGTH:
        errors.append(
            f"Subject is too long (max {MAX_SUBJECT_LENGTH} characters)."
        )

    # --- Body validation ---
    body = body.strip()
    if not body:
        errors.append("Email body is required.")
    elif len(body) < MIN_BODY_LENGTH:
        errors.append(
            f"Email body is too short (minimum {MIN_BODY_LENGTH} characters)."
        )
    elif len(body) > MAX_BODY_LENGTH:
        errors.append(
            f"Email body is too long (max {MAX_BODY_LENGTH} characters). "
            "Please paste the relevant portion only."
        )

    return (len(errors) == 0, errors)


def sanitize_text(text: str, max_length: int = 10_000) -> str:
    """
    Strip leading/trailing whitespace and truncate to max_length.
    Does NOT remove characters — the detection engine needs the
    original content to identify phishing indicators.
    """
    return text.strip()[:max_length]


# -------------------------------------------------------------------
# Private helpers
# -------------------------------------------------------------------

# Regex that covers the vast majority of real-world email formats.
# We intentionally keep this simple – the rule engine will do
# deeper sender-domain analysis later.
_EMAIL_RE = re.compile(
    r'^[^@\s]+@[^@\s]+\.[^@\s]+$',
    re.IGNORECASE
)

# Also allow "Display Name <user@example.com>" format
_DISPLAY_EMAIL_RE = re.compile(
    r'^.+<[^@\s]+@[^@\s]+\.[^@\s]+>\s*$',
    re.IGNORECASE
)


def _looks_like_email(value: str) -> bool:
    """
    Return True if the value looks like a bare email address
    OR a display-name + address combo.
    """
    return bool(_EMAIL_RE.match(value) or _DISPLAY_EMAIL_RE.match(value))
