#!/usr/bin/env python3

"""
Data Extraction & Secure Validation Assignment

This program extracts four types of information from raw text:
- Email addresses
- URLs
- Phone numbers
- Credit card numbers

The input is treated as untrusted. Extracted values are validated,
unsafe content is ignored, and sensitive information is masked.
"""

import json
import re
from pathlib import Path


# Project paths
BASE_DIR = Path(__file__).resolve().parents[1]
INPUT_FILE = BASE_DIR / "input" / "raw-text.txt"
OUTPUT_FILE = BASE_DIR / "output" / "sample-output.json"


# Regular expressions

# Email addresses
EMAIL_RE = re.compile(
    r"(?<![\w.+-])"
    r"[A-Za-z0-9](?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]*[A-Za-z0-9])?"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
    r"(?![\w.-])"
)


# Only HTTP and HTTPS URLs are considered valid.
URL_RE = re.compile(
    r"(?<![\w])"
    r"https?://"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}"
    r"(?::\d{2,5})?"
    r"(?:/[^\s<>'\"`\\]*)?",
    re.IGNORECASE
)


# Supports international and local phone formats.
PHONE_RE = re.compile(
    r"(?<!\w)"
    r"(?:\+\d{1,3}[\s.-]?)?"
    r"(?:\(?\d{2,4}\)?[\s.-]?)"
    r"\d{3,4}[\s.-]?\d{3,4}"
    r"(?!\w)"
)


# Credit card candidate.
# A separate Luhn check is used after matching.
CARD_RE = re.compile(
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
)


# Security checks

# Control characters that should not be processed.
CONTROL_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)


# Detect script tags.
SCRIPT_RE = re.compile(
    r"<\s*/?\s*script\b",
    re.IGNORECASE
)


# Dangerous URI schemes.
DANGEROUS_SCHEME_RE = re.compile(
    r"\b(?:javascript|data|file|vbscript)\s*:",
    re.IGNORECASE
)


def clean_text(text):
    """Clean unsafe control characters and record warnings."""

    warnings = []

    if CONTROL_RE.search(text):
        warnings.append(
            "Control characters detected and removed."
        )

    if SCRIPT_RE.search(text):
        warnings.append(
            "Script-like HTML detected; unsafe markup was ignored."
        )

    if DANGEROUS_SCHEME_RE.search(text):
        warnings.append(
            "Dangerous URI scheme detected; only HTTP/HTTPS URLs are accepted."
        )

    safe_text = CONTROL_RE.sub("", text)

    return safe_text, warnings


def suspicious_context(text, start, end):
    """
    Check nearby text for common injection or script patterns.
    """

    context = text[
        max(0, start - 40):min(len(text), end + 120)
    ].lower()

    sql_markers = (
        " or '1'='1",
        ' or "1"="1',
        "drop table",
        "union select",
    )

    script_markers = (
        "<script",
        "</script",
        "javascript:",
        "data:text/html",
    )

    return any(
        marker in context
        for marker in sql_markers + script_markers
    )



# Validation

def valid_email(email):
    """Check that an extracted email is properly formed."""

    if len(email) > 254:
        return False

    if ".." in email:
        return False

    local, domain = email.rsplit("@", 1)

    if len(local) > 64:
        return False

    # Required ALU domains.
    alu_domains = {
        "alueducation.com",
        "alumni.alueducation.com",
        "si.alueducation.com",
    }

    # Apply the same local-part validation to ALU addresses.
    if domain.lower() in alu_domains:
        return bool(
            re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]*[A-Za-z0-9])?",
                local
            )
        )

    return True


def valid_phone(candidate):
    """Check that the candidate has a realistic number of digits."""

    digits = re.sub(r"\D", "", candidate)

    # Accept common phone lengths.
    if not 7 <= len(digits) <= 15:
        return False

    # Avoid accepting credit-card-like groups as phone numbers.
    groups = re.split(r"[ -]+", candidate.strip())

    four_digit_groups = sum(
        group.isdigit() and len(group) == 4
        for group in groups
    )

    if len(groups) >= 3 and four_digit_groups >= 3:
        return False

    return True


def valid_url(url):
    """Accept HTTP/HTTPS URLs and reject unsafe content."""

    if len(url) > 2048:
        return False

    if DANGEROUS_SCHEME_RE.search(url):
        return False

    if any(char in url for char in ["<", ">", '"', "'"]):
        return False

    return bool(
        re.fullmatch(
            r"https?://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}"
            r"(?::\d{2,5})?"
            r"(?:/[^\s<>'\"`\\]*)?",
            url,
            re.IGNORECASE
        )
    )


def normalize_card(candidate):
    """Remove spaces and hyphens from a card candidate."""

    return re.sub(r"[ -]", "", candidate)


def luhn_valid(number):
    """Check whether a card number passes the Luhn algorithm."""

    total = 0
    parity = len(number) % 2

    for index, digit in enumerate(number):
        value = int(digit)

        if index % 2 == parity:
            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


# Data protection

def mask_email(email):
    """Mask most of the email username."""

    local, domain = email.split("@", 1)

    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = (
            local[0]
            + "*" * (len(local) - 2)
            + local[-1]
        )

    return f"{masked_local}@{domain}"


def mask_card(number):
    """Show only the last four digits of a card."""

    return "*" * (len(number) - 4) + number[-4:]


def unique(items):
    """Remove duplicates without changing their order."""

    return list(dict.fromkeys(items))


# Extraction

def extract_data(text):
    """Extract and validate data from the input."""

    safe_text, warnings = clean_text(text)

    # Emails

    emails = []

    for match in EMAIL_RE.finditer(safe_text):
        email = match.group(0)

        if (
            valid_email(email)
            and not suspicious_context(
                safe_text,
                match.start(),
                match.end()
            )
        ):
            emails.append(email)

    emails = unique(emails)

    
    # URLs

    urls = []

    for match in URL_RE.finditer(safe_text):
        url = match.group(0).rstrip(".,;:!?)]}")

        if (
            valid_url(url)
            and not suspicious_context(
                safe_text,
                match.start(),
                match.end()
            )
        ):
            urls.append(url)

    urls = unique(urls)

    # Phone numbers

    phones = []

    for match in PHONE_RE.finditer(safe_text):
        phone = match.group(0).strip()

        if (
            valid_phone(phone)
            and not suspicious_context(
                safe_text,
                match.start(),
                match.end()
            )
        ):
            phones.append(phone)

    phones = unique(phones)

    # Credit cards

    cards = []

    for match in CARD_RE.finditer(safe_text):
        candidate = normalize_card(match.group(0))

        if (
            13 <= len(candidate) <= 19
            and luhn_valid(candidate)
            and not suspicious_context(
                safe_text,
                match.start(),
                match.end()
            )
        ):
            cards.append(candidate)

    cards = unique(cards)

    # ALU-specific validation

    alu_official = [
        email for email in emails
        if email.lower().endswith("@alueducation.com")
    ]

    alu_alumni = [
        email for email in emails
        if email.lower().endswith("@alumni.alueducation.com")
    ]

    alu_si = [
        email for email in emails
        if email.lower().endswith("@si.alueducation.com")
    ]

    # Final output

    return {
        "security": {
            "input_treated_as_untrusted": True,
            "sensitive_values_masked": True,
            "full_card_numbers_written_to_output": False,
            "warnings": unique(warnings)
        },

        "extracted": {
            "emails": [
                mask_email(email)
                for email in emails
            ],
            "urls": urls,
            "phone_numbers": phones,
            "credit_cards": [
                mask_card(card)
                for card in cards
            ]
        },

        "alu_email_validation": {
            "official_alueducation_com": [
                mask_email(email)
                for email in alu_official
            ],
            "alumni_alueducation_com": [
                mask_email(email)
                for email in alu_alumni
            ],
            "si_alueducation_com": [
                mask_email(email)
                for email in alu_si
            ]
        },

        "counts": {
            "valid_emails": len(emails),
            "valid_urls": len(urls),
            "valid_phone_numbers": len(phones),
            "valid_credit_cards": len(cards)
        }
    }


# Main

def main():
    """Read the input, process it and save the results."""

    text = INPUT_FILE.read_text(encoding="utf-8")

    result = extract_data(text)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_FILE.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    print("Extraction completed successfully.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()