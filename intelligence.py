import re
import logging
from typing import List
from models import ExtractedIntelligence

logger = logging.getLogger(__name__)

# ── Pre-compiled patterns ──────────────────────────────────────────────

# Phone: 10-digit Indian numbers (starting 6-9), with optional +91/91 prefix
# Uses \b word boundary to prevent matching substrings of bank account numbers
PHONE_PATTERN = re.compile(
    r'(?<!\d)'              # not preceded by a digit
    r'(?:\+91[\s-]?|91)?'   # optional +91 or 91 prefix
    r'([6-9]\d{9})'         # capture 10-digit number starting 6-9
    r'(?!\d)',              # not followed by a digit
)

# Bank account: 9-18 digit standalone numbers
BANK_ACCOUNT_PATTERN = re.compile(r'\b(\d{9,18})\b')

# UPI: name@bankhandle (specific Indian UPI handles only)
UPI_HANDLES = (
    'ybl|paytm|oksbi|okaxis|okicici|okhdfcbank|upi|apl|axl|ibl|sbi|'
    'icici|hdfcbank|axisbank|kotak|indus|federal|barodampay|mahb|'
    'canbk|pnb|unionbank|dbs|rbl|yes|idbi|hsbc|sc|citi|bob|'
    'indianbank|iob|centralbank|allbank|pingpay|gpay|freecharge|'
    'airtel|jio|slice|jupiteraxis|postbank|dlb|kvb|kbl|'
    'abfspay|ratn|aubank|equitas|bandhan|boi|syndicate|uco|nsdl'
)
UPI_PATTERN = re.compile(
    r'[a-zA-Z0-9._\-]+@(?:' + UPI_HANDLES + r')\b',
    re.IGNORECASE
)

# Email: standard email (not UPI)
EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)

# Phishing links: http/https URLs
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')


# ── Extractors ─────────────────────────────────────────────────────────

def extract_phone_numbers(text: str) -> List[str]:
    """Extract Indian phone numbers. Returns both raw and +91 prefixed forms."""
    raw_numbers = PHONE_PATTERN.findall(text)
    result = set()
    for digits in raw_numbers:
        # digits is always the 10-digit capture group
        if len(digits) == 10:
            result.add(digits)
            result.add("+91" + digits)
    return list(result)


def extract_bank_accounts(text: str) -> List[str]:
    """Extract bank account numbers (9-18 digits), excluding phone numbers and timestamps."""
    matches = BANK_ACCOUNT_PATTERN.findall(text)
    # Get all phone numbers to exclude
    phone_digits = set(PHONE_PATTERN.findall(text))

    filtered = []
    for m in matches:
        # Skip phone numbers (10 digits starting 6-9)
        if len(m) == 10 and m[0] in "6789":
            continue
        # Skip 12-digit numbers that look like 91+phone
        if len(m) == 12 and m.startswith("91") and m[2] in "6789":
            continue
        # Skip timestamps (13-digit ms timestamps starting with 1)
        if len(m) == 13 and m.startswith("1"):
            continue
        # Skip if it's a known phone number
        if m in phone_digits:
            continue
        filtered.append(m)
    return list(set(filtered))


def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs (name@bankhandle)."""
    return list(set(UPI_PATTERN.findall(text)))


def extract_phishing_links(text: str) -> List[str]:
    """Extract suspicious URLs."""
    return list(set(URL_PATTERN.findall(text)))


def extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses, excluding UPI IDs."""
    all_emails = set(EMAIL_PATTERN.findall(text))
    upi_ids = set(extract_upi_ids(text))
    return list(all_emails - upi_ids)


def extract_all_intelligence(text: str) -> ExtractedIntelligence:
    """Extract all intelligence from a single message."""
    return ExtractedIntelligence(
        phoneNumbers=extract_phone_numbers(text),
        bankAccounts=extract_bank_accounts(text),
        upiIds=extract_upi_ids(text),
        phishingLinks=extract_phishing_links(text),
        emailAddresses=extract_email_addresses(text),
    )
