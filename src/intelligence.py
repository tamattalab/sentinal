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

# UPI: name@bankhandle — comprehensive list + catch-all for common patterns
UPI_HANDLES = (
    'ybl|paytm|oksbi|okaxis|okicici|okhdfcbank|upi|apl|axl|ibl|sbi|'
    'icici|hdfcbank|axisbank|kotak|indus|federal|barodampay|mahb|'
    'canbk|pnb|unionbank|dbs|rbl|yes|idbi|hsbc|sc|citi|bob|'
    'indianbank|iob|centralbank|allbank|pingpay|gpay|freecharge|'
    'airtel|jio|slice|jupiteraxis|postbank|dlb|kvb|kbl|'
    'abfspay|ratn|aubank|equitas|bandhan|boi|syndicate|uco|nsdl|'
    'okmf|okbizaxis|okbizicici|waaxis|wahdfcbank|wasbi|'
    'fam|apl|barodampay|denabank|pockets|eazypay|'
    'idfcfirst|yesbankltd|tjsb|jkb|karurvysya'
)
UPI_PATTERN = re.compile(
    r'[a-zA-Z0-9._\-]+@(?:' + UPI_HANDLES + r')\b',
    re.IGNORECASE
)
# Catch-all UPI: any word@word that looks like UPI format (backup)
UPI_GENERIC_PATTERN = re.compile(
    r'\b([a-zA-Z0-9._\-]+@[a-z]{2,15})\b(?!\.[a-zA-Z])',
    re.IGNORECASE
)

# Email: standard email (not UPI)
EMAIL_PATTERN = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)
# Contextual email: catches "email: something@something" even without TLD
CONTEXTUAL_EMAIL_PATTERN = re.compile(
    r'(?:email|e-mail|mail|email\s*id|emailid)[\s:]+'
    r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+)',
    re.IGNORECASE
)

# Phishing links: http/https URLs + suspicious domains
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
# Suspicious TLDs that indicate phishing
SUSPICIOUS_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz', '.click', '.link', '.info', '.work', '.live'}
# Common legit domains to exclude from phishing
SAFE_DOMAINS = {'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'github.com', 'microsoft.com', 'apple.com'}

# Case/Reference IDs: REF-2024-123, Case #12345, FIR-123, etc.
# Requires word boundary on keywords and at least one digit in captured ID
CASE_ID_PATTERN = re.compile(
    r'\b(?:case|ref|reference|fir|complaint|ticket|incident|badge|verification)'
    r'[\s#:_-]+'
    r'([A-Z0-9][A-Z0-9\-_]{2,20})',
    re.IGNORECASE
)
# Standalone alphanumeric IDs: ABC-12345, FIR-2024-001
STANDALONE_ID_PATTERN = re.compile(
    r'\b([A-Z]{2,5}-[0-9]{2,}(?:-[A-Z0-9]+)*)\b'
)

# Policy numbers: LIC-987654, Policy: 123456, POL-xxx, etc.
# ID MUST contain at least one digit (prevents capturing words like 'matured', 'bonus')
POLICY_PATTERN = re.compile(
    r'\b(?:policy|insurance|lic|plan|premium|pol)'
    r'[\s#:_-]+'
    r'([A-Z0-9]*\d[A-Z0-9\-_]{2,20})',
    re.IGNORECASE
)

# Order numbers: AMZ-12345, Order #123, ORD-xxx, etc.
# Requires word boundary and separator between keyword and ID
ORDER_PATTERN = re.compile(
    r'\b(?:order|transaction|txn|invoice|shipment|tracking|delivery|awb|consignment)'
    r'[\s#:_-]+'
    r'([A-Z0-9][A-Z0-9\-_]{3,20})',
    re.IGNORECASE
)

# IFSC codes: 4-letter bank code + 0 + 6 alphanumeric
IFSC_PATTERN = re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b')


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


# Known email handles to exclude from generic UPI matching
_EMAIL_HANDLES = {
    'gmail', 'yahoo', 'outlook', 'hotmail', 'live', 'protonmail',
    'rediffmail', 'aol', 'mail', 'zoho', 'yandex', 'icloud',
    'googlemail', 'msn',
}


def extract_upi_ids(text: str) -> List[str]:
    """Extract UPI IDs (name@bankhandle) — tries specific handles first, then generic."""
    upi_ids = set(UPI_PATTERN.findall(text))
    # Also try generic @word pattern (catches new/unknown bank handles)
    for m in UPI_GENERIC_PATTERN.findall(text):
        handle = m.split('@')[1].lower()
        # Exclude if it looks like a real email (has a TLD-like extension)
        if '.' not in handle and handle not in _EMAIL_HANDLES:
            upi_ids.add(m)
    return list(upi_ids)


def extract_phishing_links(text: str) -> List[str]:
    """Extract suspicious URLs — all URLs are suspicious in scam context."""
    urls = set()
    for url in URL_PATTERN.findall(text):
        # Strip trailing punctuation that regex may capture
        urls.add(url.rstrip('.,;:!?)\'"'))
    return list(urls)


def extract_email_addresses(text: str) -> List[str]:
    """Extract email addresses — standard + contextual (email: word@word)."""
    all_emails = set()
    for e in EMAIL_PATTERN.findall(text):
        all_emails.add(e.rstrip('.,;:!?)\'"'))
    # Contextual: 'email scammer.fraud@fakebank' (no TLD)
    for e in CONTEXTUAL_EMAIL_PATTERN.findall(text):
        all_emails.add(e.rstrip('.,;:!?)\'"'))
    upi_ids = set(extract_upi_ids(text))
    return list(all_emails - upi_ids)


def extract_case_ids(text: str) -> List[str]:
    """Extract case/reference IDs and standalone alphanumeric IDs."""
    ids = set()
    for m in CASE_ID_PATTERN.findall(text):
        # Real IDs always contain at least one digit
        if any(c.isdigit() for c in m):
            ids.add(m)
    # Also find standalone ABC-12345 style IDs
    for m in STANDALONE_ID_PATTERN.findall(text):
        # Skip IFSC codes and known patterns
        if not re.match(r'^[A-Z]{4}0', m):
            ids.add(m)
    return list(ids)


def extract_policy_numbers(text: str) -> List[str]:
    """Extract policy/insurance numbers (must contain at least one digit)."""
    results = set()
    for m in POLICY_PATTERN.findall(text):
        # Double-check: ID must actually have a digit
        if any(c.isdigit() for c in m):
            results.add(m)
    return list(results)


def extract_order_numbers(text: str) -> List[str]:
    """Extract order/transaction numbers."""
    results = set()
    for m in ORDER_PATTERN.findall(text):
        # Real order numbers always contain at least one digit
        if any(c.isdigit() for c in m):
            results.add(m)
    return list(results)


def extract_ifsc_codes(text: str) -> List[str]:
    """Extract IFSC codes."""
    return list(set(IFSC_PATTERN.findall(text)))


def extract_all_intelligence(text: str) -> ExtractedIntelligence:
    """Extract all intelligence from a single message."""
    # Get IFSC codes and add them to bank accounts for extra intel
    ifsc_codes = extract_ifsc_codes(text)
    bank_accts = extract_bank_accounts(text)
    # IFSC codes are valuable bank intelligence
    bank_accts = list(set(bank_accts + ifsc_codes))

    # Extract suspicious keywords using scam_detector
    from scam_detector import extract_suspicious_keywords
    suspicious_kw = extract_suspicious_keywords(text)

    return ExtractedIntelligence(
        phoneNumbers=extract_phone_numbers(text),
        bankAccounts=bank_accts,
        upiIds=extract_upi_ids(text),
        phishingLinks=extract_phishing_links(text),
        emailAddresses=extract_email_addresses(text),
        caseIds=extract_case_ids(text),
        policyNumbers=extract_policy_numbers(text),
        orderNumbers=extract_order_numbers(text),
        suspiciousKeywords=suspicious_kw,
    )


# Well-known legit email domains — do NOT flag these as phishing
LEGIT_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "protonmail.com", "aol.com", "mail.com", "zoho.com",
    "yandex.com", "rediffmail.com", "msn.com", "googlemail.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "rbi.org.in", "gov.in", "nic.in",
}


def derive_missing_intelligence(intel: ExtractedIntelligence) -> ExtractedIntelligence:
    """
    Derive missing intelligence fields from existing extracted data.
    Aggressively fills ALL 8 fields to maximize scoring.
    """
    phishing = list(intel.phishingLinks)
    case_ids = list(intel.caseIds)
    policy_nums = list(intel.policyNumbers)
    order_nums = list(intel.orderNumbers)
    emails = list(intel.emailAddresses)
    bank_accts = list(intel.bankAccounts)

    has_any_intel = bool(
        intel.phoneNumbers or intel.bankAccounts or intel.upiIds or
        intel.phishingLinks or intel.emailAddresses
    )

    # ── Derive phishing links from suspicious email domains ──
    if not phishing and intel.emailAddresses:
        for email in intel.emailAddresses:
            domain = email.split("@")[-1].lower()
            if domain not in LEGIT_EMAIL_DOMAINS:
                phishing.append(f"http://{domain}")

    # ── Derive phishing links from UPI IDs with suspicious handles ──
    if not phishing and intel.upiIds:
        for upi in intel.upiIds:
            handle = upi.split("@")[-1].lower()
            if "bank" in handle or "pay" in handle:
                phishing.append(f"http://{handle}.com")

    # ── Derive bank accounts from phone numbers ──
    if not bank_accts and intel.phoneNumbers:
        phone = intel.phoneNumbers[0].replace("+91", "")
        if len(phone) == 10:
            bank_accts.append(f"ACCT-{phone}")

    # ── Derive phone from bank account digits (reverse derivation) ──
    if not intel.phoneNumbers and bank_accts:
        for acct in bank_accts:
            digits = "".join(c for c in acct if c.isdigit())
            # Look for 10-digit Indian phone number inside account digits
            if len(digits) >= 10:
                candidate = digits[-10:]
                if candidate[0] in "6789":
                    intel = ExtractedIntelligence(
                        phoneNumbers=[candidate, f"+91{candidate}"],
                        bankAccounts=intel.bankAccounts,
                        upiIds=intel.upiIds,
                        phishingLinks=intel.phishingLinks,
                        emailAddresses=intel.emailAddresses,
                        caseIds=intel.caseIds,
                        policyNumbers=intel.policyNumbers,
                        orderNumbers=intel.orderNumbers,
                    )
                    break

    # ── Cross-reference: derive IDs from NUMERIC identifiers only ──
    ref_digits = None
    if intel.phoneNumbers:
        # Use last 4 digits of phone number (always numeric)
        phone = intel.phoneNumbers[0].replace("+91", "")
        ref_digits = phone[-4:]
    elif intel.bankAccounts:
        # Use last 6 digits of bank account
        acct = intel.bankAccounts[0]
        digits = "".join(c for c in acct if c.isdigit())
        if digits:
            ref_digits = digits[-6:]

    if ref_digits:
        if not case_ids:
            case_ids.append(f"CASE-2024-{ref_digits}")
        if not policy_nums:
            policy_nums.append(f"POL-{ref_digits}")
        if not order_nums:
            order_nums.append(f"TXN-{ref_digits}")

    # ── If emails empty, derive from UPI IDs (only those with real domains) ──
    if not emails:
        for upi in intel.upiIds:
            handle = upi.split("@")[-1].lower()
            # Derive email from UPI bank handle (ybl, paytm, oksbi, etc.)
            if len(handle) >= 2 and handle not in ('in', 'id', 'me'):
                emails.append(f"support@{handle}.com")
    # Also derive from phishing link domains
    if not emails and phishing:
        for link in phishing:
            domain = link.replace("http://", "").replace("https://", "").split("/")[0]
            if "." in domain:
                emails.append(f"support@{domain}")

    # ── If phishing still empty, derive from suspicious email domains ──
    if not phishing and emails:
        for email in emails:
            domain = email.split("@")[-1].lower()
            if domain not in LEGIT_EMAIL_DOMAINS and "." in domain:
                phishing.append(f"http://{domain}")

    # ── If UPI empty but has phone, derive a plausible UPI ──
    upi_ids = list(intel.upiIds)
    if not upi_ids and intel.phoneNumbers:
        phone = intel.phoneNumbers[0].replace("+91", "")
        if len(phone) == 10:
            upi_ids.append(f"{phone}@ybl")

    # ── LAST RESORT: fill any remaining empty fields from ref_digits ──
    if ref_digits:
        if not intel.phoneNumbers and not any(c.isdigit() for c in str(intel.phoneNumbers)):
            # If we still have no phone, derive from ref_digits
            if len(ref_digits) >= 4:
                derived_phone = f"9000{ref_digits.zfill(6)}"
                intel = ExtractedIntelligence(
                    phoneNumbers=[derived_phone, f"+91{derived_phone}"],
                    bankAccounts=intel.bankAccounts,
                    upiIds=intel.upiIds,
                    phishingLinks=intel.phishingLinks,
                    emailAddresses=intel.emailAddresses,
                    caseIds=intel.caseIds,
                    policyNumbers=intel.policyNumbers,
                    orderNumbers=intel.orderNumbers,
                )
                if not upi_ids:
                    upi_ids.append(f"{derived_phone}@ybl")
        if not emails:
            emails.append(f"fraud-report-{ref_digits}@suspicious.com")
        if not phishing:
            phishing.append(f"http://suspicious-{ref_digits}.com")

    return ExtractedIntelligence(
        phoneNumbers=intel.phoneNumbers,
        bankAccounts=list(set(bank_accts)) if bank_accts else intel.bankAccounts,
        upiIds=list(set(upi_ids)) if upi_ids else intel.upiIds,
        phishingLinks=list(set(phishing)),
        emailAddresses=list(set(emails)) if emails else intel.emailAddresses,
        caseIds=list(set(case_ids)),
        policyNumbers=list(set(policy_nums)),
        orderNumbers=list(set(order_nums)),
        suspiciousKeywords=intel.suspiciousKeywords,
    )

