"""
Honeypot Agent Persona — Smart Response Engine
Uses the comprehensive response dataset with context-aware selection.

Persona: Ramesh Kumar, 52-year-old retired govt employee
Selection: scam_type → category mapping → phase-based → random from pool
"""
import random
import logging
from response_dataset import RESPONSE_DB
from hinglish_dataset import HINGLISH_DB

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────
# Keep English and Hinglish pools SEPARATE for language matching
# ─────────────────────────────────────────────────────────────────────────

# Hindi/Hinglish characters and common words for detection
HINDI_MARKERS = set("अआइईउऊएऐओऔकखगघचछजझटठडढणतथदधनपफबभमयरलवशषसह")
HINGLISH_WORDS = {
    "hai", "hain", "nahi", "kya", "kaise", "kahan", "kaun", "kyun", "bhai",
    "ji", "mera", "meri", "mere", "tera", "teri", "tere", "aapka", "aapki",
    "yeh", "woh", "abhi", "bolo", "batao", "karo", "karna", "hona", "raha",
    "rahi", "rahe", "toh", "bhi", "aur", "par", "lekin", "pehle", "baad",
    "mein", "ko", "ka", "ki", "ke", "se", "pe", "ne", "sir", "madam",
    "arrey", "theek", "accha", "haan", "nahin", "chahiye", "dijiye", "dena",
    "lena", "jaana", "aana", "paisa", "rupee", "lakh", "crore", "sahib",
    "beta", "beti", "bhai", "didi", "uncle", "aunty", "sahab",
}


def _detect_language(text: str) -> str:
    """Detect if message is English or Hinglish based on content."""
    # Check for Devanagari script
    if any(c in HINDI_MARKERS for c in text):
        return "hinglish"

    # Check for common Hinglish words
    words = set(text.lower().split())
    hinglish_count = len(words & HINGLISH_WORDS)
    if hinglish_count >= 2:
        return "hinglish"

    return "english"


def _get_pool(category: str, phase: str, language: str) -> list:
    """Get the response pool matching category, phase, and language."""
    if language == "hinglish":
        pool = HINGLISH_DB.get(category, {}).get(phase, [])
        if pool:
            return pool
        # Fallback to English if Hinglish pool empty for this category
        return RESPONSE_DB.get(category, {}).get(phase, [])
    else:
        pool = RESPONSE_DB.get(category, {}).get(phase, [])
        if pool:
            return pool
        # Fallback to Hinglish if English pool empty
        return HINGLISH_DB.get(category, {}).get(phase, [])

# ─────────────────────────────────────────────────────────────────────────
# Map scam types (from scam_detector.py) → response database categories
# ─────────────────────────────────────────────────────────────────────────

SCAM_TYPE_TO_CATEGORY = {
    "KYC_FRAUD":        "kyc_fraud",
    "ACCOUNT_THREAT":   "account_threat",
    "OTP_FRAUD":        "otp_fraud",
    "LOTTERY_SCAM":     "lottery_scam",
    "INVESTMENT_SCAM":  "investment_scam",
    "PHISHING":         "phishing",
    "UPI_FRAUD":        "payment_request",
    "BANK_FRAUD":       "account_threat",
    "GENERAL_FRAUD":    "general",
}

# ─────────────────────────────────────────────────────────────────────────
# Keyword-based category detection (supplements scam_type for precision)
# ─────────────────────────────────────────────────────────────────────────

def _detect_category(text: str) -> str:
    """Detect the best response category from message content."""
    t = text.lower()

    # OTP/PIN/CVV — highest priority (most dangerous)
    if any(w in t for w in ["otp", "pin", "cvv", "password", "code", "one time", "verification code"]):
        return "otp_fraud"

    # Threats and legal pressure
    if any(w in t for w in ["arrest", "police", "legal", "court", "jail", "fine", "penalty",
                             "case filed", "fir", "warrant", "summon"]):
        return "tax_scam"  # threats usually come from fake govt/police

    # Investment / crypto
    if any(w in t for w in ["invest", "bitcoin", "crypto", "trading", "returns", "profit",
                             "guaranteed", "mutual fund", "stock", "forex", "doubl"]):
        return "investment_scam"

    # Lottery / prize / reward
    if any(w in t for w in ["won", "winner", "prize", "lottery", "reward", "congratulat",
                             "selected", "lucky", "cashback", "gift"]):
        return "lottery_scam"

    # Job / work-from-home
    if any(w in t for w in ["job", "work from home", "part time", "earn", "hiring",
                             "vacancy", "resume", "salary", "registration fee"]):
        return "job_scam"

    # Insurance / policy
    if any(w in t for w in ["insurance", "policy", "lic", "premium", "maturity",
                             "claim", "nominee", "endowment", "irda"]):
        return "insurance_scam"

    # Delivery / courier
    if any(w in t for w in ["deliver", "courier", "package", "parcel", "customs",
                             "shipment", "tracking", "dispatch", "consignment"]):
        return "delivery_scam"

    # Tech support / remote access
    if any(w in t for w in ["virus", "hack", "malware", "computer", "laptop",
                             "microsoft", "remote", "teamviewer", "anydesk"]):
        return "tech_support"

    # Loan / credit
    if any(w in t for w in ["loan", "credit card", "emi", "cibil", "pre-approved",
                             "disburse", "sanction", "processing fee"]):
        return "loan_scam"

    # Romance / relationship
    if any(w in t for w in ["dear", "beloved", "love", "marry", "relationship",
                             "lonely", "heart", "dating", "soul"]):
        return "romance_scam"

    # Payment / money transfer
    if any(w in t for w in ["pay", "send money", "transfer", "amount", "rupee",
                             "rs ", "rs.", "fee", "charge", "upi", "cashback"]):
        return "payment_request"

    # KYC / verification
    if any(w in t for w in ["kyc", "verify", "update", "document", "aadhaar",
                             "pan", "aadhar", "identity"]):
        return "kyc_fraud"

    # Phishing links
    if any(w in t for w in ["click", "link", "url", "website", "download",
                             "http", "www", "log in", "login"]):
        return "phishing"

    # Account block / urgency
    if any(w in t for w in ["block", "suspend", "urgent", "immediately",
                             "deactivat", "frozen", "expire", "terminat"]):
        return "account_threat"

    return "general"


def _get_phase(turn_count: int) -> str:
    """Determine conversation phase from turn count."""
    if turn_count <= 2:
        return "early"     # Turns 1-2: confused, scared
    elif turn_count <= 6:
        return "middle"    # Turns 3-6: cooperative, extracting intel
    else:
        return "late"      # Turns 7+: stalling, squeezing last details


# ─────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────

def generate_honeypot_response(current_message: str, turn_count: int = 1,
                                scam_type: str = None, **kwargs) -> str:
    """
    Generate a context-aware honeypot response.

    Args:
        current_message: The scammer's current message
        turn_count: Which turn we're on (1-based)
        scam_type: Detected scam type from scam_detector (optional)

    Returns:
        A phase-appropriate, category-matched response string
    """
    # 1. Determine category: use scam_type mapping first, fallback to keyword detection
    category = None
    if scam_type and scam_type in SCAM_TYPE_TO_CATEGORY:
        category = SCAM_TYPE_TO_CATEGORY[scam_type]

    # 2. Refine category from message content (might be more specific)
    content_category = _detect_category(current_message)
    if content_category != "general":
        category = content_category  # content-based is more specific
    elif category is None:
        category = "general"

    # 3. Determine conversation phase
    phase = _get_phase(turn_count)

    # 4. Detect scammer's language and get matching pool
    language = _detect_language(current_message)
    pool = _get_pool(category, phase, language)

    if not pool:
        pool = _get_pool("general", "middle", language)

    response = random.choice(pool)

    logger.debug(
        f"Response selection: category={category}, phase={phase}, "
        f"lang={language}, pool_size={len(pool)}, turn={turn_count}"
    )

    return response


def generate_confused_response(message: str) -> str:
    """Generate a confused/clarifying response for non-scam messages."""
    language = _detect_language(message)
    return random.choice(_get_pool("general", "early", language))

