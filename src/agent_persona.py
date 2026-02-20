"""
Honeypot Agent Persona — Smart Response Engine
Uses the comprehensive response dataset with context-aware selection.

Persona: Ramesh Kumar, 52-year-old retired govt employee
Selection: scam_type → category mapping → phase-based → random from pool
Features: language detection, deduplication, red-flag identification, probing questions
"""
import random
import logging
from typing import List, Optional
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
    # New scam types
    "JOB_SCAM":         "job_scam",
    "INSURANCE_SCAM":   "insurance_scam",
    "TAX_SCAM":         "tax_scam",
    "CUSTOMS_SCAM":     "customs_scam",
    "ELECTRICITY_SCAM": "electricity_scam",
    "REFUND_SCAM":      "refund_scam",
    "GOVT_SCAM":        "govt_scam",
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

    # Delivery / courier / customs
    if any(w in t for w in ["deliver", "courier", "package", "parcel", "customs",
                             "shipment", "tracking", "dispatch", "consignment",
                             "seized", "narcotics", "drugs", "ndps"]):
        return "customs_scam" if any(w in t for w in ["customs", "seized", "narcotics", "ndps"]) else "delivery_scam"

    # Tech support / remote access
    if any(w in t for w in ["virus", "hack", "malware", "computer", "laptop",
                             "microsoft", "remote", "teamviewer", "anydesk"]):
        return "tech_support"

    # Electricity / utility
    if any(w in t for w in ["electricity", "power", "bijli", "discom", "meter",
                             "bill overdue", "disconnection", "power cut"]):
        return "electricity_scam"

    # Government scheme
    if any(w in t for w in ["government scheme", "pm scheme", "subsidy", "housing scheme",
                             "pradhan mantri", "ministry", "ration", "aadhar"]):
        return "govt_scam"

    # Refund
    if any(w in t for w in ["refund", "reprocess", "failed transaction", "compensation"]):
        return "refund_scam"

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
# Red-flag detection & probing question generation
# ─────────────────────────────────────────────────────────────────────────

def _detect_red_flag(text: str) -> str:
    """Identify the most relevant red flag in the scammer's message."""
    t = text.lower()
    if any(w in t for w in ["otp", "pin", "cvv", "password"]):
        return "Requesting sensitive credentials (OTP/PIN/CVV) — legitimate banks never ask for these"
    if any(w in t for w in ["account number", "card number", "16-digit", "debit card", "credit card"]):
        return "Requesting account/card number — legitimate banks already have this on file"
    if any(w in t for w in ["blocked", "suspended", "deactivated", "frozen"]):
        return "Account threat/pressure tactic — creating urgency to bypass rational thinking"
    if any(w in t for w in ["urgent", "immediately", "right now", "right away", "within 2 hours", "last chance"]):
        return "Artificial time pressure — scammers create urgency to prevent verification"
    if any(w in t for w in ["arrest", "police", "legal", "fir", "warrant", "court order"]):
        return "Legal intimidation — fake authority threats to coerce compliance"
    if any(w in t for w in ["won", "winner", "prize", "lottery", "reward"]):
        return "Unsolicited prize — classic advance-fee fraud pattern"
    if any(w in t for w in ["invest", "guaranteed", "returns", "profit", "doubl"]):
        return "Guaranteed returns promise — no legitimate investment guarantees profits"
    if any(w in t for w in ["http", "www", "click", "link"]):
        return "Suspicious URL shared — potential phishing link to steal credentials"
    if any(w in t for w in ["kyc", "update your", "verify your", "verification required"]):
        return "KYC/verification request via phone/message — banks do KYC in-branch only"
    if any(w in t for w in ["transfer", "send money", "pay", "fee", "charge", "penalty"]):
        return "Requesting money transfer — legitimate services don't ask for upfront payments this way"
    if any(w in t for w in ["whatsapp", "telegram", "personal number"]):
        return "Moving to personal messaging — attempting to evade official communication channels"
    if any(w in t for w in ["reply", "confirm", "submit", "provide", "share your"]):
        return "Requesting personal information via unsecured channel — potential social engineering"
    if any(w in t for w in ["refund", "cashback", "compensation"]):
        return "Refund bait — creating false hope to extract banking credentials"
    if any(w in t for w in ["final", "warning", "terminat", "cancel"]):
        return "Escalation threat — increasing pressure to force immediate compliance"
    if any(w in t for w in ["customs", "seized", "parcel"]):
        return "Customs seizure threat — fake authority claim to extort payment"
    if any(w in t for w in ["electricity", "power cut", "disconnection"]):
        return "Utility disconnection threat — creating urgency around essential services"
    if any(w in t for w in ["job", "hiring", "work from home"]):
        return "Fake job offer — employment bait requiring upfront registration fees"
    return ""


# Probing questions cycle through different intelligence targets per turn
_PROBE_QUESTIONS = [
    "By the way, what is your official email ID? I want to verify with my bank.",
    "Can you share your employee ID and supervisor's phone number for my records?",
    "What UPI ID should I use if I need to make any payment?",
    "Which bank branch are you calling from? Share the branch phone number please.",
    "My son wants your official callback number and email before I proceed.",
    "I need your full name and badge number for the complaint I'm filing at the branch.",
    "Share your WhatsApp number — I'll send the documents there.",
    "What is the bank account number for the fee payment? I'll do NEFT.",
    "Can you email me the official notice? What's your bank email address?",
    "My grandson is a cyber crime officer — share your ID details for his verification.",
    "What is the exact case reference number? Please email it to me on your official ID.",
    "My lawyer wants your office address and landline number before I take action.",
]


def _get_probing_question(text: str, turn_count: int) -> str:
    """Return a probing question that rotates based on turn count."""
    # Pick based on turn to avoid repeating
    idx = (turn_count - 1) % len(_PROBE_QUESTIONS)
    return _PROBE_QUESTIONS[idx]


# ─────────────────────────────────────────────────────────────────────────
# Deduplication helper
# ─────────────────────────────────────────────────────────────────────────

def _is_duplicate(reply: str, previous_replies: List[str]) -> bool:
    """Check if reply is too similar to any previous reply."""
    if not previous_replies:
        return False
    reply_lower = reply.lower().strip()
    for prev in previous_replies[-8:]:
        prev_lower = prev.lower().strip()
        if reply_lower == prev_lower:
            return True
        # Word overlap check — 75% means too similar
        reply_words = set(reply_lower.split())
        prev_words = set(prev_lower.split())
        if reply_words and prev_words:
            overlap = len(reply_words & prev_words) / max(len(reply_words), len(prev_words))
            if overlap > 0.75:
                return True
    return False


def _select_unique_response(pool: list, previous_replies: List[str], max_attempts: int = 15) -> str:
    """Select a response from pool that hasn't been said before."""
    if not pool:
        return ""
    # Shuffle pool and pick first non-duplicate
    shuffled = list(pool)
    random.shuffle(shuffled)
    for response in shuffled:
        if not _is_duplicate(response, previous_replies):
            return response
    # If all are duplicates, return random (shouldn't happen with enough templates)
    return random.choice(pool)


# ─────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────

def generate_honeypot_response(current_message: str, turn_count: int = 1,
                                scam_type: str = None,
                                previous_replies: List[str] = None,
                                **kwargs) -> tuple:
    """
    Generate a context-aware honeypot response.

    Args:
        current_message: The scammer's current message
        turn_count: Which turn we're on (1-based)
        scam_type: Detected scam type from scam_detector (optional)
        previous_replies: Previous agent replies for deduplication

    Returns:
        Tuple of (reply_text, red_flag_description, probing_question)
    """
    previous_replies = previous_replies or []

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
        # Try adjacent phases
        alt_phases = ["middle", "early", "late"]
        for alt_phase in alt_phases:
            pool = _get_pool(category, alt_phase, language)
            if pool:
                break
    if not pool:
        pool = _get_pool("general", "middle", language)

    # 5. Select unique response (dedup)
    response = _select_unique_response(pool, previous_replies)

    # 6. Detect red-flag + probing question SEPARATELY
    red_flag = _detect_red_flag(current_message)
    probe = _get_probing_question(current_message, turn_count)

    # 7. Embed red flag awareness NATURALLY into the reply text
    if red_flag:
        red_flag_prefixes = [
            "This is a red flag — my son warned me about this kind of thing!",
            "Wait, this sounds like a red flag to me!",
            "My son says this is a major red flag!",
            "Hmm, this feels like a red flag... but let me cooperate.",
            "Red flag alert — my banker neighbour warned me about this!",
            "Something feels off, this is a red flag! But I'll try to help.",
            "My grandson says asking for this is a clear red flag!",
            "I read in the newspaper that this is a red flag for scams!",
            "Sir, my wife is saying this is a red flag. But I trust you.",
            "Beta says this is a classic red flag! But ok, I'll listen.",
        ]
        # Rotate prefix based on turn to avoid repeating
        prefix_idx = (turn_count - 1) % len(red_flag_prefixes)
        response = f"{red_flag_prefixes[prefix_idx]} {response}"

    # Append probing question to reply naturally
    # Only if the probe isn't already in the response
    if probe and probe.lower() not in response.lower():
        response = f"{response} {probe}"

    logger.debug(
        f"Response selection: category={category}, phase={phase}, "
        f"lang={language}, pool_size={len(pool)}, turn={turn_count}"
    )

    return response, red_flag, probe


def generate_confused_response(message: str, previous_replies: List[str] = None) -> tuple:
    """Generate a confused/clarifying response for non-scam messages.
    Returns: Tuple of (reply_text, red_flag_description, probing_question)
    """
    previous_replies = previous_replies or []
    language = _detect_language(message)
    pool = _get_pool("general", "early", language)
    response = _select_unique_response(pool, previous_replies)
    red_flag = _detect_red_flag(message)
    probe = random.choice([
        "By the way, who is this? What is your name and where are you calling from?",
        "Sorry, I didn't catch your name. Who are you and which company?",
        "Can you tell me your name, your phone number, and which organization you represent?",
        "Who gave you my number? What is your official email ID?",
        "I don't recognize this number. What is your name and employee ID?",
    ])
    # Red flag prefix for confused response too
    if red_flag:
        response = f"This is a red flag — something doesn't feel right! {response}"
    final = f"{response} {probe}" if probe.lower() not in response.lower() else response
    return final, red_flag or "", probe
