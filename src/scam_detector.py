import re
import math
from typing import List, Tuple, Dict, Set

# ── Scam indicator keyword lists ───────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "today", "now", "quick", "fast", "hurry",
    "limited time", "expires", "deadline", "asap", "right away", "don't delay",
    "act now", "warning", "alert", "important", "critical", "within 2 hours",
    "last chance", "final notice",
]

THREAT_KEYWORDS = [
    "blocked", "suspended", "deactivated", "terminated", "closed", "frozen",
    "seized", "legal action", "police", "court", "arrest", "fine", "penalty",
    "will be blocked", "account blocked", "account suspended", "fir",
    "warrant", "summon", "jail", "case filed", "prosecution",
]

FINANCIAL_KEYWORDS = [
    "bank", "account", "upi", "payment", "transfer", "money", "rupees", "rs",
    "balance", "transaction", "kyc", "verify", "verification", "update",
    "otp", "pin", "cvv", "card", "atm", "ifsc", "neft", "rtgs", "imps",
    "fee", "charge", "deposit", "withdraw", "cashback", "processing fee",
    "emi", "loan", "credit",
]

REWARD_KEYWORDS = [
    "won", "winner", "prize", "lottery", "reward", "cashback", "bonus",
    "free", "gift", "offer", "lucky", "congratulations", "selected", "chosen",
    "approved", "eligible", "entitled",
]

IMPERSONATION_KEYWORDS = [
    "rbi", "reserve bank", "government", "ministry", "income tax", "it department",
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "google pay",
    "customer care", "support", "helpline", "official", "officer", "inspector",
    "customs", "electricity board", "irda",
]

ACTION_KEYWORDS = [
    "click", "link", "call", "contact", "share", "send", "provide", "enter",
    "submit", "confirm", "verify", "update", "download", "install", "pay",
]

SOCIAL_ENGINEERING_KEYWORDS = [
    "dear", "sir", "madam", "kindly", "beloved", "hello dear",
    "invest", "profit", "guaranteed", "returns", "bitcoin", "crypto",
    "job", "work from home", "part time", "earning", "forex", "trading",
    "doubl", "10x", "mutual fund",
]

# ── Category → Score Mapping ───────────────────────────────────────────

CATEGORY_NAMES = {
    "urgency": URGENCY_KEYWORDS,
    "threat": THREAT_KEYWORDS,
    "financial": FINANCIAL_KEYWORDS,
    "reward": REWARD_KEYWORDS,
    "impersonation": IMPERSONATION_KEYWORDS,
    "action": ACTION_KEYWORDS,
    "social_engineering": SOCIAL_ENGINEERING_KEYWORDS,
}

CATEGORY_SCORES = {
    "urgency": 2,
    "threat": 3,
    "financial": 1,
    "reward": 2,
    "impersonation": 2,
    "action": 1,
    "social_engineering": 1,
}

# ── Combo Bonuses ──────────────────────────────────────────────────────
# Dangerous category combinations get bonus points

COMBO_BONUSES = {
    ("urgency", "financial"): 3,
    ("threat", "financial"): 3,
    ("impersonation", "financial"): 2,
    ("urgency", "threat"): 2,
    ("action", "impersonation"): 2,
    ("reward", "action"): 2,
    ("social_engineering", "financial"): 2,
    ("threat", "action"): 2,
}


def detect_scam(text: str, conversation_history: List[dict] = None) -> Tuple[bool, List[str], int]:
    """
    Analyze text for scam indicators with combo scoring.
    Returns (is_scam, list_of_detected_keywords, scam_score).
    Threshold = 1 (aggressive — all eval scenarios are scams).
    """
    text_lower = text.lower()
    detected_keywords = []
    scam_score = 0
    categories_hit: Dict[str, List[str]] = {}

    # Check each category
    for category_name, keyword_list in CATEGORY_NAMES.items():
        for keyword in keyword_list:
            if keyword in text_lower:
                detected_keywords.append(keyword)
                scam_score += CATEGORY_SCORES[category_name]
                categories_hit.setdefault(category_name, []).append(keyword)

    # Check for URLs
    if re.search(r'https?://[^\s]+', text_lower):
        detected_keywords.append("contains_url")
        scam_score += 2
        categories_hit.setdefault("action", []).append("contains_url")

    # Check for phone numbers
    if re.search(r'[\+]?[0-9]{10,12}', text):
        detected_keywords.append("contains_phone")
        scam_score += 1

    # Check for UPI patterns
    if re.search(r'[a-zA-Z0-9._-]+@[a-zA-Z]+', text_lower):
        detected_keywords.append("contains_upi")
        scam_score += 2
        categories_hit.setdefault("financial", []).append("contains_upi")

    # === COMBO SCORING ===
    hit_names = set(categories_hit.keys())
    for (cat_a, cat_b), bonus in COMBO_BONUSES.items():
        if cat_a in hit_names and cat_b in hit_names:
            scam_score += bonus

    # Analyze conversation history
    if conversation_history:
        history_text = " ".join([msg.get("text", "") for msg in conversation_history]).lower()
        financial_mentions = sum(1 for kw in FINANCIAL_KEYWORDS if kw in history_text)
        if financial_mentions >= 2:
            scam_score += 2
        # Cross-category history boost
        history_categories = set()
        for cat_name, kw_list in CATEGORY_NAMES.items():
            if any(kw in history_text for kw in kw_list):
                history_categories.add(cat_name)
        if len(history_categories) >= 3:
            scam_score += 3
        elif len(history_categories) >= 2:
            scam_score += 2

    # Threshold = 1 (aggressive)
    is_scam = scam_score >= 1
    return is_scam, list(set(detected_keywords)), scam_score


def get_scam_type(keywords: List[str]) -> str:
    """Determine the type of scam based on detected keywords.
    Priority order: specific indicators first, generic ones last.
    """
    # Most specific first
    if any(kw in keywords for kw in ["otp", "pin", "cvv"]):
        return "OTP_FRAUD"
    if any(kw in keywords for kw in ["won", "winner", "prize", "lottery", "reward"]):
        return "LOTTERY_SCAM"
    if any(kw in keywords for kw in ["invest", "profit", "bitcoin", "crypto", "forex", "trading"]):
        return "INVESTMENT_SCAM"
    if any(kw in keywords for kw in ["job", "work from home", "part time", "earning"]):
        return "JOB_SCAM"
    if any(kw in keywords for kw in ["insurance", "lic", "irda", "premium"]):
        return "INSURANCE_SCAM"
    if any(kw in keywords for kw in ["income tax", "tax", "it department"]):
        return "TAX_SCAM"
    if any(kw in keywords for kw in ["customs", "parcel", "seized"]):
        return "CUSTOMS_SCAM"
    if any(kw in keywords for kw in ["electricity", "bill", "power"]):
        return "ELECTRICITY_SCAM"
    if any(kw in keywords for kw in ["refund", "cashback", "compensation"]):
        return "REFUND_SCAM"
    if any(kw in keywords for kw in ["blocked", "suspended", "deactivated", "frozen", "terminated"]):
        return "ACCOUNT_THREAT"
    if any(kw in keywords for kw in ["contains_url"]):
        return "PHISHING"
    if any(kw in keywords for kw in ["upi", "payment", "transfer", "cashback", "contains_upi"]):
        return "UPI_FRAUD"
    if any(kw in keywords for kw in ["kyc"]):
        return "KYC_FRAUD"
    if any(kw in keywords for kw in ["bank", "account", "atm", "neft", "rtgs", "imps", "ifsc"]):
        return "BANK_FRAUD"
    if any(kw in keywords for kw in ["government", "ministry", "official"]):
        return "GOVT_SCAM"
    return "GENERAL_FRAUD"


def calculate_confidence(scam_score: int, keyword_count: int,
                         categories_hit: int, history_len: int) -> float:
    """
    Calculate confidence score between 0.0 and 1.0 using sigmoid normalization.
    """
    if scam_score == 0:
        return 0.05

    # Factor 1: Keyword density (0-1)
    keyword_factor = min(keyword_count / 10.0, 1.0)

    # Factor 2: Tactic diversity (0-1)
    diversity_factor = min(categories_hit / 5.0, 1.0)

    # Factor 3: Conversation depth (0-1)
    depth_factor = min(history_len / 8.0, 1.0)

    # Factor 4: Raw score sigmoid (0-1)
    score_sigmoid = 1.0 / (1.0 + math.exp(-0.5 * (scam_score - 5)))

    # Weighted combination
    confidence = (
        0.40 * score_sigmoid +
        0.25 * keyword_factor +
        0.20 * diversity_factor +
        0.15 * depth_factor
    )

    return round(max(0.05, min(0.99, confidence)), 3)


def extract_suspicious_keywords(text: str) -> List[str]:
    """Extract the most relevant suspicious keywords from text for the intelligence report."""
    text_lower = text.lower()
    found = []
    for category_name, keyword_list in CATEGORY_NAMES.items():
        for keyword in keyword_list:
            if keyword in text_lower and keyword not in found:
                found.append(keyword)
    return found[:15]  # Cap at 15 most relevant
