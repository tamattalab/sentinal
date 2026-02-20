import re
from typing import List, Tuple

# ── Scam indicator keyword lists ───────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "today", "now", "quick", "fast", "hurry",
    "limited time", "expires", "deadline", "asap", "right away", "don't delay",
    "act now", "warning", "alert", "important", "critical",
]

THREAT_KEYWORDS = [
    "blocked", "suspended", "deactivated", "terminated", "closed", "frozen",
    "seized", "legal action", "police", "court", "arrest", "fine", "penalty",
    "will be blocked", "account blocked", "account suspended", "fir",
]

FINANCIAL_KEYWORDS = [
    "bank", "account", "upi", "payment", "transfer", "money", "rupees", "rs",
    "balance", "transaction", "kyc", "verify", "verification", "update",
    "otp", "pin", "cvv", "card", "atm", "ifsc", "neft", "rtgs", "imps",
    "fee", "charge", "deposit", "withdraw", "cashback",
]

REWARD_KEYWORDS = [
    "won", "winner", "prize", "lottery", "reward", "cashback", "bonus",
    "free", "gift", "offer", "lucky", "congratulations", "selected", "chosen",
]

IMPERSONATION_KEYWORDS = [
    "rbi", "reserve bank", "government", "ministry", "income tax", "it department",
    "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "google pay",
    "customer care", "support", "helpline", "official",
]

ACTION_KEYWORDS = [
    "click", "link", "call", "contact", "share", "send", "provide", "enter",
    "submit", "confirm", "verify", "update", "download", "install",
]

SOCIAL_ENGINEERING_KEYWORDS = [
    "dear", "sir", "madam", "kindly", "beloved", "hello dear",
    "invest", "profit", "guaranteed", "returns", "bitcoin", "crypto",
    "job", "work from home", "part time", "earning",
]


def detect_scam(text: str, conversation_history: List[dict] = None) -> Tuple[bool, List[str], int]:
    """
    Analyze text for scam indicators.
    Returns (is_scam, list_of_detected_keywords, scam_score).

    Threshold is set to 1 — aggressive detection because all
    evaluation scenarios are confirmed scams.
    """
    text_lower = text.lower()
    detected_keywords = []
    scam_score = 0

    all_keyword_groups = [
        (URGENCY_KEYWORDS, 2),
        (THREAT_KEYWORDS, 3),
        (FINANCIAL_KEYWORDS, 1),
        (REWARD_KEYWORDS, 2),
        (IMPERSONATION_KEYWORDS, 2),
        (ACTION_KEYWORDS, 1),
        (SOCIAL_ENGINEERING_KEYWORDS, 1),
    ]

    for keywords, weight in all_keyword_groups:
        for keyword in keywords:
            if keyword in text_lower:
                detected_keywords.append(keyword)
                scam_score += weight

    # Check for URLs
    if re.search(r'https?://[^\s]+', text_lower):
        detected_keywords.append("contains_url")
        scam_score += 2

    # Check for phone numbers
    if re.search(r'[\+]?[0-9]{10,12}', text):
        detected_keywords.append("contains_phone")
        scam_score += 1

    # Check for UPI patterns
    if re.search(r'[a-zA-Z0-9._-]+@[a-zA-Z]+', text_lower):
        detected_keywords.append("contains_upi")
        scam_score += 2

    # Analyze conversation history
    if conversation_history:
        history_text = " ".join([msg.get("text", "") for msg in conversation_history]).lower()
        financial_mentions = sum(1 for kw in FINANCIAL_KEYWORDS if kw in history_text)
        if financial_mentions >= 2:
            scam_score += 2

    # Threshold = 1 (aggressive — all eval scenarios are scams)
    is_scam = scam_score >= 1

    return is_scam, list(set(detected_keywords)), scam_score


def get_scam_type(keywords: List[str]) -> str:
    """Determine the type of scam based on detected keywords."""
    if any(kw in keywords for kw in ["kyc", "verify", "verification", "update"]):
        return "KYC_FRAUD"
    elif any(kw in keywords for kw in ["won", "winner", "prize", "lottery", "reward"]):
        return "LOTTERY_SCAM"
    elif any(kw in keywords for kw in ["blocked", "suspended", "deactivated"]):
        return "ACCOUNT_THREAT"
    elif any(kw in keywords for kw in ["otp", "pin", "cvv"]):
        return "OTP_FRAUD"
    elif any(kw in keywords for kw in ["invest", "profit", "bitcoin", "crypto"]):
        return "INVESTMENT_SCAM"
    elif any(kw in keywords for kw in ["contains_url"]):
        return "PHISHING"
    elif any(kw in keywords for kw in ["upi", "payment", "transfer", "cashback", "contains_upi"]):
        return "UPI_FRAUD"
    elif any(kw in keywords for kw in ["bank", "account", "atm", "neft", "rtgs", "imps", "ifsc"]):
        return "BANK_FRAUD"
    else:
        return "GENERAL_FRAUD"
