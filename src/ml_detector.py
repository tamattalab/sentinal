"""
ML-style Scam Detector — lightweight feature-based classifier.
No torch/sklearn dependency — uses hand-crafted feature engineering for speed.
Toggle: set USE_ML=true in environment to enable.

This is a supplementary classifier that runs alongside the rule-based detector.
"""
import os
import math
import re
from typing import Tuple, List

USE_ML = os.getenv("USE_ML", "false").lower() == "true"


def extract_features(text: str) -> dict:
    """Extract numerical features from text for classification."""
    text_lower = text.lower()
    words = text_lower.split()
    word_count = len(words)

    features = {
        "word_count": word_count,
        "char_count": len(text),

        # Urgency indicators
        "urgency_count": sum(1 for w in words if w in {
            "urgent", "immediately", "now", "hurry", "fast", "quick",
            "asap", "warning", "alert", "critical",
        }),

        # Threat indicators
        "threat_count": sum(1 for w in words if w in {
            "blocked", "suspended", "arrested", "police", "court",
            "legal", "penalty", "frozen", "terminated",
        }),

        # Financial keywords
        "financial_count": sum(1 for w in words if w in {
            "bank", "account", "upi", "payment", "transfer", "money",
            "otp", "pin", "cvv", "kyc", "verify", "atm",
        }),

        # Reward/greed bait
        "reward_count": sum(1 for w in words if w in {
            "won", "winner", "prize", "lottery", "reward", "free",
            "cashback", "gift", "bonus", "profit",
        }),

        # URL presence
        "has_url": 1 if re.search(r'https?://[^\s]+', text_lower) else 0,

        # Phone number presence
        "has_phone": 1 if re.search(r'[\+]?[0-9]{10,12}', text) else 0,

        # UPI pattern presence
        "has_upi": 1 if re.search(r'[a-zA-Z0-9._-]+@[a-zA-Z]+', text_lower) else 0,

        # Exclamation marks (urgency signal)
        "exclamation_count": text.count("!"),

        # Caps ratio (shouting = urgency)
        "caps_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),

        # Request action words
        "action_count": sum(1 for w in words if w in {
            "click", "call", "send", "share", "provide", "enter",
            "download", "install", "pay", "submit",
        }),
    }

    return features


def classify_text(text: str) -> Tuple[float, str, dict]:
    """
    Classify text using weighted feature scoring.

    Returns:
        Tuple of (scam_probability: 0.0-1.0, predicted_type: str, features: dict)
    """
    features = extract_features(text)

    # Feature weights (hand-tuned for scam detection)
    weights = {
        "urgency_count": 0.15,
        "threat_count": 0.20,
        "financial_count": 0.10,
        "reward_count": 0.15,
        "has_url": 0.10,
        "has_phone": 0.05,
        "has_upi": 0.08,
        "exclamation_count": 0.03,
        "caps_ratio": 0.04,
        "action_count": 0.10,
    }

    # Weighted score
    raw_score = sum(
        weights.get(feature, 0) * value
        for feature, value in features.items()
        if feature in weights
    )

    # Sigmoid normalization to probability
    probability = 1.0 / (1.0 + math.exp(-2 * (raw_score - 0.5)))
    probability = max(0.01, min(0.99, probability))

    # Determine type from dominant features
    type_scores = {
        "FINANCIAL_SCAM": features["financial_count"] * 2,
        "THREAT_SCAM": features["threat_count"] * 3,
        "REWARD_SCAM": features["reward_count"] * 2,
        "PHISHING": features["has_url"] * 5 + features["action_count"],
        "URGENCY_SCAM": features["urgency_count"] * 2,
    }
    predicted_type = max(type_scores, key=type_scores.get) if max(type_scores.values()) > 0 else "GENERAL_FRAUD"

    return probability, predicted_type, features


def ml_detect(text: str, conversation_history: List[dict] = None) -> Tuple[bool, float, str]:
    """
    Run ML detection on text.
    Returns: (is_scam: bool, confidence: float, predicted_type: str)

    Only runs if USE_ML env var is true. Otherwise returns neutral result.
    """
    if not USE_ML:
        return True, 0.50, "GENERAL_FRAUD"  # Neutral — let rule-based handle it

    probability, predicted_type, features = classify_text(text)

    # Also analyze history if available
    if conversation_history:
        for msg in conversation_history[-5:]:
            msg_text = msg.get("text", "")
            if msg_text:
                hist_prob, _, _ = classify_text(msg_text)
                probability = max(probability, hist_prob * 0.8)

    is_scam = probability >= 0.3  # Low threshold for aggressive detection
    return is_scam, round(probability, 3), predicted_type
