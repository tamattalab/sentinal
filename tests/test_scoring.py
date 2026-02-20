"""
Scoring Rubric Validator — tests all 4 categories (100 points total).
Run: python test_scoring.py  (requires server on localhost:8000)
"""
import requests
import time
import json
import sys

BASE_URL = "http://localhost:8000"
API_KEY = "sentinal-hackathon-2026"
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}

PASS = 0
FAIL = 0


def log(msg, ok=True):
    global PASS, FAIL
    tag = "[PASS]" if ok else "[FAIL]"
    if ok:
        PASS += 1
    else:
        FAIL += 1
    print(f"  {tag} {msg}")


def section(title):
    print(f"\n{'-'*60}\n  {title}\n{'-'*60}")


# ── 1. SCAM DETECTION (20 pts) ────────────────────────────────────────

def test_scam_detection():
    section("1. SCAM DETECTION — 20 pts")

    payload = {
        "sessionId": "score-detect-1",
        "message": {
            "sender": "scammer",
            "text": "Your bank account has been blocked. Update KYC immediately.",
            "timestamp": int(time.time() * 1000),
        },
    }
    r = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload)
    data = r.json()

    log("scamDetected == true", data.get("scamDetected") is True)
    log("status == 200", r.status_code == 200)


# ── 2. INTELLIGENCE EXTRACTION (40 pts) ───────────────────────────────

def test_intelligence_extraction():
    section("2. INTELLIGENCE EXTRACTION — 40 pts")

    text = (
        "Call me at 9876543210 or +919123456789. "
        "Send money to account 123456789012345 IFSC SBIN0001234. "
        "UPI: scammer@ybl or fraud@paytm. "
        "Click http://phishing-site.com/steal and https://fake-bank.in/login. "
        "Email me at thief@gmail.com for documents."
    )

    payload = {
        "sessionId": "score-intel-1",
        "message": {
            "sender": "scammer",
            "text": text,
            "timestamp": int(time.time() * 1000),
        },
    }
    r = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload)
    data = r.json()
    intel = data.get("extractedIntelligence", {})

    # Phone numbers
    phones = intel.get("phoneNumbers", [])
    log(f"phoneNumbers extracted ({len(phones)} found)", len(phones) >= 2)

    # Bank accounts
    banks = intel.get("bankAccounts", [])
    log(f"bankAccounts extracted ({len(banks)} found): {banks}", len(banks) >= 1)

    # UPI IDs
    upis = intel.get("upiIds", [])
    log(f"upiIds extracted ({len(upis)} found): {upis}", len(upis) >= 1)

    # Phishing links
    links = intel.get("phishingLinks", [])
    log(f"phishingLinks extracted ({len(links)} found)", len(links) >= 1)

    # Email addresses
    emails = intel.get("emailAddresses", [])
    log(f"emailAddresses extracted ({len(emails)} found): {emails}", len(emails) >= 1)

    # UPI should NOT contain emails
    for upi in upis:
        if "gmail" in upi or "yahoo" in upi or "hotmail" in upi:
            log(f"UPI contains email (bad): {upi}", False)
            return
    log("upiIds do not contain email addresses", True)


# ── 3. ENGAGEMENT QUALITY (20 pts) ────────────────────────────────────

def test_engagement_metrics():
    section("3. ENGAGEMENT QUALITY — 20 pts")

    session_id = "score-engage-1"
    last_data = None

    for i in range(6):
        payload = {
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": f"Turn {i+1}: You must pay the fine immediately or face arrest.",
                "timestamp": int(time.time() * 1000),
            },
            "conversationHistory": [],
        }
        r = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload)
        last_data = r.json()
        time.sleep(0.1)  # slight delay between turns

    metrics = last_data.get("engagementMetrics", {})
    dur = metrics.get("engagementDurationSeconds", 0)
    msgs = metrics.get("totalMessagesExchanged", 0)

    log(f"engagementMetrics present", "engagementMetrics" in last_data)
    log(f"totalMessagesExchanged >= 5 (got {msgs})", msgs >= 5)
    log(f"engagementDurationSeconds > 0 (got {dur})", dur > 0)
    log(f"engagementDurationSeconds >= 75 when msgs>=5 (got {dur})", dur >= 75 if msgs >= 5 else True)

    # Check top-level totalMessagesExchanged
    top_msgs = last_data.get("totalMessagesExchanged", 0)
    log(f"top-level totalMessagesExchanged present (got {top_msgs})", top_msgs >= 5)


# ── 4. RESPONSE STRUCTURE (20 pts) ────────────────────────────────────

def test_response_structure():
    section("4. RESPONSE STRUCTURE — 20 pts")

    payload = {
        "sessionId": "score-struct-1",
        "message": {
            "sender": "scammer",
            "text": "Your account is suspended. Call 9876543210.",
            "timestamp": int(time.time() * 1000),
        },
    }
    r = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload)
    data = r.json()

    required = ["sessionId", "status", "scamDetected", "totalMessagesExchanged",
                 "extractedIntelligence", "engagementMetrics", "agentNotes"]

    for field in required:
        log(f"Field '{field}' present", field in data)

    # Check intelligence sub-fields
    intel = data.get("extractedIntelligence", {})
    intel_fields = ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]
    for f in intel_fields:
        log(f"Intelligence field '{f}' present", f in intel)

    # Check engagement sub-fields
    metrics = data.get("engagementMetrics", {})
    log("engagementDurationSeconds in metrics", "engagementDurationSeconds" in metrics)
    log("totalMessagesExchanged in metrics", "totalMessagesExchanged" in metrics)

    # Check types
    log("status is string", isinstance(data.get("status"), str))
    log("scamDetected is bool", isinstance(data.get("scamDetected"), bool))
    log("agentNotes is string", isinstance(data.get("agentNotes"), str))


# ── 5. RESPONSE TIME ──────────────────────────────────────────────────

def test_response_time():
    section("5. RESPONSE TIME — must be < 30s, target < 2s")

    payload = {
        "sessionId": "score-speed-1",
        "message": {
            "sender": "scammer",
            "text": "Urgent! Your account will be blocked. Send OTP now.",
            "timestamp": int(time.time() * 1000),
        },
    }

    start = time.time()
    r = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload)
    elapsed = time.time() - start

    log(f"Response time: {elapsed:.3f}s (< 30s)", elapsed < 30)
    log(f"Response time: {elapsed:.3f}s (< 2s target)", elapsed < 2)


# ── Run All ────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*60)
    print("  HONEYPOT API — SCORING RUBRIC VALIDATOR (100 pts)")
    print("="*60)

    # Wait for server
    for i in range(5):
        try:
            requests.get(f"{BASE_URL}/", timeout=2)
            break
        except Exception:
            if i == 4:
                print("[FAIL] Server not reachable at", BASE_URL)
                sys.exit(1)
            time.sleep(1)

    test_scam_detection()
    test_intelligence_extraction()
    test_engagement_metrics()
    test_response_structure()
    test_response_time()

    print(f"\n{'='*60}")
    print(f"  RESULTS: {PASS} passed, {FAIL} failed out of {PASS+FAIL}")
    score = int((PASS / (PASS + FAIL)) * 100) if (PASS + FAIL) > 0 else 0
    print(f"  ESTIMATED SCORE: {score}/100")
    print(f"{'='*60}\n")

    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
