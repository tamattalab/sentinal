"""
Comprehensive Edge Case & Adversarial Tests
Tests: malformed input, empty messages, missing fields, Hinglish, 
       concurrency, session isolation, all 15 scenarios, response dedup.
"""
import requests
import time
import json
import sys
import threading

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


def post(payload, expect_200=True):
    r = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload)
    if expect_200:
        return r.json(), r.status_code
    return None, r.status_code


# ── 1. MALFORMED INPUT ─────────────────────────────────────────────────

def test_malformed_input():
    section("1. MALFORMED INPUT HANDLING")

    # Missing message field entirely
    d, code = post({"sessionId": "edge-1"})
    log(f"Missing message field → status {code}", code == 200)
    log(f"Missing message → has reply", bool(d.get("reply")))

    # Empty message text
    d, code = post({"sessionId": "edge-2", "message": {"sender": "x", "text": "", "timestamp": 0}})
    log(f"Empty text → status {code}", code == 200)

    # Message as string instead of dict
    d, code = post({"sessionId": "edge-3", "message": "Hello, your account is blocked"})
    log(f"Message as string → status {code}", code == 200)
    log(f"Message as string → has reply", bool(d.get("reply")))

    # No sessionId
    d, code = post({"message": {"sender": "scammer", "text": "Pay me", "timestamp": 0}})
    log(f"No sessionId → status {code}", code == 200)

    # Extra unknown fields (should be ignored)
    d, code = post({
        "sessionId": "edge-5",
        "message": {"sender": "scammer", "text": "Your UPI scammer@ybl", "timestamp": 0},
        "unknownField": "test",
        "anotherField": 123,
    })
    log(f"Extra fields → status {code}", code == 200)
    log(f"Extra fields → UPI extracted", len(d.get("extractedIntelligence", {}).get("upiIds", [])) > 0)

    # Alternative field names
    d, code = post({
        "session_id": "edge-6",
        "message": {"sender": "scammer", "content": "Call 9876543210", "timestamp": 0},
        "conversation_history": [],
    })
    log(f"Alt field names → status {code}", code == 200)


# ── 2. EMPTY/MINIMAL MESSAGES ─────────────────────────────────────────

def test_empty_minimal():
    section("2. EMPTY & MINIMAL MESSAGE HANDLING")

    # Single word
    d, code = post({"sessionId": "min-1", "message": {"sender": "s", "text": "hello", "timestamp": 0}})
    log(f"Single word → status {code}", code == 200)
    log(f"Single word → has reply", bool(d.get("reply")))

    # Only numbers
    d, code = post({"sessionId": "min-2", "message": {"sender": "s", "text": "9876543210", "timestamp": 0}})
    log(f"Only phone → phone extracted", "9876543210" in str(d.get("extractedIntelligence", {})))

    # Only URL
    d, code = post({"sessionId": "min-3", "message": {"sender": "s", "text": "http://malware.com/steal", "timestamp": 0}})
    log(f"Only URL → link extracted", len(d.get("extractedIntelligence", {}).get("phishingLinks", [])) > 0)

    # Unicode/emoji
    d, code = post({"sessionId": "min-4", "message": {"sender": "s", "text": "🚨 Urgent! 😱", "timestamp": 0}})
    log(f"Unicode/emoji → status {code}", code == 200)


# ── 3. ALL 15 COMPETITION SCENARIOS ───────────────────────────────────

def test_all_15_scenarios():
    section("3. ALL 15 COMPETITION SCENARIOS")

    scenarios = {
        "bank":       "Your bank account 123456789012345 has been compromised. Call 9876543210.",
        "upi":        "Send Rs 1 to verify your UPI scammer@ybl. Mandatory RBI compliance.",
        "phishing":   "Click http://fake-bank.com/verify to restore your account access.",
        "kyc":        "Your KYC is expired. Update now or account frozen. Ref: REF-2024-KYC001",
        "job":        "Congratulations! Selected for data entry. Pay Rs 500 to 9123456789@paytm",
        "lottery":    "You won Rs 50 lakhs! Contact +919876543210 to claim your prize.",
        "electricity":"Electricity disconnection in 2 hours. Pay bill at http://pay-bill.in/urgent",
        "govt":       "PM housing scheme approved. Transfer Rs 2000 to account 987654321098765",
        "crypto":     "Invest Rs 10000 in crypto, get 10x returns. UPI: invest@oksbi",
        "customs":    "Parcel seized by customs. Pay fine Rs 5000 to release. Call 8765432109",
        "tech":       "Computer has virus. Download fix from https://fix-pc.com/download",
        "loan":       "Instant loan approved! Email loans@scam.com. Fee via 7654321098@paytm",
        "tax":        "Income tax refund Rs 25000 pending. Verify at http://tax-refund.co.in",
        "refund":     "Refund of Rs 1500 failed. Share bank details. Call 6543219876",
        "insurance":  "Insurance claim approved. Pay Rs 1000 processing to 5432109876@ybl",
    }

    for name, msg in scenarios.items():
        d, code = post({
            "sessionId": f"scenario-{name}",
            "message": {"sender": "scammer", "text": msg, "timestamp": int(time.time() * 1000)},
        })
        scam = d.get("scamDetected", False)
        has_reply = bool(d.get("reply"))
        log(f"{name:12s} → scam={scam}, reply={has_reply}", scam and has_reply)


# ── 4. HINGLISH / BILINGUAL DETECTION ─────────────────────────────────

def test_hinglish():
    section("4. HINGLISH / BILINGUAL DETECTION")

    hinglish_msgs = [
        "Aapka account block ho jayega. Abhi 9876543210 pe call karo.",
        "Sir aapka KYC update nahi hai. Immediately karna padega.",
        "Paisa bhejo scammer@ybl pe nahin toh account freeze ho jayega.",
        "Arrey bhai, ye OTP bhej do 4521. Nahi toh police aa jayegi.",
    ]

    for i, msg in enumerate(hinglish_msgs):
        d, code = post({
            "sessionId": f"hinglish-{i}",
            "message": {"sender": "scammer", "text": msg, "timestamp": int(time.time() * 1000)},
        })
        scam = d.get("scamDetected", False)
        has_reply = bool(d.get("reply"))
        log(f"Hinglish msg {i+1} → scam={scam}, has_reply={has_reply}", scam and has_reply)


# ── 5. RESPONSE DEDUPLICATION ─────────────────────────────────────────

def test_deduplication():
    section("5. RESPONSE DEDUPLICATION (10 turns)")

    session_id = "dedup-test"
    replies = []

    for i in range(10):
        d, code = post({
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": f"Turn {i+1}: Your account is blocked. Pay now or face arrest.",
                "timestamp": int(time.time() * 1000),
            },
        })
        reply = d.get("reply", "")
        replies.append(reply)

    # Check for duplicates (exact match)
    unique_count = len(set(replies))
    log(f"Unique replies: {unique_count}/{len(replies)}", unique_count >= 8)

    # Check for high word overlap
    overlap_count = 0
    for i in range(len(replies)):
        for j in range(i + 1, len(replies)):
            words_i = set(replies[i].lower().split())
            words_j = set(replies[j].lower().split())
            if words_i and words_j:
                overlap = len(words_i & words_j) / max(len(words_i), len(words_j))
                if overlap > 0.8:
                    overlap_count += 1
    log(f"High-overlap pairs: {overlap_count} (want < 5)", overlap_count < 5)


# ── 6. SESSION ISOLATION ──────────────────────────────────────────────

def test_session_isolation():
    section("6. SESSION ISOLATION")

    # Session A — has phone
    post({
        "sessionId": "iso-A",
        "message": {"sender": "s", "text": "Call 9876543210 now", "timestamp": 0},
    })

    # Session B — has UPI
    post({
        "sessionId": "iso-B",
        "message": {"sender": "s", "text": "Pay scammer@ybl now", "timestamp": 0},
    })

    # Check A doesn't have B's UPI
    d_a, _ = post({
        "sessionId": "iso-A",
        "message": {"sender": "s", "text": "Please help me", "timestamp": 0},
    })
    intel_a = d_a.get("extractedIntelligence", {})

    d_b, _ = post({
        "sessionId": "iso-B",
        "message": {"sender": "s", "text": "Please help me", "timestamp": 0},
    })
    intel_b = d_b.get("extractedIntelligence", {})

    # Neither should have the other's specific intel
    a_has_upi = "scammer@ybl" in str(intel_a.get("upiIds", []))
    b_has_phone = "9876543210" in str(intel_b.get("phoneNumbers", []))
    log(f"Session A has no UPI from B", not a_has_upi)
    log(f"Session B has no phone from A", not b_has_phone)


# ── 7. RED FLAGS IN REPLIES ───────────────────────────────────────────

def test_red_flags_in_replies():
    section("7. RED FLAGS EMBEDDED IN REPLY TEXT")

    test_messages = [
        "Send your OTP immediately",
        "Your account is blocked, call now",
        "Click http://phishing-site.com to verify",
        "Pay Rs 5000 or face arrest",
    ]

    red_flag_count = 0
    for i, msg in enumerate(test_messages):
        d, code = post({
            "sessionId": f"redflag-{i}",
            "message": {"sender": "scammer", "text": msg, "timestamp": int(time.time() * 1000)},
        })
        reply = d.get("reply", "").lower()
        has_rf = "red flag" in reply
        if has_rf:
            red_flag_count += 1
        log(f"'{msg[:40]}...' → red flag in reply: {has_rf}", has_rf)

    log(f"Total replies with red flag: {red_flag_count}/4", red_flag_count >= 3)


# ── 8. AUTH SECURITY ──────────────────────────────────────────────────

def test_auth():
    section("8. AUTHENTICATION / SECURITY")

    # No API key
    r = requests.post(f"{BASE_URL}/analyze", json={"sessionId": "x", "message": {"text": "test"}})
    log(f"No API key → {r.status_code}", r.status_code == 401)

    # Wrong API key
    r = requests.post(
        f"{BASE_URL}/analyze",
        headers={"x-api-key": "wrong-key", "Content-Type": "application/json"},
        json={"sessionId": "x", "message": {"text": "test"}},
    )
    log(f"Wrong API key → {r.status_code}", r.status_code == 401)


# ── 9. ENGAGEMENT METRICS ACCURACY ───────────────────────────────────

def test_engagement_metrics():
    section("9. ENGAGEMENT METRICS ACCURACY")

    session_id = "metrics-test"
    for i in range(5):
        d, code = post({
            "sessionId": session_id,
            "message": {
                "sender": "scammer",
                "text": f"Turn {i+1}: Pay now or face arrest!",
                "timestamp": int(time.time() * 1000),
            },
        })

    metrics = d.get("engagementMetrics", {})
    msgs = metrics.get("totalMessagesExchanged", 0)
    dur = metrics.get("engagementDurationSeconds", 0)

    log(f"5 turns → msgs={msgs} (expect 10)", msgs == 10)
    log(f"5 turns → duration={dur}s (expect >= 100)", dur >= 100)

    # Top-level should match
    top_msgs = d.get("totalMessagesExchanged", 0)
    log(f"Top-level msgs matches metrics", top_msgs == msgs)


# ── 10. RESPONSE TIME CONSISTENCY ────────────────────────────────────

def test_response_time():
    section("10. RESPONSE TIME CONSISTENCY (20 requests)")

    times = []
    for i in range(20):
        start = time.perf_counter()
        post({
            "sessionId": f"speed-{i}",
            "message": {"sender": "s", "text": "Urgent! Account blocked!", "timestamp": 0},
        })
        elapsed = (time.perf_counter() - start) * 1000
        times.append(elapsed)

    avg = sum(times) / len(times)
    max_t = max(times)
    log(f"Avg response time: {avg:.1f}ms (target < 50ms)", avg < 50)
    log(f"Max response time: {max_t:.1f}ms (target < 500ms)", max_t < 500)
    log(f"All under 30s timeout", all(t < 30000 for t in times))


# ── 11. AGENT NOTES QUALITY ──────────────────────────────────────────

def test_agent_notes_quality():
    section("11. AGENT NOTES QUALITY")

    d, code = post({
        "sessionId": "notes-test",
        "message": {
            "sender": "scammer",
            "text": "Your KYC is expired. Call +919876543210 immediately. Pay Rs 500 to scammer@ybl or account frozen.",
            "timestamp": int(time.time() * 1000),
        },
    })

    notes = d.get("agentNotes", "")
    log(f"Notes length > 50 chars", len(notes) > 50)
    log(f"Notes has 'Scam Type'", "Scam Type:" in notes)
    log(f"Notes has 'Confidence'", "Confidence" in notes)
    log(f"Notes has 'Tactics'", "Tactics:" in notes)
    log(f"Notes has 'Red Flags'", "Red Flag" in notes)
    log(f"Notes has 'Intelligence'", "Intelligence" in notes)


# ── Run All ────────────────────────────────────────────────────────────

def main():
    print("\n" + "=" * 60)
    print("  COMPREHENSIVE EDGE CASE & ADVERSARIAL TESTS")
    print("=" * 60)

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

    test_malformed_input()
    test_empty_minimal()
    test_all_15_scenarios()
    test_hinglish()
    test_deduplication()
    test_session_isolation()
    test_red_flags_in_replies()
    test_auth()
    test_engagement_metrics()
    test_response_time()
    test_agent_notes_quality()

    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {PASS} passed, {FAIL} failed out of {PASS + FAIL}")
    pct = int(PASS / (PASS + FAIL) * 100) if (PASS + FAIL) > 0 else 0
    print(f"  PASS RATE: {pct}%")
    print(f"{'=' * 60}\n")

    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
