#!/usr/bin/env python3
"""
SLM Integration Tests — Test SmolLM2-135M-Instruct Layer 4D

Tests both SLM-enabled and SLM-disabled modes.
Requires server running on localhost:8000.
"""
import requests
import time
import sys
import os

BASE_URL = os.getenv("TEST_URL", "http://localhost:8000")
API_KEY = os.getenv("TEST_API_KEY", "sentinal-hackathon-2026")
HEADERS = {"x-api-key": API_KEY, "Content-Type": "application/json"}

passed = 0
failed = 0


def log(msg, ok):
    global passed, failed
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    print(f"  [{status}] {msg}")


def section(title):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def post(payload):
    r = requests.post(f"{BASE_URL}/analyze", headers=HEADERS, json=payload, timeout=30)
    return r.json(), r.status_code


# ── 1. BASIC FUNCTIONALITY (SLM on or off) ──────────────────────────

def test_basic_response():
    section("1. BASIC RESPONSE — SLM toggle-safe")
    ts = int(time.time() * 1000)
    d, code = post({
        "sessionId": f"slm-basic-{ts}",
        "message": {"sender": "scammer", "text": "Your SBI account is blocked! Send OTP immediately to +919876543210", "timestamp": ts},
    })
    log(f"HTTP {code} == 200", code == 200)
    log(f"scamDetected == True", d.get("scamDetected") is True)
    log(f"reply present ({len(d.get('reply', ''))} chars)", len(d.get("reply", "")) > 10)
    log(f"agentNotes present", len(d.get("agentNotes", "")) > 20)
    log(f"phoneNumbers extracted", len(d.get("extractedIntelligence", {}).get("phoneNumbers", [])) > 0)
    log(f"confidenceLevel > 0.5", d.get("confidenceLevel", 0) > 0.5)

    # Check if SLM insight is in notes (only if SLM is enabled)
    notes = d.get("agentNotes", "")
    has_slm_insight = "SLM Insight" in notes
    print(f"  [INFO] SLM active in response: {has_slm_insight}")


# ── 2. MULTI-TURN WITH SLM ──────────────────────────────────────────

def test_multi_turn():
    section("2. MULTI-TURN ENGAGEMENT (5 turns)")
    ts = int(time.time() * 1000)
    session_id = f"slm-multi-{ts}"

    messages = [
        "URGENT: Your bank account is compromised! Call +919876543210 now!",
        "I am Officer Singh from RBI. Send OTP to secure@bank.com immediately.",
        "Your KYC is expiring! Update at http://fake-kyc.com or account will be frozen.",
        "Transfer Rs 5000 processing fee to scammer@ybl to unlock your account.",
        "This is your LAST CHANCE! Pay penalty of Rs 10000 or face arrest!",
    ]

    for i, msg in enumerate(messages):
        d, code = post({
            "sessionId": session_id,
            "message": {"sender": "scammer", "text": msg, "timestamp": ts + i * 1000},
        })
        log(f"Turn {i+1}: HTTP {code}, scam={d.get('scamDetected')}, reply_len={len(d.get('reply', ''))}", code == 200)

    # Final state checks
    log(f"Messages >= 10 (got {d.get('totalMessagesExchanged', 0)})", d.get("totalMessagesExchanged", 0) >= 10)
    log(f"Duration >= 100s (got {d.get('engagementDurationSeconds', 0)})", d.get("engagementDurationSeconds", 0) >= 100)

    intel = d.get("extractedIntelligence", {})
    log(f"Phones extracted ({len(intel.get('phoneNumbers', []))})", len(intel.get("phoneNumbers", [])) > 0)
    log(f"UPIs extracted ({len(intel.get('upiIds', []))})", len(intel.get("upiIds", [])) > 0)
    log(f"Emails extracted ({len(intel.get('emailAddresses', []))})", len(intel.get("emailAddresses", [])) > 0)
    log(f"Links extracted ({len(intel.get('phishingLinks', []))})", len(intel.get("phishingLinks", [])) > 0)


# ── 3. LATENCY CHECK ────────────────────────────────────────────────

def test_latency():
    section("3. LATENCY CHECK")
    ts = int(time.time() * 1000)
    times = []
    for i in range(5):
        start = time.perf_counter()
        d, code = post({
            "sessionId": f"slm-latency-{ts}-{i}",
            "message": {"sender": "scammer", "text": "Send your OTP now!", "timestamp": ts},
        })
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    avg = sum(times) / len(times)
    max_t = max(times)
    log(f"Avg response: {avg*1000:.0f}ms", True)
    log(f"Max response: {max_t*1000:.0f}ms", True)
    log(f"All under 30s timeout", max_t < 30)
    # If SLM is on, each turn may take ~1-8s; if off, <50ms
    print(f"  [INFO] SLM likely {'ON' if avg > 0.5 else 'OFF'} based on latency")


# ── 4. HINGLISH WITH SLM ────────────────────────────────────────────

def test_hinglish():
    section("4. HINGLISH HANDLING")
    ts = int(time.time() * 1000)
    d, code = post({
        "sessionId": f"slm-hinglish-{ts}",
        "message": {"sender": "scammer", "text": "Bhai urgent hai! Aapka account block ho jayega. OTP bhejo 9876543210 pe!", "timestamp": ts},
    })
    log(f"Hinglish detected scam=True", d.get("scamDetected") is True)
    log(f"Reply present ({len(d.get('reply', ''))} chars)", len(d.get("reply", "")) > 10)
    log(f"Phone extracted", len(d.get("extractedIntelligence", {}).get("phoneNumbers", [])) > 0)


# ── 5. RUBRIC COMPLIANCE ────────────────────────────────────────────

def test_rubric_compliance():
    section("5. RUBRIC COMPLIANCE (all required fields)")
    ts = int(time.time() * 1000)
    d, code = post({
        "sessionId": f"slm-rubric-{ts}",
        "message": {"sender": "scammer", "text": "Transfer Rs 50000 to account 123456789012345 IFSC SBIN0001234 or face arrest!", "timestamp": ts},
    })

    required_fields = ["sessionId", "status", "scamDetected", "totalMessagesExchanged",
                       "extractedIntelligence", "engagementMetrics", "agentNotes", "reply"]
    for field in required_fields:
        log(f"Field '{field}' present", field in d)

    intel_fields = ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks",
                    "emailAddresses", "suspiciousKeywords"]
    intel = d.get("extractedIntelligence", {})
    for field in intel_fields:
        log(f"Intel field '{field}' present", field in intel)

    log(f"Bank account extracted", len(intel.get("bankAccounts", [])) > 0)
    log(f"status == 'success'", d.get("status") == "success")
    log(f"scamDetected is bool", isinstance(d.get("scamDetected"), bool))
    log(f"agentNotes is string", isinstance(d.get("agentNotes"), str))


# ── MAIN ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  HONEYPOT API — SLM INTEGRATION TESTS")
    print("=" * 60)

    test_basic_response()
    test_multi_turn()
    test_latency()
    test_hinglish()
    test_rubric_compliance()

    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {passed} passed, {failed} failed out of {passed + failed}")
    print(f"  PASS RATE: {passed * 100 // (passed + failed)}%")
    print(f"{'=' * 60}\n")

    sys.exit(1 if failed > 0 else 0)
