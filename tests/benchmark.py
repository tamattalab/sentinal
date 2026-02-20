"""
Speed benchmark — simulates GUVI evaluation (15 scenarios x 10 turns = 150 calls).
Uses requests.Session for connection reuse (same as GUVI's evaluation client).
"""
import requests
import time
import sys

BASE_URL = "http://localhost:8000"
API_KEY = "sentinal-hackathon-2026"

SCENARIOS = [
    ("bank_fraud", "Your bank account has been compromised. Call 9876543210 immediately to update KYC."),
    ("upi_fraud", "Send Rs 1 to verify your UPI ID scammer@ybl. This is mandatory for RBI compliance."),
    ("phishing", "Click http://fake-bank.com/verify to restore your account access immediately."),
    ("kyc_fraud", "Your KYC is expired. Update now or account will be frozen. Account: 123456789012345"),
    ("job_scam", "Congratulations! You are selected for data entry job. Pay Rs 500 to 9123456789@paytm"),
    ("lottery", "You won Rs 50 lakhs! Contact officer at +919876543210 to claim your prize."),
    ("electricity", "Your electricity will be cut in 2 hours. Pay bill at http://pay-bill-now.in/urgent"),
    ("govt_scheme", "PM housing scheme approved. Transfer Rs 2000 to account 987654321098765"),
    ("crypto", "Invest Rs 10000 in crypto and get 10x returns. UPI: invest@oksbi"),
    ("customs", "Your parcel seized by customs. Pay fine Rs 5000 to release. Call 8765432109"),
    ("tech_support", "Your computer has virus. Download fix from https://fix-pc-now.com/download"),
    ("loan", "Instant loan approved! Send documents to loans@scammail.com. Processing fee via 7654321098@paytm"),
    ("tax", "Income tax refund of Rs 25000 pending. Verify at http://tax-refund.co.in/claim"),
    ("refund", "Your refund of Rs 1500 failed. Share bank details to reprocess. Call 6543219876"),
    ("insurance", "Your insurance claim approved. Pay Rs 1000 processing fee to 5432109876@ybl"),
]

FOLLOW_UPS = [
    "Yes, I am worried about this. What should I do?",
    "Can you tell me more? I don't understand.",
    "Oh no, that sounds serious. How do I fix this?",
    "I see, let me check. What details do you need?",
    "I'm confused, can you explain again?",
    "Wait, is this really urgent?",
    "I want to resolve this. What's the next step?",
    "Please give me more information about this.",
    "I'm scared. What will happen if I don't act now?",
]


def main():
    print("=" * 60)
    print("  SPEED BENCHMARK - 15 scenarios x 10 turns = 150 calls")
    print("  Code Riders baseline: ~27s/scenario, ~7 min total")
    print("=" * 60)

    session = requests.Session()
    session.headers.update({
        "x-api-key": API_KEY,
        "Content-Type": "application/json",
    })

    # Warm up
    session.get(f"{BASE_URL}/")

    total_start = time.perf_counter()
    scenario_times = []
    turn_times = []
    server_times = []

    for i, (name, first_msg) in enumerate(SCENARIOS):
        session_id = f"bench-{name}-{int(time.time())}"
        scenario_start = time.perf_counter()

        for turn in range(10):
            text = first_msg if turn == 0 else FOLLOW_UPS[turn % len(FOLLOW_UPS)]
            payload = {
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": text,
                    "timestamp": int(time.time() * 1000),
                },
            }

            t0 = time.perf_counter()
            r = session.post(f"{BASE_URL}/analyze", json=payload)
            t1 = time.perf_counter()

            client_ms = (t1 - t0) * 1000
            server_ms = float(r.headers.get("X-Process-Time-Ms", "0"))
            turn_times.append(client_ms)
            server_times.append(server_ms)

            if r.status_code != 200:
                print(f"  [ERROR] Scenario {name} turn {turn}: status {r.status_code}")
                return

        scenario_time = time.perf_counter() - scenario_start
        scenario_times.append(scenario_time)
        print(f"  [{i+1:2d}/15] {name:20s}  {scenario_time:.3f}s  ({scenario_time/10*1000:.0f}ms/turn)")

    total_time = time.perf_counter() - total_start

    print(f"\n{'-' * 60}")
    print(f"  CLIENT-SIDE (including network):")
    print(f"    Total time:       {total_time:.2f}s")
    print(f"    Avg per scenario: {sum(scenario_times)/len(scenario_times)*1000:.0f}ms")
    print(f"    Avg per turn:     {sum(turn_times)/len(turn_times):.1f}ms")
    print(f"    Min turn:         {min(turn_times):.1f}ms")
    print(f"    Max turn:         {max(turn_times):.1f}ms")
    print(f"")
    print(f"  SERVER-SIDE (actual processing):")
    print(f"    Avg per turn:     {sum(server_times)/len(server_times):.1f}ms")
    print(f"    Min turn:         {min(server_times):.1f}ms")
    print(f"    Max turn:         {max(server_times):.1f}ms")
    print(f"")
    print(f"  COMPARISON:")
    print(f"    Code Riders:      ~7 min (420s)")
    print(f"    Us:               {total_time:.1f}s")
    print(f"    Speedup:          {(420)/total_time:.0f}x faster")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
