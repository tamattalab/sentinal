"""Final verification — checks all rubric dimensions after patches."""
import requests
import time
import json

BASE_URL = "http://localhost:8000"
s = requests.Session()
s.headers.update({"x-api-key": "sentinal-hackathon-2026", "Content-Type": "application/json"})

# warmup
s.get(f"{BASE_URL}/")

sid = f"verify-final-{int(time.time())}"
messages = [
    "Your bank account has been compromised. Call 9876543210 immediately. Account: 123456789012345",
    "Send Rs 1 to verify your UPI scammer@ybl to avoid account freeze",
    "Yes sir please help. My pension is in that account!",
    "You must pay penalty fee of Rs 500",
    "Click http://fake-bank.com/verify to restore access",
    "Your KYC is expired. Update now.",
    "Send OTP to +919876543210",
    "Your account will be blocked in 2 hours",
    "Contact loans@scammail.com for documentation",
    "Final warning. Invest Rs 10000 for guaranteed returns via invest@oksbi",
]

print("=" * 60)
print("  FINAL VERIFICATION - 10 turns, all rubric dimensions")
print("=" * 60)
print(f"Session: {sid}")
print(f"Sending {len(messages)} turns...\n")

for i, msg in enumerate(messages):
    r = s.post(f"{BASE_URL}/analyze", json={
        "sessionId": sid,
        "message": {"sender": "scammer", "text": msg, "timestamp": int(time.time() * 1000)},
    })
    data = r.json()
    server_ms = r.headers.get("X-Process-Time-Ms", "?")
    msgs = data["totalMessagesExchanged"]
    scam = data["scamDetected"]
    print(f"  Turn {i+1:2d}: {server_ms}ms | msgs={msgs} | scam={scam}")

print(f"\n{'=' * 60}")
print("  FINAL RESPONSE (Turn 10)")
print("=" * 60)
for k, v in data.items():
    if k == "reply":
        print(f"  {k}: {v[:80]}...")
    elif isinstance(v, dict):
        print(f"  {k}: {json.dumps(v)}")
    else:
        print(f"  {k}: {v}")

print(f"\n{'=' * 60}")
print("  STRUCTURE CHECK")
print("=" * 60)

required = ["sessionId", "status", "scamDetected", "totalMessagesExchanged",
            "extractedIntelligence", "engagementMetrics", "agentNotes", "reply"]
for field in required:
    present = field in data
    status = "OK" if present else "MISSING!!!"
    print(f"  {field}: {status}")

intel = data["extractedIntelligence"]
for f in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]:
    vals = intel.get(f, [])
    print(f"  intel.{f}: OK = {vals}")

metrics = data["engagementMetrics"]
print(f"  metrics.engagementDurationSeconds: {metrics.get('engagementDurationSeconds', 'MISSING')}")
print(f"  metrics.totalMessagesExchanged: {metrics.get('totalMessagesExchanged', 'MISSING')}")

print(f"\n{'=' * 60}")
print("  SCORING SUMMARY")
print("=" * 60)

checks = 0
total = 0

def check(name, ok, detail=""):
    global checks, total
    total += 1
    if ok:
        checks += 1
    tag = "PASS" if ok else "FAIL"
    extra = f" ({detail})" if detail else ""
    print(f"  [{tag}] {name}{extra}")

check("scamDetected=True", data["scamDetected"])
check("totalMessagesExchanged=20", data["totalMessagesExchanged"] == 20, f"got {data['totalMessagesExchanged']}")
check("phoneNumbers extracted", len(intel["phoneNumbers"]) > 0, f"{intel['phoneNumbers']}")
check("bankAccounts extracted", len(intel["bankAccounts"]) > 0, f"{intel['bankAccounts']}")
check("upiIds extracted", len(intel["upiIds"]) > 0, f"{intel['upiIds']}")
check("phishingLinks extracted", len(intel["phishingLinks"]) > 0, f"{intel['phishingLinks']}")
check("emailAddresses extracted", len(intel["emailAddresses"]) > 0, f"{intel['emailAddresses']}")
check("duration >= 60s", metrics["engagementDurationSeconds"] >= 60, f"{metrics['engagementDurationSeconds']}s")
check("agentNotes present", len(data["agentNotes"]) > 10)
check("reply present", len(data["reply"]) > 10)

print(f"\n  RESULT: {checks}/{total} checks passed")
print("=" * 60)
