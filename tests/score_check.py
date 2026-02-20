"""Simple scoring analysis — writes results to results.txt"""
import requests, json, time, uuid

BASE = "http://127.0.0.1:8000"
KEY = "sentinal-hackathon-2026"
H = {"x-api-key": KEY, "Content-Type": "application/json"}

def post(msg, sid=None, history=None):
    payload = {"sessionId": sid or str(uuid.uuid4()), "message": msg}
    if history:
        payload["conversationHistory"] = history
    return requests.post(f"{BASE}/analyze", headers=H, json=payload, timeout=10).json()

lines = []
lines.append("=== [1] SCAM DETECTION (25 pts) ===")
det = 0
for name, msg in [
    ("KYC", "Your KYC expired share Aadhaar and PAN immediately or account blocked"),
    ("Lottery", "Congratulations you won 50 Lakhs pay 5000 tax to claim prize"),
    ("OTP", "I am from SBI share the OTP sent to your phone right now"),
    ("Threat", "Account suspended in 24 hours transfer Rs 10000 to avoid legal action"),
    ("Invest", "Invest in crypto guaranteed 200 percent returns in 30 days"),
    ("Phish", "Click http://sbi-update.xyz/kyc to update KYC before blocking"),
]:
    d = post(msg)
    ok = d.get("scamDetected", False)
    if ok:
        det += 1
    lines.append(f"  {'Y' if ok else 'N'} {name:10s} type={d.get('scamType','N/A'):20s} conf={d.get('confidenceLevel',0)}")
s1 = 25 if det == 6 else int(25 * det / 6)
lines.append(f"  Score: {s1}/25 ({det}/6 detected)")

lines.append("")
lines.append("=== [2] INTELLIGENCE (25 pts) ===")
d = post("Call 9876543210 or 08012345678. Acct 1234567890123456 IFSC SBIN0001234. UPI ram@oksbi fraud@paytm. Visit http://scam.xyz email a@b.com. Case FIR-2024-001 policy POL-98765 order ORD-12345")
intel = d.get("extractedIntelligence", {})
found = 0
for f in ["phoneNumbers","bankAccounts","upiIds","phishingLinks","emailAddresses","caseIds","policyNumbers","orderNumbers"]:
    vals = intel.get(f, [])
    ok = len(vals) > 0
    if ok:
        found += 1
    lines.append(f"  {'Y' if ok else 'N'} {f:20s} = {vals}")
s2 = int(25 * found / 8)
lines.append(f"  Score: {s2}/25 ({found}/8 types)")

lines.append("")
lines.append("=== [3] ENGAGEMENT (15 pts) ===")
sid = str(uuid.uuid4())
hist = []
reply = ""
scam_turns = [
    "Hello I am calling from SBI about your account",
    "Your account has been flagged for suspicious activity",
    "Please share your Aadhaar number for verification",
    "Now I need the OTP sent to your phone",
    "Time running out share OTP now or account blocked",
    "Last chance pay Rs 5000 security fee to UPI ramesh@fraud",
]
for i, m in enumerate(scam_turns):
    ts = int(time.time() * 1000) - (6 - i) * 45000
    hist.append({"sender": "scammer", "text": m, "timestamp": ts})
    if reply:
        hist.append({"sender": "agent", "text": reply, "timestamp": ts + 5000})
    d = post(m, sid, hist[:-1] if i > 0 else [])
    reply = d.get("reply", "")

mc = d.get("totalMessagesExchanged", 0)
dur = d.get("engagementDurationSeconds", 0)
lines.append(f"  Messages: {mc} (need >=6)")
lines.append(f"  Duration: {dur}s (need >=180)")
lines.append(f"  Reply: {reply[:120]}")
m_ok = mc >= 6
d_ok = dur >= 180
r_ok = len(reply) > 20
s3 = 5 * (int(m_ok) + int(d_ok) + int(r_ok))
lines.append(f"  Score: {s3}/15")

lines.append("")
lines.append("=== [4] RESPONSE STRUCTURE (20 pts) ===")
req_fields = ["sessionId","status","scamDetected","scamType","confidenceLevel",
              "totalMessagesExchanged","engagementDurationSeconds",
              "extractedIntelligence","engagementMetrics","agentNotes","reply"]
p = 0
for f in req_fields:
    ok = f in d
    if ok:
        p += 1
    val = str(d.get(f, "MISSING"))[:60]
    lines.append(f"  {'Y' if ok else 'N'} {f:30s} = {val}")
s4 = int(20 * p / len(req_fields))
lines.append(f"  Score: {s4}/20 ({p}/{len(req_fields)} fields)")

lines.append("")
lines.append("=== [5] CONVERSATION QUALITY (15 pts) ===")
rl = reply.lower()
has_q = "?" in reply
has_rf = any(w in rl for w in ["suspicious","red flag","fraud","scam","warning","dangerous"])
has_el = any(w in rl for w in ["number","address","name","id","email","phone","office","branch","upi"])
lines.append(f"  {'Y' if has_q else 'N'} Has questions")
lines.append(f"  {'Y' if has_rf else 'N'} Red flag callouts")
lines.append(f"  {'Y' if has_el else 'N'} Elicitation")
s5 = 5 * (int(has_q) + int(has_rf) + int(has_el))
lines.append(f"  Score: {s5}/15")

total = s1 + s2 + s3 + s4 + s5
lines.append("")
lines.append("=" * 50)
lines.append(f"TOTAL: {total}/100")
lines.append(f"  [1] Detection:    {s1}/25")
lines.append(f"  [2] Intelligence: {s2}/25")
lines.append(f"  [3] Engagement:   {s3}/15")
lines.append(f"  [4] Structure:    {s4}/20")
lines.append(f"  [5] Quality:      {s5}/15")
lines.append("=" * 50)

output = "\n".join(lines)
with open("results.txt", "w", encoding="utf-8") as f:
    f.write(output)
print(output)
