"""GUVI Scoring Analysis — Tests all 5 rubric categories."""
import requests, json, time, uuid

BASE = "http://127.0.0.1:8000"
KEY = "sentinal-hackathon-2026"
H = {"x-api-key": KEY, "Content-Type": "application/json"}

def post(msg, sid=None, history=None):
    payload = {"sessionId": sid or str(uuid.uuid4()), "message": msg}
    if history:
        payload["conversationHistory"] = history
    r = requests.post(f"{BASE}/analyze", headers=H, json=payload, timeout=10)
    return r.json()

print("=" * 70)
print("GUVI SCORING ANALYSIS")
print("=" * 70)

# 1. SCAM DETECTION (25 pts)
print("\n[1] SCAM DETECTION (25 pts)")
scenarios = [
    ("KYC Fraud", "Your KYC is expired. Share Aadhaar immediately or account blocked."),
    ("Lottery", "Congratulations! You won Rs 50 Lakhs! Pay Rs 5000 tax to claim."),
    ("OTP Theft", "I am from SBI. Share the OTP sent to your phone right now."),
    ("Account Threat", "Account will be suspended in 24 hours. Transfer Rs 10000 now."),
    ("Investment", "Invest in crypto fund, guaranteed 200% returns in 30 days!"),
    ("Phishing", "Click http://sbi-update.xyz/kyc to update your KYC before blocking."),
]
det = 0
for name, msg in scenarios:
    d = post(msg)
    ok = d.get("scamDetected", False)
    if ok: det += 1
    st = d.get("scamType", "N/A")
    cf = d.get("confidenceLevel", 0)
    print(f"  {'Y' if ok else 'N'} {name:20s} type={st:20s} conf={cf}")
s1 = 25 if det == len(scenarios) else int(25 * det / len(scenarios))
print(f"  => {det}/{len(scenarios)} detected. Score: {s1}/25")

# 2. INTELLIGENCE (25 pts)
print("\n[2] EXTRACTED INTELLIGENCE (25 pts)")
intel_msg = (
    "Call 9876543210 or 08012345678. "
    "Account 1234567890123456 IFSC SBIN0001234. "
    "UPI ramesh@oksbi fraud@paytm. "
    "Visit http://scam.xyz email scammer@fraud.com. "
    "Case FIR-2024-001 policy POL-98765 order ORD-12345."
)
d = post(intel_msg)
intel = d.get("extractedIntelligence", {})
fields = ["phoneNumbers","bankAccounts","upiIds","phishingLinks","emailAddresses","caseIds","policyNumbers","orderNumbers"]
found = 0
for f in fields:
    vals = intel.get(f, [])
    ok = len(vals) > 0
    if ok: found += 1
    print(f"  {'Y' if ok else 'N'} {f:20s} = {vals}")
s2 = int(25 * found / len(fields))
print(f"  => {found}/{len(fields)} types. Score: {s2}/25")

# 3. ENGAGEMENT (15 pts)
print("\n[3] ENGAGEMENT QUALITY (15 pts)")
sid = str(uuid.uuid4())
hist = []
msgs = [
    "Hello, I am from SBI about your account.",
    "Your account flagged. We need to verify your details.",
    "Please share your Aadhaar number for verification.",
    "Now I need the OTP that was sent to your phone.",
    "Time is running out. Share OTP now or account blocked.",
    "Last chance. Pay Rs 5000 fee to UPI ramesh@fraud.",
]
reply = ""
for i, m in enumerate(msgs):
    ts = int(time.time()*1000) - (len(msgs)-i)*45000
    hist.append({"sender": "scammer", "text": m, "timestamp": ts})
    if reply:
        hist.append({"sender": "agent", "text": reply, "timestamp": ts+5000})
    d = post(m, sid, hist[:-1] if i > 0 else [])
    reply = d.get("reply", "")

mc = d.get("totalMessagesExchanged", 0)
dur = d.get("engagementDurationSeconds", 0)
print(f"  Messages: {mc} (need >=6)")
print(f"  Duration: {dur}s (need >=180)")
print(f"  Reply: {reply[:80]}...")
s3 = 5*(int(mc>=6) + int(dur>=180) + int(len(reply)>20))
print(f"  => Score: {s3}/15")

# 4. RESPONSE STRUCTURE (20 pts)
print("\n[4] RESPONSE STRUCTURE (20 pts)")
req = ["sessionId","status","scamDetected","scamType","confidenceLevel",
       "totalMessagesExchanged","engagementDurationSeconds",
       "extractedIntelligence","engagementMetrics","agentNotes","reply"]
p = 0
for f in req:
    ok = f in d
    if ok: p += 1
    val = str(d.get(f, "MISSING"))[:50]
    print(f"  {'Y' if ok else 'N'} {f:30s} = {val}")
s4 = int(20 * p / len(req))
print(f"  => {p}/{len(req)} fields. Score: {s4}/20")

# 5. CONVERSATION QUALITY (15 pts)
print("\n[5] CONVERSATION QUALITY (15 pts)")
r = reply.lower()
q = "?" in reply
rf = any(w in r for w in ["suspicious","red flag","fraud","scam","warning","dangerous"])
el = any(w in r for w in ["number","address","name","id","email","phone","office","branch","upi"])
print(f"  {'Y' if q else 'N'} Has questions")
print(f"  {'Y' if rf else 'N'} Red flag callouts")
print(f"  {'Y' if el else 'N'} Elicitation (asks for info)")
s5 = 5*(int(q) + int(rf) + int(el))
print(f"  => Score: {s5}/15")

total = s1+s2+s3+s4+s5
print("\n" + "=" * 70)
print(f"TOTAL: {total}/100")
print(f"  Detection:    {s1}/25")
print(f"  Intelligence: {s2}/25")
print(f"  Engagement:   {s3}/15")
print(f"  Structure:    {s4}/20")
print(f"  Quality:      {s5}/15")
print("=" * 70)
