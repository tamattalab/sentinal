#!/bin/bash
# ================================================================
# SLM Comparison Test — 10-turn bank fraud scenario
# Runs with SLM disabled, then summarizes results.
# To test with SLM enabled: set USE_SLM=true and restart server.
# ================================================================

BASE_URL="${1:-http://localhost:8000}"
API_KEY="${2:-sentinal-hackathon-2026}"
SESSION_ID="slm-scenario-$(date +%s)"

echo ""
echo "================================================================"
echo "  SLM SCENARIO TEST — 10-Turn Bank Fraud"
echo "  Server: $BASE_URL"
echo "  Session: $SESSION_ID"
echo "================================================================"

MESSAGES=(
    "URGENT: Your SBI account has been compromised! Send OTP immediately."
    "I am Officer Sharma from RBI Cyber Cell. Your account will be frozen."
    "Share your OTP or your money will be transferred to criminal account."
    "Your OTP: Send to secure@sbi-verify.com or call +919876543210."
    "Transfer Rs 5000 processing fee. UPI: officer.sharma@ybl"
    "This is your LAST WARNING. Account 123456789012345 IFSC SBIN0001234."
    "We have a warrant for your arrest! Pay Rs 10000 penalty NOW!"
    "Your case number is CASE-2026-9876. Share Aadhaar for clearance."
    "Final notice: http://sbi-verify-kyc.com — update or face legal action."
    "DON'T IGNORE! Your account will be PERMANENTLY BLOCKED in 10 minutes!"
)

TOTAL_PASS=0
TOTAL_FAIL=0
START_TIME=$(python3 -c "import time; print(time.time())")

for i in "${!MESSAGES[@]}"; do
    TURN=$((i + 1))
    MSG="${MESSAGES[$i]}"
    TS=$(python3 -c "import time; print(int(time.time() * 1000))")

    RESPONSE=$(curl -s -X POST "$BASE_URL/analyze" \
        -H "x-api-key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"sessionId\": \"$SESSION_ID\",
            \"message\": {\"sender\": \"scammer\", \"text\": \"$MSG\", \"timestamp\": $TS}
        }")

    STATUS=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null)
    SCAM=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('scamDetected',''))" 2>/dev/null)
    REPLY_LEN=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('reply','')))" 2>/dev/null)
    HAS_SLM=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print('SLM' in d.get('agentNotes',''))" 2>/dev/null)

    if [ "$STATUS" == "success" ] && [ "$SCAM" == "True" ]; then
        echo "  [PASS] Turn $TURN: scam=True, reply=${REPLY_LEN}chars, slm=${HAS_SLM}"
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        echo "  [FAIL] Turn $TURN: status=$STATUS, scam=$SCAM"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
done

END_TIME=$(python3 -c "import time; print(time.time())")
ELAPSED=$(python3 -c "print(f'{$END_TIME - $START_TIME:.2f}')")

# Final state check
FINAL=$(curl -s -X POST "$BASE_URL/analyze" \
    -H "x-api-key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
        \"sessionId\": \"$SESSION_ID\",
        \"message\": {\"sender\": \"scammer\", \"text\": \"Hello?\", \"timestamp\": $(python3 -c "import time; print(int(time.time() * 1000))")}
    }")

echo ""
echo "================================================================"
echo "  FINAL STATE"
echo "================================================================"
echo "$FINAL" | python3 -c "
import sys, json
d = json.load(sys.stdin)
intel = d.get('extractedIntelligence', {})
print(f'  Messages:  {d.get(\"totalMessagesExchanged\", 0)}')
print(f'  Duration:  {d.get(\"engagementDurationSeconds\", 0)}s')
print(f'  Phones:    {intel.get(\"phoneNumbers\", [])}')
print(f'  UPIs:      {intel.get(\"upiIds\", [])}')
print(f'  Banks:     {intel.get(\"bankAccounts\", [])}')
print(f'  Emails:    {intel.get(\"emailAddresses\", [])}')
print(f'  Links:     {intel.get(\"phishingLinks\", [])}')
print(f'  Keywords:  {len(intel.get(\"suspiciousKeywords\", []))} keywords')
notes = d.get('agentNotes', '')
print(f'  SLM Used:  {\"SLM Insight\" in notes}')
"

echo ""
echo "================================================================"
echo "  RESULTS: $TOTAL_PASS passed, $TOTAL_FAIL failed out of 10"
echo "  Total time: ${ELAPSED}s"
echo "================================================================"
echo ""
