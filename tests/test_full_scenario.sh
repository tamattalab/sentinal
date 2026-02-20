#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
# Full Scenario Test — 10-turn Bank Fraud simulation via curl
# Usage: bash tests/test_full_scenario.sh [base_url] [api_key]
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

BASE_URL="${1:-http://localhost:8000}"
API_KEY="${2:-sentinal-hackathon-2026}"
SESSION_ID="test-bank-fraud-$(date +%s)"

echo "============================================================"
echo "  FULL SCENARIO TEST — Bank Fraud (10 turns)"
echo "  Base URL:   $BASE_URL"
echo "  Session ID: $SESSION_ID"
echo "============================================================"

MESSAGES=(
    "Your bank account has been compromised. Call 9876543210 immediately to update KYC."
    "Sir your account 123456789012345 will be blocked. Send Rs 1 to verify UPI scammer@ybl"
    "This is very urgent! Your account will be frozen within 2 hours if you don't verify!"
    "Send your OTP immediately to avoid account suspension. This is RBI compliance."
    "Click http://fake-bank.com/verify to restore access. Enter your details there."
    "Your KYC is expired. Contact our officer at loans@scammail.com immediately."
    "Final warning! Your pension account will be terminated. Pay penalty of Rs 5000."
    "Transfer Rs 500 to 9876543210@ybl immediately to avoid legal action and arrest."
    "Your case has been filed. Case ID: CRN-2024-5678. Pay fine to avoid court summon."
    "Last chance sir. Send money to account 987654321098765 IFSC SBIN0005678 or face FIR."
)

PASS=0
FAIL=0
LAST_RESPONSE=""

for i in "${!MESSAGES[@]}"; do
    turn=$((i + 1))
    msg="${MESSAGES[$i]}"
    ts=$(date +%s000)

    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/analyze" \
        -H "x-api-key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"sessionId\": \"$SESSION_ID\",
            \"message\": {
                \"sender\": \"scammer\",
                \"text\": \"$msg\",
                \"timestamp\": $ts
            },
            \"conversationHistory\": []
        }")

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    LAST_RESPONSE="$BODY"

    if [ "$HTTP_CODE" = "200" ]; then
        REPLY=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('reply','')[:60])" 2>/dev/null || echo "parse_error")
        SCAM=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('scamDetected','?'))" 2>/dev/null || echo "?")
        MSGS=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('totalMessagesExchanged',0))" 2>/dev/null || echo "0")
        echo "  Turn $turn: HTTP=$HTTP_CODE | scam=$SCAM | msgs=$MSGS | reply=$REPLY..."
        PASS=$((PASS + 1))
    else
        echo "  Turn $turn: HTTP=$HTTP_CODE [FAIL]"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "============================================================"
echo "  FINAL RESPONSE VALIDATION"
echo "============================================================"

# Parse last response
echo "$LAST_RESPONSE" | python3 -c "
import sys, json

try:
    d = json.load(sys.stdin)
except:
    print('  [FAIL] Could not parse response JSON')
    sys.exit(1)

checks = 0
total = 0

def check(name, ok, detail=''):
    global checks, total
    total += 1
    tag = 'PASS' if ok else 'FAIL'
    if ok: checks += 1
    extra = f' ({detail})' if detail else ''
    print(f'  [{tag}] {name}{extra}')

check('sessionId present', 'sessionId' in d)
check('status == success', d.get('status') == 'success')
check('scamDetected == True', d.get('scamDetected') == True)
check('reply present', bool(d.get('reply')))

msgs = d.get('totalMessagesExchanged', 0)
check(f'totalMessagesExchanged >= 5', msgs >= 5, f'got {msgs}')

intel = d.get('extractedIntelligence', {})
check('phoneNumbers extracted', len(intel.get('phoneNumbers', [])) > 0,
      str(intel.get('phoneNumbers', [])))
check('bankAccounts extracted', len(intel.get('bankAccounts', [])) > 0,
      str(intel.get('bankAccounts', [])))
check('upiIds extracted', len(intel.get('upiIds', [])) > 0,
      str(intel.get('upiIds', [])))
check('phishingLinks extracted', len(intel.get('phishingLinks', [])) > 0,
      str(intel.get('phishingLinks', [])))
check('emailAddresses extracted', len(intel.get('emailAddresses', [])) > 0,
      str(intel.get('emailAddresses', [])))

metrics = d.get('engagementMetrics', {})
dur = metrics.get('engagementDurationSeconds', 0)
check(f'engagementDurationSeconds >= 60', dur >= 60, f'{dur}s')

notes = d.get('agentNotes', '')
check('agentNotes present', len(notes) > 20)
check('agentNotes has Red Flags', 'Red Flag' in notes, notes[:80])

print(f'')
print(f'  RESULT: {checks}/{total} checks passed')
print(f'  ESTIMATED SCORE: {int(checks/total*100)}/100')
" || echo "  [FAIL] Validation script failed"

echo "============================================================"
echo "  HTTP RESULTS: $PASS passed, $FAIL failed out of 10 turns"
echo "============================================================"
