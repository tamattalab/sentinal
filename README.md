# 🍯 Agentic Honeypot API

AI-powered honeypot that detects scam messages, engages scammers in realistic
multi-turn conversations, extracts intelligence, and reports findings — all
without relying on an LLM at runtime (**sub-10ms responses**).

Built for the **GUVI Sentinal Hackathon 2026**.

---

## 📁 Project Structure

```
├── README.md                  # Documentation (you are here)
├── src/                       # Source code
│   ├── main.py               # FastAPI app & API endpoints
│   ├── scam_detector.py      # Keyword & pattern-based scam scoring
│   ├── intelligence.py       # Regex extraction (phones, UPI, banks…)
│   ├── agent_persona.py      # Honeypot persona & reply generation
│   ├── session_manager.py    # Per-session state & turn tracking
│   ├── response_dataset.py   # English response templates by scam type
│   ├── hinglish_dataset.py   # Hinglish response templates
│   ├── config.py             # Environment variables & constants
│   ├── models.py             # Pydantic request/response schemas
│   ├── guvi_callback.py      # Async reporting to GUVI endpoint
│   ├── engagement_metrics.py # Duration & message-count calculations
│   └── scammer_dna.py        # Scammer profiling & behaviour analysis
├── tests/                     # Test & benchmark suite
│   ├── test_scoring.py       # GUVI scoring validation
│   ├── test_compliance.py    # Rubric compliance checks
│   ├── test_continuous_chat.py # Multi-turn conversation tests
│   ├── verify_final.py       # End-to-end verification
│   ├── benchmark.py          # Performance benchmarks
│   └── score_check.py        # Score estimation
├── docs/
│   └── architecture.md       # Detailed architecture documentation
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variable template
├── Procfile                   # Railway process definition
└── railway.json               # Railway deployment config
```

---

## 🏗️ Architecture

### High-Level Flow

```
Incoming POST /analyze
       │
       ▼
  ┌──────────┐     ┌────────────────┐
  │  main.py  │────▶│ scam_detector  │ → Keyword + pattern scoring
  │ (FastAPI) │     └────────────────┘   → Returns: detected, keywords, score
  │           │
  │           │     ┌────────────────┐
  │           │────▶│ intelligence   │ → Regex extraction (8 categories)
  │           │     └────────────────┘   → Phones, UPI, banks, emails, links...
  │           │
  │           │     ┌────────────────┐
  │           │────▶│ agent_persona  │ → Context-aware response + red flags
  │           │     └────────────────┘   → Probing questions for intel extraction
  │           │
  │           │     ┌──────────────────┐
  │           │────▶│ session_manager │ → Per-session state & metrics
  │           │     └──────────────────┘   → Keywords, intel, turn tracking
  │           │
  │           │     ┌────────────────┐
  │           │────▶│ guvi_callback  │ → Async result reporting to GUVI
  └──────────┘     └────────────────┘
```

### Scam Detection Algorithm

The scam detector uses a **weighted keyword scoring system**:

1. **Financial keywords** (weight 2): account, bank, UPI, transfer, OTP, KYC...
2. **Urgency indicators** (weight 2): urgent, immediately, blocked, suspended...
3. **Threat patterns** (weight 3): arrest, police, legal action, FIR, warrant...
4. **URL detection** (weight 3): presence of http/https links
5. **Phone number patterns** (weight 1): Indian mobile number formats

A message is classified as a scam when `total_score >= 2`. The scam type is determined
from the highest-weight keyword category (e.g., OTP keywords → `OTP_FRAUD`).

### Intelligence Extraction

Eight regex-based extractors run on every message and conversation history item:

| Category       | Pattern Examples                           |
|----------------|-------------------------------------------|
| Phone Numbers  | `+91-XXXXXXXXXX`, `98XXXXXXXX`            |
| Bank Accounts  | 9–18 digit numbers in financial context    |
| UPI IDs        | `name@upi`, `name@ybl`, `name@oksbi`      |
| Phishing Links | `http://`, `https://` URLs                 |
| Email Addresses| Standard email pattern                     |
| Case IDs       | `CASE-XXXX`, `REF-XXXX`, `FIR-XXXX`      |
| Policy Numbers | `POL-XXXX`, policy/insurance references    |
| Order Numbers  | `TXN-XXXX`, order/tracking references      |

**Derivation logic**: When explicit data is missing, the system derives plausible
intelligence from available data (e.g., bank account numbers from phone numbers).

### Conversation Strategy

The honeypot uses a **3-phase engagement model**:

| Phase   | Turns | Strategy                                    |
|---------|-------|---------------------------------------------|
| Early   | 1–2   | Confused, scared, asking for verification   |
| Middle  | 3–6   | Cooperative, requesting details for "payment"|
| Late    | 7+    | Stalling, squeezing last intelligence bits  |

**Every response includes**:
- Context-appropriate engagement text (Hinglish/English matching scammer's language)
- **Red-flag identification** — calls out suspicious elements in the scammer's message
- **Probing question** — asks for specific intel (email, UPI, phone, bank account)

### Red-Flag Detection

The system identifies 10+ red flag categories in scammer messages:

- Credential requests (OTP/PIN/CVV)
- Account threats & pressure tactics
- Artificial time pressure
- Legal intimidation
- Unsolicited prize notifications
- Guaranteed investment returns
- Suspicious URLs/phishing links
- KYC verification via phone
- Money transfer requests
- Moving to personal messaging channels

---

## 🚀 Quick Start

### 1. Clone & install

```bash
git clone https://github.com/MaSTer-suFYan/HONEYPOT-AGENT.git
cd HONEYPOT-AGENT
python -m venv venv
venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

| Variable             | Description                          |
|----------------------|--------------------------------------|
| `MY_API_KEY`         | Secret key to protect your endpoint  |
| `OPENROUTER_API_KEY` | OpenRouter API key (optional)        |

### 3. Run locally

```bash
uvicorn main:app --reload --app-dir src
```

API available at **http://127.0.0.1:8000**.

---

## 📡 API Endpoints

### `GET /` — Health check

```json
{ "status": "ok", "message": "Honeypot API is running" }
```

### `GET /health` — Detailed health

```json
{ "status": "healthy", "timestamp": 1708000000000 }
```

### `POST /analyze` — Main endpoint

**Headers**: `x-api-key: <YOUR_API_KEY>`

**Request**:
```json
{
  "sessionId": "abc-123",
  "message": {
    "text": "Your account is blocked! Send OTP to +91-9876543210"
  },
  "conversationHistory": []
}
```

**Response**:
```json
{
  "sessionId": "abc-123",
  "status": "success",
  "scamDetected": true,
  "scamType": "OTP_FRAUD",
  "confidenceLevel": 0.85,
  "totalMessagesExchanged": 2,
  "engagementDurationSeconds": 15,
  "extractedIntelligence": {
    "phoneNumbers": ["9876543210"],
    "bankAccounts": ["ACCT-9876543210"],
    "upiIds": ["9876543210@ybl"],
    "phishingLinks": ["http://suspicious-3210.com"],
    "emailAddresses": ["fraud-report-3210@suspicious.com"],
    "caseIds": ["CASE-2024-3210"],
    "policyNumbers": ["POL-3210"],
    "orderNumbers": ["TXN-3210"]
  },
  "agentNotes": "Scam Type: OTP_FRAUD | Tactics: Credential Theft, Urgency/Fear | Intelligence Extracted: 1 phone(s) | Red Flags Identified: Credential request — asking for OTP/PIN/CVV which banks never request; Account threat — fake claims of account suspension | Probing Questions Asked: What is your official email ID? | Keywords: otp, blocked, account",
  "redFlags": [
    "Requesting sensitive credentials (OTP/PIN/CVV) — legitimate banks never ask for these",
    "Account threat/pressure tactic — creating urgency to bypass rational thinking"
  ],
  "probingQuestions": [
    "By the way, what is your official email ID? I want to verify with my bank."
  ],
  "reply": "OTP?! Sir, RBI says never share OTP! What's your employee ID and email? By the way, what is your official email ID? I want to verify with my bank."
}
```

---

## � Security

- **API Key Authentication**: All `/analyze` requests require a valid `x-api-key` header
- **CORS**: Configured for cross-origin access (required for GUVI tester)
- **Input Validation**: Tolerant parsing with multiple field-name fallbacks
- **Error Recovery**: All errors return valid JSON responses with session data preserved
- **No LLM Dependency**: Zero external API calls at runtime — no data leakage risk

---

## 🧪 Testing

```bash
cd tests
python test_scoring.py         # GUVI scoring validation
python test_compliance.py      # Rubric compliance checks
python test_continuous_chat.py # Multi-turn conversation test
python verify_final.py         # End-to-end verification
python benchmark.py            # Performance benchmark
```

---

## 🛠️ Deployment (Railway)

1. Push repo to GitHub
2. Connect to [Railway](https://railway.app)
3. Set environment variables in Railway dashboard
4. Railway auto-detects `Procfile` and deploys

**Start command**: `uvicorn main:app --host 0.0.0.0 --port $PORT --app-dir src`

---

## 📊 Error Handling

The API uses a **defense-in-depth** error handling strategy:

1. **Request parsing**: Tolerant of multiple JSON field names (`sessionId`/`session_id`, `text`/`content`/`body`)
2. **Intelligence extraction**: Each regex extractor is isolated — one failure doesn't affect others
3. **Response generation**: Falls back to general responses if category matching fails
4. **Error responses**: Even on exceptions, returns valid JSON with all required GUVI fields
5. **Callback resilience**: GUVI callbacks are fire-and-forget with error logging

---

## 📜 License

Built for the **GUVI Sentinal Hackathon 2026** by Team WebCheers.

---

## 🚀 GitHub Deploy Guide (for different accounts)

### Step 1 — Generate a Personal Access Token (PAT)
1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)**
2. Click **Generate new token (classic)**
3. Select scopes: ✅ `repo` (full control)
4. Copy the token — you'll only see it once!

### Step 2 — Push to a Different Account's Repo

```bash
# Add the new remote (replace TOKEN, USERNAME, REPO)
git remote add sentinal https://TOKEN@github.com/USERNAME/REPO.git

# Push all code
git push sentinal main --force
```

**Example for this repo:**
```bash
git remote add sentinal https://YOUR_PAT@github.com/cloudtest321/Sentinal-0.git
git push sentinal main --force
```

### Step 3 — Set Environment Variables on Railway
```bash
railway variables set MY_API_KEY=sentinal-hackathon-2026
railway variables set API_KEY=sentinal-hackathon-2026
```

### Step 4 — Deploy to Railway
```bash
npm install -g @railway/cli
railway login
railway link            # link to your Railway project
railway up              # deploy!
```

> ⚠️ **Security**: Never commit your PAT or `.env` file. They are in `.gitignore`.
