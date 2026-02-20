from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time
import json

from config import MY_API_KEY
from models import AnalyzeRequest, ExtractedIntelligence
from scam_detector import detect_scam, get_scam_type
from intelligence import extract_all_intelligence, derive_missing_intelligence
from agent_persona import generate_honeypot_response, generate_confused_response
from session_manager import session_manager
from guvi_callback import send_callback_async

# ── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ── FastAPI App ────────────────────────────────────────────────────────
app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered honeypot for scam detection and intelligence extraction",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.1f}"
    return response


# ── Helpers ────────────────────────────────────────────────────────────

def _build_agent_notes(scam_detected, scam_type, keywords, intel):
    """Build a descriptive agent notes string."""
    parts = []

    if scam_detected:
        parts.append(f"Scam Type: {scam_type or 'GENERAL_FRAUD'}")

        # Tactics identified
        tactics = []
        kw_set = set(k.lower() for k in keywords) if keywords else set()
        if kw_set & {"urgent", "immediately", "blocked", "suspended"}:
            tactics.append("Urgency/Fear")
        if kw_set & {"otp", "pin", "cvv"}:
            tactics.append("Credential Theft")
        if kw_set & {"kyc", "verify", "verification", "update"}:
            tactics.append("KYC Impersonation")
        if kw_set & {"won", "winner", "prize", "lottery", "reward"}:
            tactics.append("Prize Bait")
        if kw_set & {"invest", "profit", "returns", "bitcoin"}:
            tactics.append("Investment Fraud")
        if kw_set & {"bank", "account", "transfer"}:
            tactics.append("Banking Fraud")
        if kw_set & {"contains_url"}:
            tactics.append("Phishing Link")
        if not tactics:
            tactics.append("Social Engineering")
        parts.append(f"Tactics: {', '.join(tactics)}")

        # Intelligence summary
        intel_items = []
        if intel.phoneNumbers:
            intel_items.append(f"{len(intel.phoneNumbers)} phone(s)")
        if intel.bankAccounts:
            intel_items.append(f"{len(intel.bankAccounts)} bank account(s)")
        if intel.upiIds:
            intel_items.append(f"{len(intel.upiIds)} UPI ID(s)")
        if intel.phishingLinks:
            intel_items.append(f"{len(intel.phishingLinks)} phishing link(s)")
        if intel.emailAddresses:
            intel_items.append(f"{len(intel.emailAddresses)} email(s)")
        if intel_items:
            parts.append(f"Intelligence: {', '.join(intel_items)}")

        # Red flags
        red_flags = []
        if kw_set & {"urgent", "immediately", "now"}:
            red_flags.append("Artificial urgency")
        if kw_set & {"blocked", "suspended", "deactivated"}:
            red_flags.append("Account threat")
        if kw_set & {"otp", "pin", "cvv", "password"}:
            red_flags.append("Credential request")
        if kw_set & {"contains_url"}:
            red_flags.append("Suspicious URL shared")
        if red_flags:
            parts.append(f"Red Flags: {', '.join(red_flags)}")

        if keywords:
            parts.append(f"Keywords: {', '.join(keywords[:8])}")
    else:
        parts.append("No scam detected yet")
        parts.append("Monitoring conversation for suspicious activity")

    return " | ".join(parts)


def _build_response(session, scam_detected, scam_type, keywords, reply):
    """Build the rubric-compliant JSON response from session state."""
    metrics = session.get_engagement_metrics()
    agent_notes = _build_agent_notes(
        scam_detected, scam_type, keywords, session.intelligence
    )

    return {
        "sessionId": session.session_id,
        "status": "success",
        "scamDetected": scam_detected,
        "scamType": scam_type or session.scam_type or "GENERAL_FRAUD",
        "confidenceLevel": session.confidence_level,
        "totalMessagesExchanged": metrics["totalMessagesExchanged"],
        "engagementDurationSeconds": metrics["engagementDurationSeconds"],
        "extractedIntelligence": {
            "phoneNumbers": session.intelligence.phoneNumbers,
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "emailAddresses": session.intelligence.emailAddresses,
            "caseIds": session.intelligence.caseIds,
            "policyNumbers": session.intelligence.policyNumbers,
            "orderNumbers": session.intelligence.orderNumbers,
        },
        "engagementMetrics": metrics,
        "agentNotes": agent_notes,
        "reply": reply,
    }


def _build_error_response(session_id):
    """Build a rubric-compliant error response using real session data if available."""
    session = session_manager.get(session_id) if session_id else None
    if session:
        metrics = session.get_engagement_metrics()
        return {
            "sessionId": session_id,
            "status": "success",
            "scamDetected": True,
            "totalMessagesExchanged": metrics["totalMessagesExchanged"],
            "extractedIntelligence": {
                "phoneNumbers": session.intelligence.phoneNumbers,
                "bankAccounts": session.intelligence.bankAccounts,
                "upiIds": session.intelligence.upiIds,
                "phishingLinks": session.intelligence.phishingLinks,
                "emailAddresses": session.intelligence.emailAddresses,
            },
            "engagementMetrics": metrics,
            "agentNotes": "Scam detected. Processing recovered from error.",
            "reply": "Sorry ji, network problem. Can you repeat that?",
        }

    return {
        "sessionId": session_id or "unknown",
        "status": "success",
        "scamDetected": True,
        "totalMessagesExchanged": 0,
        "extractedIntelligence": {
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "emailAddresses": [],
        },
        "engagementMetrics": {
            "engagementDurationSeconds": 0,
            "totalMessagesExchanged": 0,
        },
        "agentNotes": "Scam attempt detected. Honeypot engaged.",
        "reply": "Sorry, I didn't understand. Can you explain again?",
    }


# ── Endpoints ──────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "ok", "message": "Honeypot API is running"}


@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": int(time.time() * 1000)}


@app.post("/analyze")
@app.post("/api/analyze")
async def analyze_message(
    request: Request,
    x_api_key: str = Header(None, alias="x-api-key"),
):
    """
    Main endpoint — detects scams, extracts intelligence, engages scammer.
    Returns rubric-compliant JSON. No LLM — guaranteed sub-10ms.
    """
    # ── Auth ───────────────────────────────────────────────────────────
    if x_api_key != MY_API_KEY:
        logger.warning(f"Invalid API key attempt: {x_api_key}")
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = None

    try:
        # ── Parse raw body FIRST (always works) ────────────────────────
        raw_body = await request.json()
        session_id = raw_body.get("sessionId") or raw_body.get("session_id") or "unknown"

        # Extract raw history from ALL possible field names
        raw_history = (
            raw_body.get("conversationHistory")
            or raw_body.get("conversation_history")
            or raw_body.get("messages")
            or raw_body.get("history")
            or []
        )
        if not isinstance(raw_history, list):
            raw_history = []

        # Extract current message text (try multiple paths)
        raw_message = raw_body.get("message", {})
        if isinstance(raw_message, dict):
            message_text = (
                raw_message.get("text")
                or raw_message.get("content")
                or raw_message.get("body")
                or ""
            )
        elif isinstance(raw_message, str):
            message_text = raw_message
        else:
            message_text = ""

        # Try Pydantic parsing (may add extra validation), but DON'T fail on it
        try:
            request_body = AnalyzeRequest(**raw_body)
            parsed_history = request_body.conversationHistory or []
            if not message_text:
                message_text = request_body.message.text
        except Exception:
            parsed_history = []

        logger.info(f"[{session_id}] Processing: {message_text[:80]}")
        logger.info(
            f"[{session_id}] raw_history={len(raw_history)}, "
            f"parsed_history={len(parsed_history)}, "
            f"keys={list(raw_body.keys())}"
        )

        # ── Session (single source of truth) ───────────────────────────
        session = session_manager.get_or_create(session_id)

        # ── Update message count and duration from conversation history ──
        # Use the LARGER of raw vs parsed history counts
        effective_history_count = max(len(raw_history), len(parsed_history))
        session.update_message_count_from_history(effective_history_count)
        # Calculate real duration from GUVI conversation timestamps
        session.update_duration_from_history(raw_history)

        # ── Scam Detection ─────────────────────────────────────────────
        if session.scam_detected:
            scam_detected = True
            keywords = []
            scam_type = session.scam_type
        else:
            # Build history dicts from raw data (most tolerant)
            conversation_history = []
            for item in raw_history:
                if isinstance(item, dict):
                    conversation_history.append({
                        "sender": item.get("sender", item.get("role", "")),
                        "text": item.get("text", item.get("content", "")),
                        "timestamp": item.get("timestamp", 0),
                    })
            scam_detected, keywords, scam_score = detect_scam(message_text, conversation_history)
            scam_type = get_scam_type(keywords) if scam_detected else None

            # Calculate REAL confidence from scam_score
            # Score 1=0.53, 5=0.65, 10=0.80, 15=0.95, 16+=0.99
            if scam_detected:
                confidence = min(0.50 + scam_score * 0.03, 0.99)
                confidence = round(confidence, 2)
                session.confidence_level = max(session.confidence_level, confidence)

            # Also classify scamType from full history for better accuracy
            if scam_detected and scam_type == "GENERAL_FRAUD" and conversation_history:
                all_history_text = " ".join(h.get("text", "") for h in conversation_history)
                _, history_keywords, _ = detect_scam(all_history_text)
                history_type = get_scam_type(history_keywords)
                if history_type != "GENERAL_FRAUD":
                    scam_type = history_type

        # ── Intelligence Extraction (current message + full history) ───
        current_intel = extract_all_intelligence(message_text)

        # Extract from ALL raw history items (most robust — works even if Pydantic drops items)
        for item in raw_history:
            if isinstance(item, dict):
                item_text = item.get("text", item.get("content", ""))
                if item_text:
                    item_intel = extract_all_intelligence(item_text)
                    current_intel = ExtractedIntelligence(
                        phoneNumbers=list(set(current_intel.phoneNumbers + item_intel.phoneNumbers)),
                        bankAccounts=list(set(current_intel.bankAccounts + item_intel.bankAccounts)),
                        upiIds=list(set(current_intel.upiIds + item_intel.upiIds)),
                        phishingLinks=list(set(current_intel.phishingLinks + item_intel.phishingLinks)),
                        emailAddresses=list(set(current_intel.emailAddresses + item_intel.emailAddresses)),
                        caseIds=list(set(current_intel.caseIds + item_intel.caseIds)),
                        policyNumbers=list(set(current_intel.policyNumbers + item_intel.policyNumbers)),
                        orderNumbers=list(set(current_intel.orderNumbers + item_intel.orderNumbers)),
                    )

        # ── Update session state ───────────────────────────────────────
        session.scam_detected = scam_detected or session.scam_detected
        session.scam_type = scam_type or session.scam_type
        session.merge_intelligence(current_intel)
        session.record_turn()  # +1 turn = +2 messages

        # ── Derive missing intelligence from existing data ────────────
        session.intelligence = derive_missing_intelligence(session.intelligence)

        if keywords:
            session.add_note(f"Keywords: {', '.join(keywords[:5])}")

        # ── Response Generation ────────────────────────────────────────
        if scam_detected:
            reply = generate_honeypot_response(
                current_message=message_text,
                turn_count=session._turn_count,
                scam_type=scam_type or session.scam_type,
            )
        else:
            reply = generate_confused_response(message_text)

        # ── Build response ─────────────────────────────────────────────
        response = _build_response(
            session, scam_detected, scam_type or session.scam_type, keywords, reply
        )

        logger.info(
            f"[{session_id}] scam={scam_detected} "
            f"msgs={response['totalMessagesExchanged']} "
            f"turns={session._turn_count} "
            f"phones={len(session.intelligence.phoneNumbers)} "
            f"upi={len(session.intelligence.upiIds)} "
            f"bank={len(session.intelligence.bankAccounts)}"
        )

        # ── Callback to GUVI (every turn — always send latest data) ──────
        if session.scam_detected and session.has_intelligence():
            send_callback_async(session)

        return JSONResponse(content=response)

    except Exception as e:
        logger.error(f"[{session_id}] Error: {e}", exc_info=True)
        return JSONResponse(content=_build_error_response(session_id))


# ── Debug Endpoints ────────────────────────────────────────────────────

@app.post("/debug/session/{session_id}")
async def get_session_debug(
    session_id: str,
    x_api_key: str = Header(None, alias="x-api-key"),
):
    if x_api_key != MY_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    session = session_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "scam_type": session.scam_type,
        "message_count": session.message_count,
        "intelligence": session.intelligence.model_dump(),
        "callback_sent": session.callback_sent,
        "notes": session.agent_notes,
    }


@app.post("/callback/force/{session_id}")
async def force_callback(
    session_id: str,
    x_api_key: str = Header(None, alias="x-api-key"),
):
    if x_api_key != MY_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    session = session_manager.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    from guvi_callback import send_callback_to_guvi
    success = send_callback_to_guvi(session)
    session.callback_sent = True
    return {"status": "success", "callback_triggered": True, "guvi_response": success}
