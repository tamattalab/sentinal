from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import time

from config import MY_API_KEY
from models import AnalyzeRequest, AnalyzeResponse, ExtractedIntelligence
from scam_detector import detect_scam, get_scam_type
from intelligence import extract_all_intelligence, extract_from_conversation
from agent_persona import generate_honeypot_response, generate_confused_response
from session_manager import session_manager
from guvi_callback import send_callback_to_guvi, send_callback_async

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered honeypot for scam detection and intelligence extraction",
    version="1.0.0"
)

# CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint - health check."""
    return {"status": "ok", "message": "Honeypot API is running"}

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": int(time.time() * 1000)}

@app.post("/analyze")
@app.post("/api/analyze")
async def analyze_message(
    request: Request,
    x_api_key: str = Header(None, alias="x-api-key")
):
    """
    Main endpoint to analyze incoming messages.
    Detects scams, engages with honeypot persona, extracts intelligence.
    """
    
    # Validate API key
    if x_api_key != MY_API_KEY:
        logger.warning(f"Invalid API key attempt: {x_api_key}")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    try:
        # Parse request body
        body = await request.json()
        
        # Handle empty or minimal requests gracefully
        if not body:
            return JSONResponse(
                content={
                    "status": "success",
                    "reply": "Hello? Is anyone there?",
                    "scamDetected": False,
                    "extractedIntelligence": {
                        "bankAccounts": [],
                        "upiIds": [],
                        "phishingLinks": [],
                        "phoneNumbers": [],
                        "suspiciousKeywords": []
                    }
                }
            )
        
        # Validate required fields
        if "message" not in body:
            return JSONResponse(
                content={
                    "status": "success",
                    "reply": "Sorry, I didn't understand. Can you say that again?",
                    "scamDetected": False,
                    "extractedIntelligence": {
                        "bankAccounts": [],
                        "upiIds": [],
                        "phishingLinks": [],
                        "phoneNumbers": [],
                        "suspiciousKeywords": []
                    }
                }
            )
        
        # Extract fields with defaults
        session_id = body.get("sessionId", "default-session")
        message = body.get("message", {})
        message_text = message.get("text", "") if isinstance(message, dict) else str(message)
        conversation_history = body.get("conversationHistory", [])
        
        logger.info(f"Processing message for session {session_id}: {message_text[:100]}...")
        
        # Get or create session
        session = session_manager.get_or_create_session(session_id)
        
        # Detect scam in current message and history
        scam_detected, keywords = detect_scam(message_text, conversation_history)
        scam_type = get_scam_type(keywords) if scam_detected else None
        
        # Extract intelligence from current message
        current_intel = extract_all_intelligence(message_text)
        
        # Also extract from conversation history
        if conversation_history:
            history_intel = extract_from_conversation(conversation_history)
            # Merge
            current_intel = ExtractedIntelligence(
                bankAccounts=list(set(current_intel.bankAccounts + history_intel.bankAccounts)),
                upiIds=list(set(current_intel.upiIds + history_intel.upiIds)),
                phishingLinks=list(set(current_intel.phishingLinks + history_intel.phishingLinks)),
                phoneNumbers=list(set(current_intel.phoneNumbers + history_intel.phoneNumbers)),
                suspiciousKeywords=list(set(current_intel.suspiciousKeywords + history_intel.suspiciousKeywords))
            )
        
        # Update session
        session = session_manager.update_session(
            session_id=session_id,
            scam_detected=scam_detected or session.scam_detected,  # Once detected, stays detected
            intelligence=current_intel,
            scam_type=scam_type or session.scam_type,
            increment_messages=True
        )
        
        # Add agent notes based on detection
        if scam_detected and not session.scam_detected:
            session.add_note(f"Scam detected: {scam_type}")
        if keywords:
            session.add_note(f"Keywords: {', '.join(keywords[:5])}")
        
        # Generate response
        if session.scam_detected:
            # Honeypot mode - engage the scammer
            reply = generate_honeypot_response(
                current_message=message_text,
                conversation_history=conversation_history,
                scam_detected=True,
                scam_type=session.scam_type
            )
        else:
            # Not sure if scam - ask for clarification
            reply = generate_confused_response(message_text)
        
        logger.info(f"Generated reply for session {session_id}: {reply[:50]}...")
        
        # Check if we should send callback to GUVI
        if session_manager.should_send_callback(session_id):
            logger.info(f"Sending GUVI callback for session {session_id}")
            send_callback_async(session)
            session_manager.mark_callback_sent(session_id)
        
        # Build response
        response = {
            "status": "success",
            "reply": reply
        }
        
        return JSONResponse(content=response)
        
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        # Return a safe fallback response
        return JSONResponse(
            content={
                "status": "success",
                "reply": "Sorry, I didn't understand. Can you explain again?",
                "scamDetected": False,
                "extractedIntelligence": {
                    "bankAccounts": [],
                    "upiIds": [],
                    "phishingLinks": [],
                    "phoneNumbers": [],
                    "suspiciousKeywords": []
                }
            }
        )

@app.post("/debug/session/{session_id}")
async def get_session_debug(
    session_id: str,
    x_api_key: str = Header(None, alias="x-api-key")
):
    """Debug endpoint to view session state."""
    if x_api_key != MY_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "scamType": session.scam_type,
        "messageCount": session.message_count,
        "intelligence": {
            "bankAccounts": session.intelligence.bankAccounts,
            "upiIds": session.intelligence.upiIds,
            "phishingLinks": session.intelligence.phishingLinks,
            "phoneNumbers": session.intelligence.phoneNumbers,
            "suspiciousKeywords": session.intelligence.suspiciousKeywords
        },
        "agentNotes": session.get_notes_string(),
        "callbackSent": session.callback_sent
    }

@app.post("/callback/force/{session_id}")
async def force_callback(
    session_id: str,
    x_api_key: str = Header(None, alias="x-api-key")
):
    """Force send callback to GUVI for a session."""
    if x_api_key != MY_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    success = send_callback_to_guvi(session)
    if success:
        session_manager.mark_callback_sent(session_id)
    
    return {"success": success, "sessionId": session_id}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
