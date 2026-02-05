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
                    "totalMessagesExchanged": 0,
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
                    "totalMessagesExchanged": 0,
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
        
        # Calculate actual message count from conversation history + current message
        # GUVI sends full conversation history with each request
        actual_message_count = len(conversation_history) + 1  # +1 for current message
        
        # Detect scam in current message and history
        scam_detected, keywords = detect_scam(message_text, conversation_history)
        scam_type = get_scam_type(keywords) if scam_detected else None
        
        # Build full conversation text for comprehensive extraction
        all_texts = [message_text]  # Start with current message
        for msg in conversation_history:
            msg_text = msg.get("text", "") if isinstance(msg, dict) else str(msg)
            if msg_text:
                all_texts.append(msg_text)
        
        # Combine all texts for extraction
        combined_text = "\n".join(all_texts)
        logger.info(f"Extracting intel from combined text ({len(all_texts)} messages)")
        
        # Extract intelligence from ALL messages combined
        current_intel = extract_all_intelligence(combined_text)
        
        logger.info(f"Extracted intel: accounts={current_intel.bankAccounts}, upi={current_intel.upiIds}, phones={current_intel.phoneNumbers}")
        
        # Update session with new message count
        session = session_manager.update_session(
            session_id=session_id,
            scam_detected=scam_detected or session.scam_detected,  # Once detected, stays detected
            intelligence=current_intel,
            scam_type=scam_type or session.scam_type,
            increment_messages=False  # Don't increment, we'll set it directly
        )
        # Set actual message count from conversation history
        session.message_count = actual_message_count
        
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
        
        # Build response with all required fields for GUVI
        response = {
            "status": "success",
            "reply": reply,
            "scamDetected": session.scam_detected,
            "totalMessagesExchanged": session.message_count,
            "extractedIntelligence": {
                "bankAccounts": session.intelligence.bankAccounts,
                "upiIds": session.intelligence.upiIds,
                "phishingLinks": session.intelligence.phishingLinks,
                "phoneNumbers": session.intelligence.phoneNumbers,
                "suspiciousKeywords": session.intelligence.suspiciousKeywords
            }
        }
        
        logger.info(f"Response: scamDetected={session.scam_detected}, messages={session.message_count}, intel={session.intelligence}")
        
        return JSONResponse(content=response)
        
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        # Return a safe fallback response
        return JSONResponse(
            content={
                "status": "success",
                "reply": "Sorry, I didn't understand. Can you explain again?",
                "scamDetected": False,
                "totalMessagesExchanged": 0,
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
