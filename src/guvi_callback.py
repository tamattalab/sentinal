import requests
import logging
from config import GUVI_CALLBACK_URL
from session_manager import SessionData

logger = logging.getLogger(__name__)


def send_callback_to_guvi(session: SessionData) -> bool:
    """Send final intelligence to GUVI evaluation endpoint."""
    metrics = session.get_engagement_metrics()

    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "scamType": session.scam_type or "GENERAL_FRAUD",
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
        "agentNotes": session.get_notes_string(),
    }

    try:
        logger.info(f"Sending callback to GUVI for session {session.session_id}")
        logger.info(f"Payload: {payload}")

        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            logger.info(f"GUVI callback successful for session {session.session_id}")
            return True
        else:
            logger.warning(f"GUVI callback status {response.status_code}: {response.text}")
            return False

    except requests.exceptions.Timeout:
        logger.error(f"GUVI callback timeout for session {session.session_id}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"GUVI callback error for session {session.session_id}: {e}")
        return False


def send_callback_async(session: SessionData):
    """Send callback in background (non-blocking)."""
    import threading

    def _send():
        send_callback_to_guvi(session)

    threading.Thread(target=_send, daemon=True).start()
