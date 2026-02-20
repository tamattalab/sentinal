"""
Callback to GUVI evaluation endpoint — fire-and-forget.
Sends the latest session intelligence + metrics + rich agentNotes after each turn.
"""
import logging
import threading
import requests
from config import GUVI_CALLBACK_URL

logger = logging.getLogger(__name__)


def send_callback_to_guvi(session) -> bool:
    """
    Send session data to GUVI callback endpoint.
    Returns True on success, False on failure.
    """
    try:
        metrics = session.get_engagement_metrics()
        notes = session.get_notes_string()

        payload = {
            "sessionId": session.session_id,
            "scamDetected": True,
            "totalMessagesExchanged": metrics["totalMessagesExchanged"],
            "extractedIntelligence": {
                "phoneNumbers": session.intelligence.phoneNumbers,
                "bankAccounts": session.intelligence.bankAccounts,
                "upiIds": session.intelligence.upiIds,
                "phishingLinks": session.intelligence.phishingLinks,
                "emailAddresses": session.intelligence.emailAddresses,
                "suspiciousKeywords": session.intelligence.suspiciousKeywords,
                "caseIds": session.intelligence.caseIds,
                "policyNumbers": session.intelligence.policyNumbers,
                "orderNumbers": session.intelligence.orderNumbers,
            },
            "engagementMetrics": metrics,
            "agentNotes": notes,
        }

        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=5,
            headers={"Content-Type": "application/json"},
        )

        logger.info(
            f"[CALLBACK] Session {session.session_id}: "
            f"status={response.status_code}, "
            f"msgs={metrics['totalMessagesExchanged']}, "
            f"intel_count={session.get_intel_count()}"
        )
        return response.status_code in (200, 201)

    except Exception as e:
        logger.error(f"[CALLBACK] Session {session.session_id} failed: {e}")
        return False


def send_callback_async(session):
    """Fire-and-forget callback in a separate thread."""
    thread = threading.Thread(
        target=send_callback_to_guvi,
        args=(session,),
        daemon=True,
    )
    thread.start()
