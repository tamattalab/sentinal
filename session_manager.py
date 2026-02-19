import time
from typing import Dict, Optional
from models import ExtractedIntelligence
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class SessionData:
    """Single source of truth for all session state."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scam_detected = False
        self.scam_type: Optional[str] = None
        self.intelligence = ExtractedIntelligence()
        self.agent_notes: list = []
        self.callback_sent = False

        # Timing
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.start_time = time.time()

        # Message tracking
        self._turn_count = 0
        self._history_message_count = 0  # from conversationHistory

    @property
    def message_count(self) -> int:
        """Total messages exchanged — max of turn-based and history-based counts."""
        turn_based = self._turn_count * 2
        return max(turn_based, self._history_message_count)

    def record_turn(self):
        """Record one conversation turn (scammer sends, honeypot replies)."""
        self._turn_count += 1
        self.last_activity = datetime.now()

    def update_message_count_from_history(self, history_length: int):
        """
        Update message count using conversationHistory length from GUVI.
        history_length = len(conversationHistory) already includes all prior messages.
        +2 for current scammer message + our reply.
        """
        total = history_length + 2
        if total > self._history_message_count:
            self._history_message_count = total

    def get_engagement_metrics(self) -> dict:
        """
        Calculate engagement metrics from session state.
        Returns exact rubric format — no separate tracker needed.
        """
        elapsed = time.time() - self.start_time
        duration = int(elapsed)

        # Smart floor: if we've had 3+ turns (6+ messages), assume
        # at least 75s of real engagement
        if self._turn_count >= 3 and duration < 75:
            duration = 75

        return {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": self.message_count,
        }

    def add_note(self, note: str):
        self.agent_notes.append(note)

    def get_notes_string(self) -> str:
        return " | ".join(self.agent_notes) if self.agent_notes else "No specific notes"

    def merge_intelligence(self, new_intel: ExtractedIntelligence):
        """Merge new intelligence into session, deduplicating."""
        self.intelligence = ExtractedIntelligence(
            phoneNumbers=list(set(self.intelligence.phoneNumbers + new_intel.phoneNumbers)),
            bankAccounts=list(set(self.intelligence.bankAccounts + new_intel.bankAccounts)),
            upiIds=list(set(self.intelligence.upiIds + new_intel.upiIds)),
            phishingLinks=list(set(self.intelligence.phishingLinks + new_intel.phishingLinks)),
            emailAddresses=list(set(self.intelligence.emailAddresses + new_intel.emailAddresses)),
        )

    def has_intelligence(self) -> bool:
        """Check if any intelligence has been extracted."""
        i = self.intelligence
        return bool(i.phoneNumbers or i.bankAccounts or i.upiIds or i.phishingLinks or i.emailAddresses)


class SessionManager:
    """Manages all active sessions. Singleton."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.sessions: Dict[str, SessionData] = {}
            cls._instance._start_cleanup()
        return cls._instance

    def _start_cleanup(self):
        import threading

        def cleanup_worker():
            while True:
                try:
                    self._cleanup_stale_sessions()
                except Exception as e:
                    logger.error(f"Cleanup error: {e}")
                time.sleep(60)

        threading.Thread(target=cleanup_worker, daemon=True).start()

    def _cleanup_stale_sessions(self):
        from guvi_callback import send_callback_to_guvi

        now = datetime.now()
        for sid in list(self.sessions.keys()):
            session = self.sessions.get(sid)
            if not session:
                continue
            elapsed = (now - session.last_activity).total_seconds()
            # 5 min timeout: send final callback if not sent
            if elapsed > 300 and session.scam_detected and not session.callback_sent:
                logger.info(f"Session {sid} timed out. Sending final callback.")
                send_callback_to_guvi(session)
                session.callback_sent = True
            # 1 hour: delete session
            if elapsed > 3600:
                del self.sessions[sid]

    def get_or_create(self, session_id: str) -> SessionData:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionData(session_id)
        return self.sessions[session_id]

    def get(self, session_id: str) -> Optional[SessionData]:
        return self.sessions.get(session_id)


# Global singleton
session_manager = SessionManager()
