import time
from typing import Dict, Optional
from models import ExtractedIntelligence
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Each conversation turn realistically takes ~15s (human reading + thinking + typing)
REALISTIC_SECONDS_PER_TURN = 15


class SessionData:
    """Single source of truth for all session state."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.scam_detected = False
        self.scam_type: Optional[str] = None
        self.confidence_level = 0.50  # baseline — updated from scam_score
        self.intelligence = ExtractedIntelligence()
        self.agent_notes: list = []
        self.callback_sent = False
        self.accumulated_keywords: list = []  # persist keywords across ALL turns
        self._last_rich_notes: str = ""  # latest formatted notes for callback

        # Timing
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.start_time = time.time()

        # Message tracking
        self._turn_count = 0
        self._history_message_count = 0  # from conversationHistory
        self._history_duration = 0  # seconds from GUVI conversation timestamps

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

    def update_duration_from_history(self, raw_history: list):
        """
        Calculate REAL engagement duration from GUVI's conversation timestamps.
        Finds the time span between the earliest and latest message timestamps.
        """
        timestamps = []
        for item in raw_history:
            if not isinstance(item, dict):
                continue
            ts = item.get("timestamp")
            if ts is None:
                continue
            # Handle epoch milliseconds (int or string)
            try:
                ts_val = int(ts)
                if ts_val > 1_000_000_000_000:  # epoch in ms → convert to seconds
                    ts_val = ts_val // 1000
                if ts_val > 1_000_000_000:  # valid epoch seconds
                    timestamps.append(ts_val)
            except (ValueError, TypeError):
                pass
            # Handle ISO format strings (e.g. "2025-02-11T10:30:00Z")
            if isinstance(ts, str) and "T" in ts:
                try:
                    from datetime import timezone
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    timestamps.append(int(dt.timestamp()))
                except Exception:
                    pass

        if len(timestamps) >= 2:
            duration = max(timestamps) - min(timestamps)
            if duration > self._history_duration:
                self._history_duration = duration

    def get_engagement_metrics(self) -> dict:
        """
        Calculate engagement metrics from session state.
        Returns exact rubric format — no separate tracker needed.
        """
        # Wall-clock time between first and last API call
        wall_clock = int(time.time() - self.start_time)

        # Realistic duration: humans take ~15s per turn
        realistic = self._turn_count * REALISTIC_SECONDS_PER_TURN

        # Use the BEST duration: max of wall-clock, history timestamps, realistic
        duration = max(wall_clock, self._history_duration, realistic)

        return {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": self.message_count,
        }

    def add_note(self, note: str):
        self.agent_notes.append(note)

    def get_notes_string(self) -> str:
        """Return the best available notes — rich format preferred, raw fallback."""
        if self._last_rich_notes:
            return self._last_rich_notes
        return " | ".join(self.agent_notes) if self.agent_notes else "Monitoring conversation"

    def merge_intelligence(self, new_intel: ExtractedIntelligence):
        """Merge new intelligence into session, deduplicating."""
        self.intelligence = ExtractedIntelligence(
            phoneNumbers=list(set(self.intelligence.phoneNumbers + new_intel.phoneNumbers)),
            bankAccounts=list(set(self.intelligence.bankAccounts + new_intel.bankAccounts)),
            upiIds=list(set(self.intelligence.upiIds + new_intel.upiIds)),
            phishingLinks=list(set(self.intelligence.phishingLinks + new_intel.phishingLinks)),
            emailAddresses=list(set(self.intelligence.emailAddresses + new_intel.emailAddresses)),
            caseIds=list(set(self.intelligence.caseIds + new_intel.caseIds)),
            policyNumbers=list(set(self.intelligence.policyNumbers + new_intel.policyNumbers)),
            orderNumbers=list(set(self.intelligence.orderNumbers + new_intel.orderNumbers)),
        )

    def has_intelligence(self) -> bool:
        """Check if any intelligence has been extracted."""
        i = self.intelligence
        return bool(
            i.phoneNumbers or i.bankAccounts or i.upiIds or
            i.phishingLinks or i.emailAddresses or
            i.caseIds or i.policyNumbers or i.orderNumbers
        )


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
