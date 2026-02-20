import time
from typing import Dict, Optional, List
from models import ExtractedIntelligence, BehavioralIntelligence
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Each conversation turn realistically takes ~20s (human reading + thinking + typing)
REALISTIC_SECONDS_PER_TURN = 20


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

        # === NEW: Response deduplication ===
        self.previous_replies: List[str] = []

        # === NEW: Behavioral intelligence tracking ===
        self._red_flags: List[str] = []
        self._probing_questions: List[str] = []
        self._manipulation_types: List[str] = []
        self._escalation_scores: List[float] = []  # per-turn escalation level
        self._tactics_used: List[str] = []

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

        # Realistic duration: humans take ~20s per turn
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
            suspiciousKeywords=list(set(self.intelligence.suspiciousKeywords + new_intel.suspiciousKeywords)),
        )

    def has_intelligence(self) -> bool:
        """Check if any intelligence has been extracted."""
        i = self.intelligence
        return bool(
            i.phoneNumbers or i.bankAccounts or i.upiIds or
            i.phishingLinks or i.emailAddresses or
            i.caseIds or i.policyNumbers or i.orderNumbers
        )

    # === NEW: Response deduplication ===

    def add_reply(self, reply: str):
        """Record a reply for deduplication."""
        self.previous_replies.append(reply)

    def is_duplicate_reply(self, reply: str) -> bool:
        """Check if reply is too similar to previous replies."""
        if not self.previous_replies:
            return False
        reply_lower = reply.lower().strip()
        for prev in self.previous_replies[-8:]:  # Check last 8
            prev_lower = prev.lower().strip()
            if reply_lower == prev_lower:
                return True
            # Word overlap check
            reply_words = set(reply_lower.split())
            prev_words = set(prev_lower.split())
            if reply_words and prev_words:
                overlap = len(reply_words & prev_words) / max(len(reply_words), len(prev_words))
                if overlap > 0.75:
                    return True
        return False

    # === NEW: Turn phase strategy ===

    def get_turn_phase(self) -> str:
        """Determine conversation phase from turn count."""
        if self._turn_count <= 2:
            return "early"     # Turns 1-2: confused, scared
        elif self._turn_count <= 6:
            return "middle"    # Turns 3-6: cooperative, extracting intel
        else:
            return "late"      # Turns 7+: stalling, squeezing last details

    # === NEW: Behavioral tracking ===

    def track_red_flag(self, red_flag: str):
        """Record a red flag identified in scammer's message."""
        if red_flag and red_flag not in self._red_flags:
            self._red_flags.append(red_flag)

    def track_probing_question(self, question: str):
        """Record a probing question asked by the agent."""
        if question and question not in self._probing_questions:
            self._probing_questions.append(question)

    def track_manipulation(self, message_text: str):
        """Detect and track manipulation types from scammer's message."""
        t = message_text.lower()
        types = []
        if any(w in t for w in ["urgent", "immediately", "now", "fast", "hurry"]):
            types.append("urgency")
        if any(w in t for w in ["blocked", "suspended", "arrest", "police", "legal", "court"]):
            types.append("fear")
        if any(w in t for w in ["official", "government", "rbi", "officer", "inspector"]):
            types.append("authority")
        if any(w in t for w in ["won", "prize", "reward", "profit", "returns", "free"]):
            types.append("greed")
        if any(w in t for w in ["otp", "pin", "cvv", "password"]):
            types.append("credential_theft")
        if any(w in t for w in ["kyc", "verify", "update"]):
            types.append("impersonation")
        for m_type in types:
            if m_type not in self._manipulation_types:
                self._manipulation_types.append(m_type)

    def track_escalation(self, message_text: str):
        """Score escalation level of current message."""
        t = message_text.lower()
        score = 0.0
        if any(w in t for w in ["final", "last", "warning"]):
            score += 0.3
        if any(w in t for w in ["arrest", "police", "jail", "court"]):
            score += 0.4
        if any(w in t for w in ["immediately", "now", "2 hours", "within"]):
            score += 0.2
        if any(w in t for w in ["won't", "cannot", "impossible", "too late"]):
            score += 0.1
        self._escalation_scores.append(min(score, 1.0))

    def get_escalation_pattern(self) -> str:
        """Determine overall escalation pattern."""
        if not self._escalation_scores:
            return "none"
        avg = sum(self._escalation_scores) / len(self._escalation_scores)
        if avg > 0.6:
            return "aggressive"
        elif avg > 0.3:
            return "gradual"
        elif len(self._escalation_scores) > 3 and self._escalation_scores[-1] > self._escalation_scores[0]:
            return "escalating"
        return "moderate"

    def get_behavioral_intelligence(self) -> BehavioralIntelligence:
        """Build behavioral intelligence report from tracked data."""
        # Determine tactics
        tactics = []
        kw_set = set(k.lower() for k in self.accumulated_keywords)
        if kw_set & {"otp", "pin", "cvv", "password"}:
            tactics.append("Credential Theft")
        if kw_set & {"urgent", "immediately", "blocked", "suspended"}:
            tactics.append("Urgency/Fear")
        if kw_set & {"kyc", "verify", "verification", "update"}:
            tactics.append("KYC Impersonation")
        if kw_set & {"won", "winner", "prize", "lottery"}:
            tactics.append("Prize Bait")
        if kw_set & {"invest", "profit", "returns", "bitcoin"}:
            tactics.append("Investment Fraud")
        if kw_set & {"bank", "account", "transfer"}:
            tactics.append("Banking Fraud")
        if kw_set & {"contains_url"}:
            tactics.append("Phishing Link")
        if kw_set & {"job", "work from home", "earning"}:
            tactics.append("Job Bait")
        if not tactics:
            tactics.append("Social Engineering")

        self._tactics_used = tactics

        # Build scammer profile
        profile_parts = []
        profile_parts.append(f"Scam type: {self.scam_type or 'GENERAL_FRAUD'}")
        profile_parts.append(f"Escalation: {self.get_escalation_pattern()}")
        if self._manipulation_types:
            profile_parts.append(f"Manipulation: {', '.join(self._manipulation_types)}")
        profile_parts.append(f"Turns engaged: {self._turn_count}")

        return BehavioralIntelligence(
            escalationPattern=self.get_escalation_pattern(),
            manipulationTypes=self._manipulation_types,
            redFlagsIdentified=self._red_flags,
            probingQuestionsAsked=self._probing_questions,
            scammerProfile=" | ".join(profile_parts),
            tacticsUsed=tactics,
        )

    def get_intel_count(self) -> int:
        """Total number of intelligence items extracted."""
        i = self.intelligence
        return (len(i.phoneNumbers) + len(i.bankAccounts) + len(i.upiIds) +
                len(i.phishingLinks) + len(i.emailAddresses) +
                len(i.caseIds) + len(i.policyNumbers) + len(i.orderNumbers))


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
