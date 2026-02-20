import hashlib
import json
from collections import Counter
from typing import List, Dict, Any, Tuple

class ScammerDNA:
    def __init__(self):
        self.known_signatures = {}
    
    def generate_fingerprint(self, session: Any) -> Tuple[str, Dict[str, Any]]:
        """Create unique behavioral signature"""
        # Session object is likely the SessionData class instance
        # We need to access conversation history. Since SessionData in session_manager 
        # doesn't strictly store the full conversation content (GUVI sends it every time),
        # we might need to pass the conversation history explicitly or rely on what's available.
        # However, looking at the plan, we want to persist this.
        # For this implementation, we will accept a list of messages or a session object 
        # if it has history. 
        # Let's assume passed 'session' has a 'history' attribute or we pass history separately.
        # Actually, in main.py we have conversation_history. The SessionData tracks aggregates.
        # Let's verify SessionData in session_manager.py... it has agent_notes but not full history.
        # Main.py receives the full history. 
        # I will change signature to accept session_id and history.
        pass

    # Redefining to match practical usage in main.py
    def generate_fingerprint_from_history(self, history: List[Dict[str, Any]]) -> Tuple[str, Dict[str, Any]]:
        features = {
            'keywords': self.extract_keyword_pattern(history),
            'timing': self.analyze_timing_pattern(history),
            'structure': self.analyze_message_structure(history),
            'tactics': self.identify_tactics(history)
        }
        
        # Create hash
        signature = hashlib.sha256(
            json.dumps(features, sort_keys=True).encode()
        ).hexdigest()[:12]
        
        return signature, features
    
    def extract_keyword_pattern(self, history: List[Dict[str, Any]]) -> List[str]:
        """Identify signature keywords"""
        all_text = " ".join([
            msg.get('text', '') for msg in history 
            if msg.get('sender') == 'scammer'
        ])
        
        # Count word frequency
        words = all_text.lower().split()
        # Filter for interesting words (simple stopword removal)
        stopwords = {'the', 'is', 'to', 'and', 'in', 'your', 'of', 'for', 'you', 'a', 'are', 'i', 'my', 'me'}
        filtered_words = [w for w in words if w not in stopwords and len(w) > 3]
        
        common_words = Counter(filtered_words).most_common(5)
        return [word for word, count in common_words]
    
    def analyze_timing_pattern(self, history: List[Dict[str, Any]]) -> str:
        """Response time signature"""
        if len(history) < 2:
            return "insufficient_data"
        
        gaps = []
        last_timestamp = 0
        
        # Sort by timestamp just in case
        sorted_history = sorted(history, key=lambda x: x.get('timestamp', 0))
        
        for i in range(1, len(sorted_history)):
            curr = sorted_history[i]
            prev = sorted_history[i-1]
            
            if curr.get('sender') == 'scammer' and prev.get('sender') != 'scammer':
                # Time taken for scammer to respond to user/honeypot
                gap = (curr.get('timestamp', 0) - prev.get('timestamp', 0)) / 1000.0
                if gap > 0:
                    gaps.append(gap)
        
        if not gaps:
            return "no_pattern"
        
        avg_gap = sum(gaps) / len(gaps)
        
        if avg_gap < 5:
            return "automated_fast"
        elif avg_gap < 45:
            return "human_responsive"
        else:
            return "human_slow"
            
    def analyze_message_structure(self, history: List[Dict[str, Any]]) -> str:
        """Analyze if messages are short/long/mixed"""
        scammer_msgs = [m.get('text', '') for m in history if m.get('sender') == 'scammer']
        if not scammer_msgs:
            return "unknown"
            
        avg_len = sum(len(m) for m in scammer_msgs) / len(scammer_msgs)
        if avg_len < 30: return "short_bursts"
        if avg_len > 100: return "long_scripts"
        return "balanced"
    
    def identify_tactics(self, history: List[Dict[str, Any]]) -> List[str]:
        """Scam tactic identification"""
        tactics = []
        all_text = " ".join([m.get('text', '') for m in history]).lower()
        
        if any(word in all_text for word in ['urgent', 'immediately', 'now', 'today']):
            tactics.append('urgency')
        if any(word in all_text for word in ['blocked', 'suspended', 'expired', 'police', 'illegal']):
            tactics.append('fear')
        if any(word in all_text for word in ['verify', 'confirm', 'update', 'submit']):
            tactics.append('authority')
        if 'http' in all_text or '.com' in all_text or 'link' in all_text:
            tactics.append('phishing')
        if any(word in all_text for word in ['upi', 'pay', 'transfer', 'amount', 'rs']):
            tactics.append('financial')
        
        return list(set(tactics))
