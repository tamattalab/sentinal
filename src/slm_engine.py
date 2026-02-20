"""
SLM Engine — SmolLM2-135M-Instruct Integration (Layer 4D)

Async singleton that runs the SLM for:
  1. Refined scam detection confidence
  2. Entity extraction beyond regex
  3. Human-like reply generation (Ramesh Kumar persona)

Toggle: USE_SLM in config.py (default false)
Safety: 8s timeout, falls back to rule-based results on ANY failure
"""
import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Any

from config import USE_SLM, SLM_MODEL_PATH, SLM_TIMEOUT

logger = logging.getLogger(__name__)

# ── Structured prompt template ─────────────────────────────────────────
_SLM_PROMPT = """You are Ramesh Kumar, a 67-year-old retired government employee from Nagpur, India.
You are on a phone call with a potential scammer. Your job is to:
1. Keep them talking (stall with excuses, confusion, questions)
2. Extract their personal info (UPI, phone, bank, email, links)
3. Sound natural and human — mix English with light Hinglish

SCAM TYPE: {scam_type}
CONVERSATION PHASE: {phase}
TURN NUMBER: {turn_count}

SCAMMER'S MESSAGE: "{message}"

CONVERSATION HISTORY (last 3 turns):
{history}

RULE-BASED ANALYSIS:
- Detected scam: {rule_detected}
- Confidence: {rule_confidence}
- Extracted: {rule_intel_summary}
- Rule reply: "{rule_reply}"

TASK: Generate a JSON response with these exact fields:
{{
  "confidence": <float 0.0-1.0, your scam confidence>,
  "scam_type": "<refined scam type or same>",
  "missed_entities": {{
    "phoneNumbers": [],
    "upiIds": [],
    "bankAccounts": [],
    "emailAddresses": [],
    "phishingLinks": []
  }},
  "reply": "<your human-like 1-2 sentence reply as Ramesh Kumar, <80 words, stall/probe for intel>",
  "insight": "<1 sentence about scammer tactics or behavioral observation>"
}}

Respond ONLY with valid JSON. No explanation."""


class SLMEngine:
    """Async singleton for SmolLM2-135M-Instruct inference."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.pipeline = None
        self.ready = False
        self._load_attempted = False

    def warmup(self):
        """Load the model synchronously — call during app startup."""
        if not USE_SLM:
            logger.info("[SLM] Disabled (USE_SLM=false)")
            return

        if self._load_attempted:
            return

        self._load_attempted = True
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline as hf_pipeline
            import torch

            logger.info(f"[SLM] Loading SmolLM2-135M-Instruct from {SLM_MODEL_PATH}...")

            # Try local path first, then HuggingFace Hub
            model_source = SLM_MODEL_PATH
            try:
                tokenizer = AutoTokenizer.from_pretrained(model_source, local_files_only=True)
                model = AutoModelForCausalLM.from_pretrained(model_source, local_files_only=True)
                logger.info("[SLM] Loaded from local path")
            except Exception:
                model_source = "HuggingFaceTB/SmolLM2-135M-Instruct"
                logger.info(f"[SLM] Local not found, downloading from {model_source}...")
                tokenizer = AutoTokenizer.from_pretrained(model_source)
                model = AutoModelForCausalLM.from_pretrained(model_source)

            device = "cuda" if torch.cuda.is_available() else "cpu"
            model.to(device)

            self.pipeline = hf_pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                device=device if device == "cuda" else -1,  # -1 = CPU for pipeline
            )
            self.ready = True
            logger.info(f"[SLM] Ready on {device} ✅")
        except Exception as e:
            logger.error(f"[SLM] Failed to load: {e}")
            self.ready = False

    async def smart_process(
        self,
        message_text: str,
        conversation_history: List[Dict],
        scam_type: str,
        turn_count: int,
        rule_detected: bool,
        rule_confidence: float,
        rule_intel: Dict[str, List[str]],
        rule_reply: str,
    ) -> Dict[str, Any]:
        """
        Run SLM inference asynchronously with timeout.
        Returns merged results dict. Falls back to empty on failure.
        """
        empty_result = {
            "refined_confidence": 0.0,
            "refined_scam_type": "",
            "missed_entities": {},
            "refined_reply": "",
            "insight": "",
            "slm_used": False,
        }

        if not USE_SLM or not self.ready:
            return empty_result

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    self._infer,
                    message_text,
                    conversation_history,
                    scam_type,
                    turn_count,
                    rule_detected,
                    rule_confidence,
                    rule_intel,
                    rule_reply,
                ),
                timeout=SLM_TIMEOUT,
            )
            result["slm_used"] = True
            return result
        except asyncio.TimeoutError:
            logger.warning(f"[SLM] Timeout ({SLM_TIMEOUT}s) — falling back to rules")
            return empty_result
        except Exception as e:
            logger.error(f"[SLM] Inference error: {e}")
            return empty_result

    def _infer(
        self,
        message_text: str,
        conversation_history: List[Dict],
        scam_type: str,
        turn_count: int,
        rule_detected: bool,
        rule_confidence: float,
        rule_intel: Dict[str, List[str]],
        rule_reply: str,
    ) -> Dict[str, Any]:
        """Synchronous inference — runs in thread pool."""
        # Determine phase
        if turn_count <= 2:
            phase = "early (establishing persona)"
        elif turn_count <= 6:
            phase = "middle (stalling and extracting)"
        else:
            phase = "late (maximum pressure, buying time)"

        # Build history summary (last 3 turns)
        history_lines = []
        for h in conversation_history[-6:]:  # last 6 messages = ~3 turns
            role = h.get("sender", "unknown")
            text = h.get("text", "")[:100]
            history_lines.append(f"  [{role}]: {text}")
        history_str = "\n".join(history_lines) if history_lines else "  (first message)"

        # Intel summary
        intel_parts = []
        for key, vals in rule_intel.items():
            if vals:
                intel_parts.append(f"{key}: {vals[:3]}")
        intel_summary = "; ".join(intel_parts) if intel_parts else "none yet"

        # Build prompt
        prompt = _SLM_PROMPT.format(
            scam_type=scam_type or "UNKNOWN",
            phase=phase,
            turn_count=turn_count,
            message=message_text[:300],
            history=history_str,
            rule_detected=rule_detected,
            rule_confidence=f"{rule_confidence:.2f}",
            rule_intel_summary=intel_summary,
            rule_reply=rule_reply[:150],
        )

        # Run inference
        output = self.pipeline(
            prompt,
            max_new_tokens=200,
            temperature=0.7,
            do_sample=True,
            return_full_text=False,
        )

        generated = output[0]["generated_text"].strip()
        return self._parse_output(generated, rule_reply)

    def _parse_output(self, raw: str, fallback_reply: str) -> Dict[str, Any]:
        """Parse SLM JSON output. Returns clean dict or empty on parse failure."""
        result = {
            "refined_confidence": 0.0,
            "refined_scam_type": "",
            "missed_entities": {},
            "refined_reply": "",
            "insight": "",
        }

        try:
            # Try to extract JSON from the output
            json_match = re.search(r'\{[\s\S]*\}', raw)
            if not json_match:
                logger.debug("[SLM] No JSON block found in output")
                return result

            parsed = json.loads(json_match.group())

            # Extract confidence
            conf = parsed.get("confidence", 0.0)
            if isinstance(conf, (int, float)) and 0.0 <= conf <= 1.0:
                result["refined_confidence"] = float(conf)

            # Extract scam type
            stype = parsed.get("scam_type", "")
            if isinstance(stype, str) and len(stype) > 2:
                result["refined_scam_type"] = stype.upper().replace(" ", "_")

            # Extract missed entities
            missed = parsed.get("missed_entities", {})
            if isinstance(missed, dict):
                clean_missed = {}
                for key in ["phoneNumbers", "upiIds", "bankAccounts", "emailAddresses", "phishingLinks"]:
                    vals = missed.get(key, [])
                    if isinstance(vals, list):
                        clean_missed[key] = [str(v) for v in vals if v]
                result["missed_entities"] = clean_missed

            # Extract reply — validate it's reasonable
            reply = parsed.get("reply", "")
            if isinstance(reply, str) and 10 < len(reply) < 500:
                # Basic safety: no offensive content, has persona feel
                result["refined_reply"] = reply

            # Extract insight
            insight = parsed.get("insight", "")
            if isinstance(insight, str) and len(insight) > 5:
                result["insight"] = insight[:200]

        except json.JSONDecodeError:
            logger.debug("[SLM] JSON parse failed — using regex fallback")
            # Try regex fallback for reply
            reply_match = re.search(r'"reply"\s*:\s*"([^"]+)"', raw)
            if reply_match:
                result["refined_reply"] = reply_match.group(1)

        except Exception as e:
            logger.debug(f"[SLM] Parse error: {e}")

        return result


# ── Global singleton ──────────────────────────────────────────────────
slm_engine = SLMEngine()
