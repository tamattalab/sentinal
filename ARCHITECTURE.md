# 🏗️ HONEYPOT-AGENT — System Architecture (v4.4.0 + SLM Layer 4D)

**Version**: 4.4.0  
**Design**: Rule-based pipeline + optional SmolLM2-135M-Instruct (Layer 4D)  
**Stack**: Python 3.12 · FastAPI · Torch/Transformers (optional)  
**Performance**: 1.5ms (SLM off) · <8s (SLM on) · 100/100 GUVI score

---

## 🗺️ 7-Layer Pipeline

```
Request → Auth → Parse → Session → [Scam Detect + Intel Extract + GNB Fraud + SLM] → Reply Gen → Response Build
           L1     L2       L3          L4A            L4B          L4C       L4D          L5           L6
```

| Layer | File | Purpose |
|---|---|---|
| **L1** (Auth) | `main.py` | x-api-key header validation |
| **L2** (Parse) | `main.py` | Tolerant JSON with multiple key fallbacks |
| **L3** (Session) | `session_manager.py` | In-memory state: turns, intel, dedup, timing |
| **L4A** (Scam) | `scam_detector.py` | 16-category weighted keywords + sigmoid confidence |
| **L4B** (Intel) | `intelligence.py` | 9 regex extractors (phone, UPI, bank, IFSC, URL, email, etc.) |
| **L4C** (Fraud) | `fraud_model.py` | GaussianNB (JP Morgan, 79.5% accuracy, 4 features) |
| **L4D** (SLM) | `slm_engine.py` | **NEW** SmolLM2-135M-Instruct refinement (optional) |
| **L5** (Reply) | `agent_persona.py` | 600+ templates, phase-rotation, dedup, red-flags, probes |
| **L6** (Build) | `main.py` | Assemble full rubric-compliant JSON response |

---

## 🤖 Layer 4D: SLM Engine (SmolLM2-135M-Instruct)

### Architecture
- **Model**: HuggingFaceTB/SmolLM2-135M-Instruct (135M params, ~270MB)
- **Toggle**: `USE_SLM` env var (default `false`)
- **Execution**: Async via `asyncio.to_thread()` with 8s timeout
- **Fallback**: On timeout/error → empty result, rules win

### What SLM Does
1. **Refine confidence**: Re-evaluates scam probability from message context + history
2. **Extract entities**: Finds entities missed by regex (e.g., implied UPI, paraphrased phone numbers)
3. **Generate reply**: Adapts template-based reply with contextual persona variation
4. **Behavioral insight**: Analyzes scammer tactics (sarcasm, escalation, new patterns)

### Merge Strategy
```
confidence = max(rule_confidence, slm_confidence)
intel = union(rule_intel, slm_missed_entities)    # dedup
reply = slm_reply if valid else rule_reply         # quality check
agentNotes += slm_insight                          # appended
```

### Performance Impact
| Metric | SLM Off | SLM On |
|---|---|---|
| Avg response | 1.5ms | 300-3000ms (CPU) |
| Max response | 32ms | 8000ms (timeout) |
| Memory | ~50MB | ~350MB |
| Failure mode | N/A | Silent fallback to rules |

---

## 📁 File Structure (v4.4.0)

```
src/
├── main.py              # Orchestrator (7-layer pipeline, v4.4.0)
├── config.py            # Env vars: USE_SLM, SLM_MODEL_PATH, SLM_TIMEOUT
├── slm_engine.py        # NEW — SmolLM2 async singleton
├── scam_detector.py     # Rule-based scam detection (16 categories)
├── intelligence.py      # Regex intel extraction (9 fields)
├── fraud_model.py       # GaussianNB fraud model (JP Morgan)
├── agent_persona.py     # Reply engine (600+ templates, dedup, probes)
├── session_manager.py   # In-memory session state machine
├── response_dataset.py  # 400+ English templates
├── hinglish_dataset.py  # 200+ Hinglish templates  
├── models.py            # Pydantic models
├── guvi_callback.py     # Async GUVI reporting
└── ml_detector.py       # Optional lightweight ML classifier

tests/
├── test_scoring.py      # 32 rubric checks
├── test_edge_cases.py   # 56 adversarial checks
├── test_slm.py          # NEW — 41 SLM integration checks
├── test_slm_scenario.sh # NEW — 10-turn SLM comparison
└── ...                  # 5 more suites
```

---

## 🎯 Design Philosophy

1. **Rules First, AI Second** — Deterministic pipeline guarantees rubric compliance; SLM only refines
2. **Toggle-Safe** — `USE_SLM=false` gives identical behavior to v4.3.0
3. **Fail-Silent** — SLM errors never crash the pipeline; rules always have the last word  
4. **Async Non-Blocking** — SLM runs in thread pool with hard timeout
5. **Rubric-Maximized** — Every GUVI field populated every turn, regardless of SLM state
